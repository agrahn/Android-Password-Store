/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.provider

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.core.net.toUri
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialNoCreateOptionException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import app.passwordstore.passkeys.crypto.PasskeyCryptoHandler
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.storage.InvalidationReason
import app.passwordstore.passkeys.storage.PasskeyRemoteRefresher
import app.passwordstore.passkeys.storage.PasskeyRepositoryState
import app.passwordstore.passkeys.storage.PasskeyStorage
import com.github.michaelbull.result.fold
import java.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import logcat.LogPriority
import logcat.logcat

@RequiresApi(34)
public abstract class PasskeyCredentialProviderService : CredentialProviderService() {

  protected abstract val passkeyStorage: PasskeyStorage
  protected abstract val cryptoHandler: PasskeyCryptoHandler
  protected abstract val providerActivity: Class<out Activity>
  protected open val remoteRefresher: PasskeyRemoteRefresher?
    get() = null

  @Suppress("RawDispatchersUse")
  private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private val refreshMutex = Mutex()
  @Volatile private var refreshGeneration = 0L

  override fun onCreate() {
    super.onCreate()
    logcat { "PasskeyCredentialProviderService created" }
  }

  override fun onDestroy() {
    serviceScope.coroutineContext[Job]?.cancel()
    super.onDestroy()
  }

  final override fun onBeginGetCredentialRequest(
    request: BeginGetCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
  ) {
    val job = serviceScope.launch {
      try {
        val options =
          request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>()
        if (options.isEmpty()) {
          if (!cancellationSignal.isCanceled) {
            callback.onError(GetCredentialUnknownException("No passkey options available"))
          }
          return@launch
        }

        val queries = parseGetQueries(options)
        val observedRefreshGeneration = refreshGeneration
        var entries = loadCredentialEntries(queries)

        if (entries.isEmpty() && queries.isNotEmpty() && remoteRefresher != null) {
          logcat { "No local passkey candidates; attempting one remote Git refresh" }
          if (refreshRemote(observedRefreshGeneration)) {
            entries = loadCredentialEntries(queries)
          }
        }

        if (cancellationSignal.isCanceled) return@launch
        if (entries.isEmpty()) {
          callback.onError(GetCredentialUnknownException("No matching passkeys found"))
          return@launch
        }

        callback.onResult(
          BeginGetCredentialResponse(
            credentialEntries = entries,
            actions = emptyList(),
            authenticationActions = emptyList(),
            remoteEntry = null,
          )
        )
      } catch (_: CancellationException) {
        // Credential Manager no longer needs this response.
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Unable to build get-credential response: $e" }
        if (!cancellationSignal.isCanceled) {
          callback.onError(GetCredentialUnknownException(e.message ?: "Unknown passkey error"))
        }
      }
    }

    cancellationSignal.setOnCancelListener { job.cancel() }
  }

  private data class GetQuery(
    val option: BeginGetPublicKeyCredentialOption,
    val request: WebAuthnGetRequest,
    val rpId: String,
  )

  private fun parseGetQueries(options: List<BeginGetPublicKeyCredentialOption>): List<GetQuery> {
    return options.mapNotNull { option ->
      val parsedRequest =
        try {
          PasskeyProviderUtils.json.decodeFromString<WebAuthnGetRequest>(option.requestJson)
        } catch (e: Exception) {
          logcat(LogPriority.WARN) { "Skipping malformed passkey request: ${e.message}" }
          return@mapNotNull null
        }
      val rpId =
        parsedRequest.rpId ?: parsedRequest.allowCredentials.firstNotNullOfOrNull { it.rpId }
      if (rpId == null) {
        logcat(LogPriority.WARN) { "Skipping passkey option without RP ID" }
        null
      } else {
        GetQuery(option, parsedRequest, rpId)
      }
    }
  }

  private suspend fun loadCredentialEntries(
    queries: List<GetQuery>
  ): List<PublicKeyCredentialEntry> {
    val entries = mutableListOf<PublicKeyCredentialEntry>()
    for (query in queries) {
      val metadata =
        passkeyStorage
          .listMetadata(query.rpId)
          .fold(
            success = {
              PasskeyProviderUtils.selectCredentialsByMetadata(it, query.request.allowCredentials)
                .map { metadata ->
                  PasskeyProviderUtils.loadStoredIdentity(passkeyStorage, metadata)
                }
            },
            failure = {
              logcat(LogPriority.ERROR) { "Failed loading passkeys for ${query.rpId}: $it" }
              emptyList()
            },
          )

      logcat {
        "Passkey candidates: rpId=${query.rpId}, allowCredentials=${query.request.allowCredentials.size}, matches=${metadata.size}"
      }

      val isAutoSelectAllowed = PasskeyProviderUtils.isAutoSelectAllowed(metadata.size)
      entries.addAll(
        metadata.map { meta -> buildCredentialEntry(query.option, meta, isAutoSelectAllowed) }
      )
    }
    return entries
  }

  private suspend fun refreshRemote(observedGeneration: Long): Boolean {
    val refresher = remoteRefresher ?: return false
    return refreshMutex.withLock {
      if (refreshGeneration != observedGeneration) {
        return@withLock true
      }
      refresher
        .refresh()
        .fold(
          success = {
            refreshGeneration++
            true
          },
          failure = {
            logcat(LogPriority.WARN) { "Remote passkey refresh failed: $it" }
            false
          },
        )
    }
  }

  final override fun onBeginCreateCredentialRequest(
    request: BeginCreateCredentialRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
  ) {
    try {
      val createRequest = request as? BeginCreatePublicKeyCredentialRequest
      if (createRequest == null) {
        callback.onError(CreateCredentialNoCreateOptionException("Unsupported credential type"))
        return
      }

      val parsedRequest =
        PasskeyProviderUtils.json.decodeFromString<WebAuthnCreateRequest>(createRequest.requestJson)
      val pendingIntent = buildCreatePendingIntent()
      val description = parsedRequest.rp.name ?: parsedRequest.rp.id
      val accountName =
        parsedRequest.user.displayName ?: parsedRequest.user.name ?: parsedRequest.rp.id
      val entry =
        CreateEntry(
          accountName,
          pendingIntent,
          description,
          Instant.now(),
          providerIcon(),
          null,
          1,
          1,
          true,
        )

      callback.onResult(
        BeginCreateCredentialResponse(createEntries = listOf(entry), remoteEntry = null)
      )
    } catch (e: Exception) {
      logcat(LogPriority.ERROR) { "Unable to build create-credential response: $e" }
      callback.onError(CreateCredentialUnknownException(e.message ?: "Unknown passkey error"))
    }
  }

  final override fun onClearCredentialStateRequest(
    request: ProviderClearCredentialStateRequest,
    cancellationSignal: CancellationSignal,
    callback: OutcomeReceiver<Void?, ClearCredentialException>,
  ) {
    val repositoryState = passkeyStorage as? PasskeyRepositoryState
    if (repositoryState != null) {
      @Suppress("BlockingMethodInNonBlockingContext")
      runBlocking { repositoryState.invalidate(InvalidationReason.CLEAR_CREDENTIAL_STATE) }
    }
    callback.onResult(null)
  }

  private fun buildCredentialEntry(
    option: BeginGetPublicKeyCredentialOption,
    metadata: PasskeyMetadata,
    isAutoSelectAllowed: Boolean,
  ): PublicKeyCredentialEntry {
    val identity = PasskeyProviderUtils.credentialEntryIdentity(metadata)
    return PublicKeyCredentialEntry(
      context = this,
      username = identity.username,
      pendingIntent = buildGetPendingIntent(metadata),
      beginGetPublicKeyCredentialOption = option,
      displayName = identity.displayName,
      lastUsedTime = Instant.ofEpochMilli(metadata.createdAt.toEpochMilliseconds()),
      icon = providerIcon(),
      isAutoSelectAllowed = isAutoSelectAllowed,
    )
  }

  private fun buildGetPendingIntent(metadata: PasskeyMetadata): PendingIntent {
    val encodedCredentialId = PasskeyProviderUtils.encodeBase64Url(metadata.credentialId)
    val intent =
      Intent(this, providerActivity)
        .setData(PasskeyProviderUtils.credentialIntentUri(metadata.credentialId).toUri())
        .putExtra(EXTRA_OPERATION, OPERATION_GET)
        .putExtra(EXTRA_CREDENTIAL_ID, encodedCredentialId)
    return PendingIntent.getActivity(
      this,
      metadata.credentialId.contentHashCode(),
      intent,
      PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
    )
  }

  private fun buildCreatePendingIntent(): PendingIntent {
    val intent = Intent(this, providerActivity).putExtra(EXTRA_OPERATION, OPERATION_CREATE)
    return PendingIntent.getActivity(
      this,
      OPERATION_CREATE.hashCode(),
      intent,
      PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
    )
  }

  private fun providerIcon(): Icon {
    return Icon.createWithResource(this, applicationInfo.icon)
  }

  public companion object {
    public const val EXTRA_OPERATION: String = "passkey_operation"
    public const val EXTRA_CREDENTIAL_ID: String = "passkey_credential_id"
    public const val OPERATION_CREATE: String = "create"
    public const val OPERATION_GET: String = "get"
  }
}
