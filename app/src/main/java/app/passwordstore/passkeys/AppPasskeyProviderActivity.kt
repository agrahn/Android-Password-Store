/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R as AppR
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.passkeys.crypto.CallerType
import app.passwordstore.passkeys.crypto.ClientDataBinding
import app.passwordstore.passkeys.crypto.PasskeyCryptoHandler
import app.passwordstore.passkeys.crypto.RpIdValidator
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import app.passwordstore.passkeys.provider.PasskeyAuthenticator
import app.passwordstore.passkeys.provider.PasskeyCredentialProviderService
import app.passwordstore.passkeys.provider.PasskeyProviderUtils
import app.passwordstore.passkeys.provider.caller.WebAuthnCallerVerifier
import app.passwordstore.passkeys.storage.MissingRecipientKeyException
import app.passwordstore.passkeys.storage.PasskeyRepositoryState
import app.passwordstore.passkeys.storage.PasskeyStorage
import app.passwordstore.passkeys.storage.RepositoryGenerationProvider
import app.passwordstore.passkeys.storage.SignatureCounterError
import app.passwordstore.passkeys.storage.SignatureCounterHighWaterMark
import app.passwordstore.passkeys.storage.SignatureCounterPolicy
import app.passwordstore.passkeys.storage.SignatureCounterTransaction
import app.passwordstore.passkeys.storage.SourceVersionResult
import app.passwordstore.ui.git.base.BaseGitActivity
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.fold
import com.github.michaelbull.result.getOrElse
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlin.coroutines.resume
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import logcat.LogPriority
import logcat.logcat

@AndroidEntryPoint
class AppPasskeyProviderActivity : BaseGitActivity() {

  @Inject lateinit var passkeyStorage: PasskeyStorage
  @Inject lateinit var cryptoHandler: PasskeyCryptoHandler
  @Inject lateinit var authenticator: PasskeyAuthenticator
  @Inject lateinit var callerVerifier: WebAuthnCallerVerifier
  @Inject lateinit var passkeyRepositoryState: PasskeyRepositoryState
  @Inject lateinit var generationProvider: RepositoryGenerationProvider
  @Inject lateinit var highWaterMark: SignatureCounterHighWaterMark
  @Inject lateinit var signatureCounterTransaction: SignatureCounterTransaction
  @Inject lateinit var passphraseCache: PasskeyPassphraseCache
  @Inject lateinit var metadataIndex: PasskeyMetadataIndex
  @Inject
  @app.passwordstore.injection.prefs.PGPPassphrases
  lateinit var persistentPassphrases: android.content.SharedPreferences

  private fun maybeSyncToGit() {
    if (!sharedPrefs.getBoolean(PreferenceKeys.PASSKEY_AUTO_GIT_SYNC, true)) return
    if (gitSettings.url == null) return
    if (PasswordRepository.repository == null) return
    PasskeySyncWorker.enqueue(this)
  }

  @RequiresApi(34)
  override fun onCreate(savedInstanceState: Bundle?) {
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    super.onCreate(savedInstanceState)
    passkeyRepositoryState.setHasRemote(gitSettings.url != null)
    lifecycleScope.launch(dispatcherProvider.mainImmediate()) { handleProviderRequest() }
  }

  @RequiresApi(34)
  private suspend fun handleProviderRequest() {
    PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)?.let {
      handleGetCredential(it)
      return
    }

    PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)?.let {
      handleCreateCredential(it)
      return
    }

    finishWithGetError(GetCredentialUnknownException("Missing provider request"))
  }

  @RequiresApi(34)
  private suspend fun handleGetCredential(
    request: androidx.credentials.provider.ProviderGetCredentialRequest
  ) {
    try {
      @Suppress("InlinedApi")
      val selectedCredentialId =
        intent.getStringExtra(PasskeyCredentialProviderService.EXTRA_CREDENTIAL_ID)
      if (selectedCredentialId == null) {
        finishWithGetError(GetCredentialCancellationException("No passkey was selected"))
        return
      }

      val option =
        request.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull()
      if (option == null) {
        finishWithGetError(GetCredentialUnknownException("Missing passkey get option"))
        return
      }

      val parsedRequest =
        PasskeyProviderUtils.json.decodeFromString<
          app.passwordstore.passkeys.provider.WebAuthnGetRequest
        >(
          option.requestJson
        )

      val rpId = parsedRequest.rpId
      if (rpId.isNullOrBlank() || !RpIdValidator.validateRpIdSyntax(rpId)) {
        finishWithGetError(GetCredentialUnknownException("Invalid RP ID in request"))
        return
      }

      if (passkeyRepositoryState.isInMergeConflict()) {
        finishWithGetError(
          GetCredentialUnknownException(
            "Repository is in a conflicted state. Please resolve conflicts first."
          )
        )
        return
      }

      val verifiedContext =
        callerVerifier
          .verifyGetRequest(request, rpId)
          .fold(
            success = { it },
            failure = { error ->
              logcat(LogPriority.WARN) {
                "Caller verification failed for get: ${error.errorCode()}"
              }
              finishWithGetError(GetCredentialUnknownException("Caller verification failed"))
              return
            },
          )

      if (verifiedContext.callerType != CallerType.NATIVE_APP) {
        if (!RpIdValidator.isValidOriginForRpId(verifiedContext.origin, rpId)) {
          finishWithGetError(GetCredentialUnknownException("Verified origin does not match RP ID"))
          return
        }
      }

      val credentialId = PasskeyProviderUtils.decodeBase64Url(selectedCredentialId)

      val metadataWithRef =
        passkeyStorage
          .listMetadataWithRefs(parsedRequest.rpId)
          .fold(
            success = { list ->
              list.firstOrNull { it.metadata.credentialId.contentEquals(credentialId) }
            },
            failure = {
              logcat(LogPriority.ERROR) { "Failed reading passkey metadata: $it" }
              null
            },
          )
      if (metadataWithRef == null) {
        finishWithGetError(GetCredentialUnknownException("Selected passkey is unavailable"))
        return
      }

      val metadata = metadataWithRef.metadata
      val fileRef = metadataWithRef.fileRef
      if (fileRef == null || metadataWithRef.sourceVersion == null) {
        finishWithGetError(
          GetCredentialUnknownException("Selected passkey has no validated file reference")
        )
        return
      }

      if (metadata.rpId != parsedRequest.rpId) {
        finishWithGetError(GetCredentialUnknownException("Credential RP ID does not match request"))
        return
      }

      val pickerVersionResult = passkeyStorage.resolveSourceVersionExact(fileRef).getOrElse { null }
      val pickerVersion =
        when (pickerVersionResult) {
          is SourceVersionResult.Stable -> pickerVersionResult.version
          is SourceVersionResult.Missing -> {
            finishWithGetError(GetCredentialUnknownException("Selected passkey was deleted"))
            return
          }
          is SourceVersionResult.Unavailable,
          null -> {
            finishWithGetError(
              GetCredentialUnknownException("Selected passkey version is unavailable")
            )
            return
          }
        }

      var userVerified = false
      if (authenticator.canAuthenticate(this)) {
        val persistentEntry = findFirstPersistentPassphrase()
        if (persistentEntry != null) {
          val (keyId, encrypted) = persistentEntry
          val cipher =
            app.passwordstore.util.crypto.AESEncryption.getCipher(
              app.passwordstore.util.crypto.AESEncryption.KeyType.PERSISTENT_WITH_AUTHENTICATION,
              encrypted,
            )
          val authResult = authenticateWithCipher(cipher)
          when (authResult) {
            is AuthOutcome.Success -> {
              userVerified = true
              val decrypted =
                app.passwordstore.util.crypto.AESEncryption.decrypt(
                  encrypted,
                  keyType =
                    app.passwordstore.util.crypto.AESEncryption.KeyType
                      .PERSISTENT_WITH_AUTHENTICATION,
                  cipher = authResult.cipher,
                )
              if (decrypted != null) {
                passphraseCache.put(keyId, decrypted)
              }
            }
            is AuthOutcome.Canceled -> {
              finishWithGetError(GetCredentialCancellationException("Authentication canceled"))
              return
            }
            is AuthOutcome.Failed -> {
              finishWithGetError(GetCredentialUnknownException(authResult.message))
              return
            }
          }
        } else {
          when (val authResult = authenticator.authenticateForPasskey(this, metadata.rpId)) {
            is PasskeyAuthenticator.Result.Success -> {
              userVerified = true
            }
            is PasskeyAuthenticator.Result.Canceled -> {
              finishWithGetError(GetCredentialCancellationException("Authentication canceled"))
              return
            }
            is PasskeyAuthenticator.Result.NotAvailable -> {
              finishWithGetError(
                GetCredentialUnknownException("Biometric authentication required but not available")
              )
              return
            }
            is PasskeyAuthenticator.Result.Failure -> {
              finishWithGetError(
                GetCredentialUnknownException("Authentication failed: ${authResult.message}")
              )
              return
            }
          }
        }
      } else {
        finishWithGetError(GetCredentialUnknownException("Biometric authentication required"))
        return
      }

      if (passkeyRepositoryState.isInMergeConflict()) {
        finishWithGetError(
          GetCredentialUnknownException(
            "Repository entered a conflicted state during authentication."
          )
        )
        return
      }

      val preSignVersionResult =
        passkeyStorage.resolveSourceVersionExact(fileRef).getOrElse { null }
      val preSignVersion =
        when (preSignVersionResult) {
          is SourceVersionResult.Stable -> preSignVersionResult
          is SourceVersionResult.Missing -> {
            finishWithGetError(
              GetCredentialUnknownException("Selected passkey was deleted during authentication")
            )
            return
          }
          is SourceVersionResult.Unavailable,
          null -> {
            finishWithGetError(GetCredentialUnknownException("Credential version unavailable"))
            return
          }
        }

      if (pickerVersionResult != preSignVersion) {
        finishWithGetError(GetCredentialUnknownException("Credential file changed since selection"))
        return
      }

      var sensitiveCredential: SensitivePasskeyCredential? = null
      try {
        sensitiveCredential =
          passkeyStorage
            .loadForSigningExact(fileRef, pickerVersion)
            .fold(
              success = { it },
              failure = {
                logcat(LogPriority.ERROR) { "Failed loading passkey for signing: $it" }
                null
              },
            )
        if (sensitiveCredential == null) {
          finishWithGetError(GetCredentialUnknownException("Selected passkey is unavailable"))
          return
        }

        val credProtectLevel = sensitiveCredential.credProtect
        if (credProtectLevel != null && credProtectLevel >= 2) {
          val credentialInAllowList =
            parsedRequest.allowCredentials.any { descriptor ->
              PasskeyProviderUtils.decodeBase64Url(descriptor.id)
                .contentEquals(sensitiveCredential.credentialId)
            }
          val uvRequired = credProtectLevel >= 3 || !credentialInAllowList
          if (uvRequired && !userVerified) {
            sensitiveCredential.close()
            finishWithGetError(
              GetCredentialUnknownException(
                "Credential requires user verification (credProtect=$credProtectLevel)"
              )
            )
            return
          }
        }

        val policy = resolveCounterPolicy()
        val newSignCount: ULong =
          when (policy) {
            SignatureCounterPolicy.ZERO_FOR_SYNCABLE -> 0u
            SignatureCounterPolicy.MONOTONIC_LOCAL -> {
              signatureCounterTransaction
                .executeMonotonicAssertionExact(
                  ref = fileRef,
                  sensitiveCredential = sensitiveCredential,
                  preSignVersion = preSignVersion,
                )
                .fold(
                  success = { it },
                  failure = { error ->
                    sensitiveCredential.close()
                    val errorMsg =
                      when (error) {
                        is SignatureCounterError.CounterOverflow -> "Signature counter overflow"
                        is SignatureCounterError.PersistenceFailed -> "Counter persistence failed"
                        is SignatureCounterError.RollbackDetected ->
                          "Rollback detected: disk=${error.diskCounter}, highWaterMark=${error.highWaterMark}"
                        is SignatureCounterError.MergeConflict ->
                          "Repository is in merge conflict; signing disabled"
                        is SignatureCounterError.FileChangedSinceSelection ->
                          "Credential file changed during transaction"
                        is SignatureCounterError.LockAcquisitionFailed ->
                          "Could not acquire counter lock"
                        is SignatureCounterError.MonotonicNotAllowed ->
                          "Monotonic mode not allowed: ${error.reason}"
                      }
                    logcat(LogPriority.ERROR) { "Monotonic assertion failed: $errorMsg" }
                    finishWithGetError(GetCredentialUnknownException(errorMsg))
                    return
                  },
                )
            }
          }

        if (policy == SignatureCounterPolicy.ZERO_FOR_SYNCABLE) {
          passkeyRepositoryState.onCredentialUpdated()
        } else {
          generationProvider.bumpWorktreeGeneration()
        }

        val effectiveBackupState =
          passkeyRepositoryState.effectiveBackupState(sensitiveCredential.backupEligible)
        val publicCredential =
          sensitiveCredential
            .toPublicCredential()
            .copy(signCount = newSignCount, backupState = effectiveBackupState)
        val requestJson = option.requestJson
        val assertion = sensitiveCredential.usePrivateKey { privateKey ->
          when (val binding = verifiedContext.clientDataBinding) {
            is ClientDataBinding.FrameworkHash ->
              cryptoHandler
                .getAssertionWithFrameworkHash(
                  credential = publicCredential,
                  privateKey = privateKey,
                  rpId = sensitiveCredential.rpId,
                  clientDataHash = binding.hash,
                  responseClientDataJson = binding.responseClientDataJson,
                  userVerified = userVerified,
                )
                .fold(
                  success = { it },
                  failure = {
                    logcat(LogPriority.ERROR) {
                      "Failed building assertion with framework hash: $it"
                    }
                    null
                  },
                )
            is ClientDataBinding.ProviderConstructed ->
              cryptoHandler
                .getAssertion(
                  credential = publicCredential,
                  privateKey = privateKey,
                  rpId = sensitiveCredential.rpId,
                  challenge = PasskeyProviderUtils.decodeBase64Url(parsedRequest.challenge),
                  origin = verifiedContext.origin,
                  userVerified = userVerified,
                )
                .fold(
                  success = { it },
                  failure = {
                    logcat(LogPriority.ERROR) { "Failed building assertion: $it" }
                    null
                  },
                )
          }
        }
        if (assertion == null) {
          finishWithGetError(GetCredentialUnknownException("Failed generating passkey assertion"))
          return
        }

        val responseJson =
          PasskeyProviderUtils.buildAssertionResponse(
            assertion,
            publicCredential,
            requestJson,
          )
        val resultIntent = Intent()
        PendingIntentHandler.setGetCredentialResponse(
          resultIntent,
          GetCredentialResponse(PublicKeyCredential(responseJson)),
        )
        setResult(Activity.RESULT_OK, resultIntent)
        maybeSyncToGit()
        finish()
      } finally {
        sensitiveCredential?.close()
      }
    } catch (e: Exception) {
      logcat(LogPriority.ERROR) { "handleGetCredential unexpected error: $e" }
      finishWithGetError(GetCredentialUnknownException("Unexpected error"))
    }
  }

  @RequiresApi(34)
  private suspend fun handleCreateCredential(
    request: androidx.credentials.provider.ProviderCreateCredentialRequest
  ) {
    try {
      val createRequest = request.callingRequest as? CreatePublicKeyCredentialRequest
      if (createRequest == null) {
        finishWithCreateError(CreateCredentialUnknownException("Missing passkey create request"))
        return
      }

      val parsedRequest =
        PasskeyProviderUtils.json.decodeFromString<
          app.passwordstore.passkeys.provider.WebAuthnCreateRequest
        >(
          createRequest.requestJson
        )

      val rpId = parsedRequest.rp.id
      if (rpId.isBlank() || !RpIdValidator.validateRpIdSyntax(rpId)) {
        finishWithCreateError(CreateCredentialUnknownException("Invalid RP ID in request"))
        return
      }

      val hasEs256 = parsedRequest.pubKeyCredParams.any { it.alg == -7L }
      if (!hasEs256) {
        val requestedAlgs = parsedRequest.pubKeyCredParams.map { it.alg }
        finishWithCreateError(
          CreateCredentialUnknownException("No supported algorithm (ES256) in request")
        )
        return
      }

      val verifiedContext =
        callerVerifier
          .verifyCreateRequest(request, rpId)
          .fold(
            success = { it },
            failure = { error ->
              logcat(LogPriority.WARN) {
                "Caller verification failed for create: ${error.errorCode()}"
              }
              finishWithCreateError(CreateCredentialUnknownException("Caller verification failed"))
              return
            },
          )

      if (verifiedContext.callerType != CallerType.NATIVE_APP) {
        if (!RpIdValidator.isValidOriginForRpId(verifiedContext.origin, rpId)) {
          finishWithCreateError(
            CreateCredentialUnknownException("Verified origin does not match RP ID")
          )
          return
        }
      }

      if (authenticator.canAuthenticate(this)) {
        when (val authResult = authenticator.authenticateForCreation(this, rpId)) {
          is PasskeyAuthenticator.Result.Success -> {}
          is PasskeyAuthenticator.Result.Canceled -> {
            finishWithCreateError(CreateCredentialUnknownException("Authentication canceled"))
            return
          }
          is PasskeyAuthenticator.Result.NotAvailable -> {
            finishWithCreateError(
              CreateCredentialUnknownException(
                "Biometric authentication required but not available"
              )
            )
            return
          }
          is PasskeyAuthenticator.Result.Failure -> {
            finishWithCreateError(
              CreateCredentialUnknownException("Authentication failed: ${authResult.message}")
            )
            return
          }
        }
      } else {
        finishWithCreateError(CreateCredentialUnknownException("Biometric authentication required"))
        return
      }

      val createdCredential =
        cryptoHandler
          .createCredential(
            rpId = rpId,
            userId = PasskeyProviderUtils.decodeBase64Url(parsedRequest.user.id),
            userName = parsedRequest.user.name ?: "",
            userDisplayName = parsedRequest.user.displayName ?: parsedRequest.user.name ?: "",
            challenge = PasskeyProviderUtils.decodeBase64Url(parsedRequest.challenge),
          )
          .fold(
            success = { it },
            failure = {
              logcat(LogPriority.ERROR) { "Failed creating passkey: $it" }
              null
            },
          )
      if (createdCredential == null) {
        finishWithCreateError(CreateCredentialUnknownException("Failed creating passkey"))
        return
      }

      try {
        val publicCredential = createdCredential.credential
        val credentialWithBinding =
          publicCredential.copy(
            createdByCallerType = verifiedContext.callerType,
            createdByPackage = verifiedContext.callingPackage,
            createdByCertificateDigest = verifiedContext.signingCertificateDigests.firstOrNull(),
            verifiedOrigin = verifiedContext.origin,
          )

        val responseJson =
          PasskeyProviderUtils.buildAttestationResponse(
            credentialWithBinding,
            createRequest.requestJson,
            verifiedContext,
          )

        val saveResult = createdCredential.usePrivateKeySuspend { privateKey ->
          passkeyStorage.saveCredential(credentialWithBinding, privateKey)
        }
        if (saveResult.isErr) {
          val error: Throwable? =
            saveResult.fold(
              success = { null },
              failure = {
                logcat(LogPriority.ERROR) { "Failed storing passkey: $it" }
                it
              },
            )
          if (error is MissingRecipientKeyException) {
            showMissingRecipientKeyDialog(error.identifier)
          } else {
            finishWithCreateError(CreateCredentialUnknownException("Failed storing passkey"))
          }
          return
        }

        passkeyRepositoryState.onCredentialSaved()
        generationProvider.bumpWorktreeGeneration()
        metadataIndex.put(
          credentialWithBinding.credentialId,
          MetadataEntry(
            userName = credentialWithBinding.user.name,
            userDisplayName = credentialWithBinding.user.displayName,
            rpId = credentialWithBinding.rpId,
            createdAt = credentialWithBinding.createdAt.toEpochMilliseconds(),
          ),
        )

        val resultIntent = Intent()
        PendingIntentHandler.setCreateCredentialResponse(
          resultIntent,
          CreatePublicKeyCredentialResponse(responseJson),
        )
        setResult(Activity.RESULT_OK, resultIntent)
        maybeSyncToGit()
        finish()
      } finally {
        createdCredential.close()
      }
    } catch (e: Exception) {
      logcat(LogPriority.ERROR) { "handleCreateCredential unexpected error: $e" }
      finishWithCreateError(CreateCredentialUnknownException("Unexpected error"))
    }
  }

  private sealed class AuthOutcome {
    data class Success(val cipher: javax.crypto.Cipher?) : AuthOutcome()

    data object Canceled : AuthOutcome()

    data class Failed(val message: String) : AuthOutcome()
  }

  private fun showMissingRecipientKeyDialog(identifier: String) {
    val exception = CreateCredentialUnknownException("Missing PGP recipient key: $identifier")
    MaterialAlertDialogBuilder(this)
      .setIcon(AppR.drawable.ic_warning_red_24dp)
      .setTitle(AppR.string.passkey_missing_recipient_key_title)
      .setMessage(getString(AppR.string.passkey_missing_recipient_key_message, identifier))
      .setCancelable(false)
      .setPositiveButton(AppR.string.no_keys_imported_dialog_open_key_manager) { _, _ ->
        startActivity(PGPKeyListActivity.newIntent(this))
        finishWithCreateError(exception)
      }
      .setNegativeButton(AppR.string.dialog_cancel) { _, _ ->
        finishWithCreateError(exception)
      }
      .show()
  }

  private fun findFirstPersistentPassphrase(): Pair<String, CharArray>? {
    val allKeys = persistentPassphrases.all
    for ((keyId, value) in allKeys) {
      if (keyId == "unlock_pin" || keyId == PreferenceKeys.BIOMETRICS_AND_PIN_LAST_USE) continue
      if (passphraseCache.contains(keyId)) continue
      val encrypted = (value as? String)?.toCharArray() ?: continue
      return keyId to encrypted
    }
    return null
  }

  private suspend fun authenticateWithCipher(cipher: javax.crypto.Cipher?): AuthOutcome {
    return suspendCancellableCoroutine { continuation ->
      app.passwordstore.util.auth.BiometricAuthenticator.authenticate(
        activity = this,
        dialogTitleRes = AppR.string.passkey_auth_title,
        dialogDescriptionRes = AppR.string.passkey_auth_description,
        allowPin = true,
        cipher = cipher,
      ) { result ->
        if (continuation.isActive) {
          when (result) {
            is app.passwordstore.util.auth.BiometricAuthenticator.Result.Success ->
              continuation.resume(AuthOutcome.Success(result.cryptoObject?.cipher))
            is app.passwordstore.util.auth.BiometricAuthenticator.Result.CanceledByUser,
            is app.passwordstore.util.auth.BiometricAuthenticator.Result.CanceledBySystem ->
              continuation.resume(AuthOutcome.Canceled)
            is app.passwordstore.util.auth.BiometricAuthenticator.Result.Failure ->
              continuation.resume(AuthOutcome.Failed(result.message.toString()))
            is app.passwordstore.util.auth.BiometricAuthenticator.Result.HardwareUnavailableOrDisabled ->
              continuation.resume(AuthOutcome.Failed("Biometric authentication not available"))
            is app.passwordstore.util.auth.BiometricAuthenticator.Result.Retry ->
              continuation.resume(AuthOutcome.Failed("Authentication retry required"))
          }
        }
      }
    }
  }

  private fun resolveCounterPolicy(): SignatureCounterPolicy {
    val hasRemote = passkeyRepositoryState.hasRemote()
    if (hasRemote) {
      return SignatureCounterPolicy.ZERO_FOR_SYNCABLE
    }
    val legacyConstant =
      sharedPrefs.getBoolean(PreferenceKeys.PASSKEY_CONSTANT_SIGNATURE_COUNTER, true)
    return if (legacyConstant) {
      SignatureCounterPolicy.ZERO_FOR_SYNCABLE
    } else {
      SignatureCounterPolicy.MONOTONIC_LOCAL
    }
  }

  private fun finishWithGetError(
    exception: androidx.credentials.exceptions.GetCredentialException
  ) {
    val resultIntent = Intent()
    PendingIntentHandler.setGetCredentialException(resultIntent, exception)
    setResult(Activity.RESULT_OK, resultIntent)
    finish()
  }

  private fun finishWithCreateError(
    exception: androidx.credentials.exceptions.CreateCredentialException
  ) {
    val resultIntent = Intent()
    PendingIntentHandler.setCreateCredentialException(resultIntent, exception)
    setResult(Activity.RESULT_OK, resultIntent)
    finish()
  }
}
