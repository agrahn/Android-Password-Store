/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.credman

import android.annotation.SuppressLint
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import androidx.annotation.RequiresApi
import androidx.core.content.edit
import androidx.credentials.provider.PendingIntentHandler
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.injection.prefs.CredentialUsernames
import app.passwordstore.injection.prefs.PasswordHistory
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.util.credman.CALLER_MISSING_ASSET_LINKS
import app.passwordstore.util.credman.CALLER_RELYING_PARTY_NOT_IDENTIFIED
import app.passwordstore.util.credman.CALLER_REQUEST_UNSUPPORTED
import app.passwordstore.util.credman.CALLER_UNKNOWN
import app.passwordstore.util.credman.CALLER_WRONG_SIGNATURE
import app.passwordstore.util.credman.CredmanUtils
import app.passwordstore.util.credman.verifyCaller
import app.passwordstore.util.extensions.base64
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.toByteArray
import app.passwordstore.util.extensions.toCharArray
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.passkey.PasskeyCredential
import app.passwordstore.util.services.UDCakeCredentialProviderService
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.getError
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Paths
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import kotlin.io.path.nameWithoutExtension
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@SuppressLint("RestrictedApi")
class PasskeyAuthenticationActivity : BasePGPActivity() {

  private val INVALID_PASSKEY_DATA = "invalid_passkey_data"
  private val PASSKEY_DATA_MISMATCH = "passkey_data_mismatch"
  private val PROVIDER_REQUEST_NULL = "provider_request_null"

  @CredentialUsernames @Inject lateinit var credentialUsernames: SharedPreferences
  @PasswordHistory @Inject lateinit var passwordHistory: SharedPreferences
  @Inject lateinit var passwordEntryFactory: PasswordEntry.Factory
  private lateinit var passkeyPath: String

  private fun getPasskeyPath(): String? {
    val credentialDataBundle =
      intent.getBundleExtra(UDCakeCredentialProviderService.CREDENTIAL_DATA_EXTRA)
    return credentialDataBundle?.getString(UDCakeCredentialProviderService.CREDENTIAL_PATH)
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    passkeyPath =
      getPasskeyPath()
        ?: run {
          logcat(ERROR) { "PasskeyAuthenticationActivity started without CREDENTIAL_PATH" }
          finish()
          return
        }

    requireKeysExist {
      requireDecryptionKeysExist(PasswordRepository.getParentPath(passkeyPath, repoPath)) { ids ->
        getPersistentAndDecrypt(ids, action = "passkey")
      }
    }
  }

  override suspend fun decryptWithPassphrase(
    passphrases: Map<String, CharArray?>,
    identifiers: List<PGPIdentifier>,
    onSuccess: suspend (String) -> Unit,
  ) {
    val encryptedFile = File(passkeyPath)
    val message = withContext(dispatcherProvider.io()) { encryptedFile.readBytes().inputStream() }
    val outputStream = ByteArrayOutputStream()
    val results = repository.decrypt(passphrases, identifiers, message, outputStream)
    val lastResult = results.last()
    if (lastResult.second.isOk) {
      val decryptedEntryBytes = lastResult.second.getOrThrow().toByteArray()
      lastResult.second.getOrThrow().wipe()
      val decryptedEntryChars = decryptedEntryBytes.toCharArray()
      decryptedEntryBytes.wipe()
      val entry = passwordEntryFactory.create(decryptedEntryChars)
      var passkey: PasskeyCredential? = null

      val providerRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)

      runCatching {
        passkey = retrievePasskey(entry) // parse
        entry.clearPassword() // wipe unparsed passkey data from memory
        if (passkey == null) throw Exception(INVALID_PASSKEY_DATA)

        // sanity checks before we proceed (or abort)
        val credentialHexIdFromFileName = Paths.get(passkeyPath).nameWithoutExtension
        val rpIdFromParentName = encryptedFile?.getParentFile()?.getName()
        if (rpIdFromParentName != passkey.rp.id || credentialHexIdFromFileName != passkey.idHex()) {
          throw Exception(PASSKEY_DATA_MISMATCH)
        }

        if (providerRequest == null) throw Exception(PROVIDER_REQUEST_NULL)

        /*
         * caller verification and origin
         */
        requireNotNull(providerRequest.callingAppInfo) { "providerRequest.callingAppInfo is null" }
        var validatedOrigin =
          providerRequest.callingAppInfo.verifyCaller(passkey.rp.id).getOrThrow()

        val resultGetCredentialResponse =
          CredmanUtils.buildGetCredentialResponse(providerRequest, passkey, validatedOrigin)

        /* It is not needed any longer and can be safely wiped from memory to keep
         * attacker's window of opportunity small. */
        passkey.clearPrivateKey()

        withContext(dispatcherProvider.main()) {
          val result = Intent()
          PendingIntentHandler.setGetCredentialResponse(
            result,
            resultGetCredentialResponse.getOrThrow(),
          )
          setResult(RESULT_OK, result)

          if (entry.hasTotp()) {
            val otp = entry.currentOtp
            val remainingTime = otp.remainingTime.inWholeSeconds
            copyTextToClipboard(otp.value.toCharArray(), isSensitive = false)
            otpTimer?.shutdownNow()
            val otpTimerNew = Executors.newSingleThreadScheduledExecutor()
            otpTimer = otpTimerNew
            otpTimerNew.schedule( // refresh otp once
              { copyTextToClipboard(entry.currentOtp.value.toCharArray(), isSensitive = false) },
              remainingTime,
              TimeUnit.SECONDS,
            )
          }
        }

        passwordHistory.edit { // create/update timestamp on the current password file
          putString(
            passkeyPath.base64(),
            System.currentTimeMillis().toString(),
          )
        }
        onSuccess(lastResult.first) // pass PGP ID for passphrase caching

        withContext(dispatcherProvider.main()) { finish() }
      }
        .onErr { e ->
          passkey?.clearPrivateKey()
          logcat(ERROR) { e.asLog() }

          val dialogMessage =
            when (e.message) {
              INVALID_PASSKEY_DATA -> {
                val credentialHexId = Paths.get(passkeyPath).nameWithoutExtension
                val shortenedHexId = credentialHexId.take(7)
                val displayPath =
                  PasswordRepository.getParentPath(passkeyPath, repoPath) + shortenedHexId + "…"
                getString(R.string.passkey_parse_error_message, displayPath)
              }
              PASSKEY_DATA_MISMATCH -> {
                val credentialHexId = Paths.get(passkeyPath).nameWithoutExtension
                val shortenedHexId = credentialHexId.take(7)
                val displayPath =
                  PasswordRepository.getParentPath(passkeyPath, repoPath) + shortenedHexId + "…"
                getString(R.string.passkey_mismatch_error_message, displayPath)
              }
              PROVIDER_REQUEST_NULL -> getString(R.string.passkey_request_error_message)
              CALLER_UNKNOWN ->
                getString(
                  R.string.passkey_caller_user_trust,
                  providerRequest?.callingAppInfo?.packageName,
                )
              CALLER_WRONG_SIGNATURE ->
                getString(
                  R.string.passkey_caller_wrong_signature,
                  providerRequest?.callingAppInfo?.packageName,
                )
              CALLER_RELYING_PARTY_NOT_IDENTIFIED ->
                getString(
                  R.string.passkey_caller_relying_party_not_identified,
                  passkey?.rp?.id,
                )
              CALLER_MISSING_ASSET_LINKS ->
                getString(R.string.passkey_caller_missing_asset_links, passkey?.rp?.id)
              CALLER_REQUEST_UNSUPPORTED -> getString(R.string.passkey_caller_request_unsupported)
              else -> getString(R.string.passkey_authentication_error_message, e.message)
            }

          val dialog = MaterialAlertDialogBuilder(this@PasskeyAuthenticationActivity)

          when (e.message) {
            CALLER_UNKNOWN -> {
              dialog
                .setIcon(R.drawable.ic_warning_red_24dp)
                .setTitle(R.string.oreo_autofill_warning_publisher_warning_sign_description)
                .setNegativeButton(
                  R.string.passkey_caller_dialog_trust,
                  null,
                )
                .setPositiveButton(R.string.dialog_cancel) { _, _ ->
                  setResult(RESULT_CANCELED)
                  finish()
                }
            }
            else -> {
              dialog
                .setIcon(R.drawable.ic_crossmark_red_24dp)
                .setTitle(R.string.passkey_authentication_error_title)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                  setResult(RESULT_CANCELED)
                  finish()
                }
            }
          }

          dialog.setMessage(dialogMessage).setCancelable(false).show()
        }
    } else {
      passphrases.values.forEach { it?.wipe() }
      if (
        results
          .filter { result ->
            if (result.second.getError() is IncorrectPassphraseException) {
              /* Remove wrong passphrases from temporary and persistent caches */
              persistentPassphrases.edit { remove(result.first) }
              cachedPassphrases[result.first]?.wipe()
              cachedPassphrases.remove(result.first)
              true
            } else false
          }
          .any()
      ) {
        /* Retry */
        decrypt(identifiers, isError = true)
      } else if (
        results.filter { it.second.getError() is NoDecryptionKeyAvailableException }.any()
      ) {
        snackbar(message = getString(R.string.password_decryption_no_decryption_key))
        val timer = Executors.newSingleThreadScheduledExecutor()
        timer.schedule({ finish() }, 4.toLong(), TimeUnit.SECONDS)
      } else {
        snackbar(message = getString(R.string.password_decryption_unknown_error))
        val timer = Executors.newSingleThreadScheduledExecutor()
        timer.schedule({ finish() }, 4.toLong(), TimeUnit.SECONDS)
      }
      results
        .filter { it.second.getError() is Throwable }
        .forEach { logcat { it.second.getError()?.asLog() ?: "unknown error" } }
    }
    if (!settings.getBoolean(PreferenceKeys.CACHE_PASSPHRASE, false)) {
      cachedPassphrases.values.forEach { it.wipe() }
      cachedPassphrases.clear()
    }
  }

  companion object {

    private var otpTimer: ScheduledExecutorService? = null
  }
}
