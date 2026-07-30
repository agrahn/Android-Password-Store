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
import androidx.credentials.exceptions.GetCredentialUnknownException
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
import app.passwordstore.util.credman.CredmanUtils
import app.passwordstore.util.extensions.base64
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.toByteArray
import app.passwordstore.util.extensions.toCharArray
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.services.UDCakeCredentialProviderService
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.get
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

      runCatching {
        val passkey = retrievePasskey(entry)
        entry.clearPassword() // wipe passkey data from memory
        if (passkey == null) throw GetCredentialUnknownException(INVALID_PASSKEY_DATA)

        // sanity checks before we proceed (or abort)
        val credentialHexIdFromFileName = Paths.get(passkeyPath).nameWithoutExtension
        val rpIdFromParentName = encryptedFile?.getParentFile()?.getName()
        if (rpIdFromParentName != passkey.rp.id || credentialHexIdFromFileName != passkey.idHex())
          throw GetCredentialUnknownException(PASSKEY_DATA_MISMATCH)

        val providerRequest =
          PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            ?: throw GetCredentialUnknownException(PROVIDER_REQUEST_NULL)

        val resultGetCredentialResponse =
          CredmanUtils.buildGetCredentialResponse(providerRequest, passkey)

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
          logcat(ERROR) { e.asLog() }
          val errMessage =
            when (e.message) {
              INVALID_PASSKEY_DATA -> {
                val credentialHexId = Paths.get(passkeyPath).nameWithoutExtension
                val shortenedHexId = credentialHexId.take(7)
                val displayPath =
                  PasswordRepository.getParentPath(passkeyPath, repoPath) + shortenedHexId + "…"
                resources.getString(R.string.passkey_parse_error_message, displayPath)
              }
              PASSKEY_DATA_MISMATCH -> {
                val credentialHexId = Paths.get(passkeyPath).nameWithoutExtension
                val shortenedHexId = credentialHexId.take(7)
                val displayPath =
                  PasswordRepository.getParentPath(passkeyPath, repoPath) + shortenedHexId + "…"
                resources.getString(R.string.passkey_mismatch_error_message, displayPath)
              }
              PROVIDER_REQUEST_NULL -> resources.getString(R.string.passkey_request_error_message)
              else -> resources.getString(R.string.passkey_sign_error_message, e.message)
            }

          MaterialAlertDialogBuilder(this@PasskeyAuthenticationActivity)
            .setIcon(R.drawable.ic_crossmark_red_24dp)
            .setTitle(R.string.passkey_authentication_error_title)
            .setMessage(errMessage)
            .setCancelable(false)
            .setPositiveButton(android.R.string.ok) { _, _ ->
              setResult(RESULT_CANCELED)
              finish()
            }
            .show()
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
        snackbar(message = resources.getString(R.string.password_decryption_no_decryption_key))
        val timer = Executors.newSingleThreadScheduledExecutor()
        timer.schedule({ finish() }, 4.toLong(), TimeUnit.SECONDS)
      } else {
        snackbar(message = resources.getString(R.string.password_decryption_unknown_error))
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
