/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.credman

import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import androidx.core.content.edit
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.webauthn.AuthenticatorAssertionResponse
import androidx.credentials.webauthn.FidoPublicKeyCredential
import androidx.credentials.webauthn.PublicKeyCredentialRequestOptions
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
import com.github.michaelbull.result.onSuccess
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
class PasskeyAuthenticationActivity : BasePGPActivity() {

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
        getPersistentAndDecrypt(ids)
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

      val passkey = retrievePasskey(entry)
      entry.clearPassword()

      if (passkey != null) {
        val providerRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        requireNotNull(providerRequest) {
          "PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) returned null"
        }

        val origin = CredmanUtils.appInfoToOrigin(providerRequest.callingAppInfo)
        val packageName = providerRequest.callingAppInfo.packageName

        val publicKeyRequest =
          providerRequest.credentialOptions.first() as GetPublicKeyCredentialOption
        val requestOptions = PublicKeyCredentialRequestOptions(publicKeyRequest.requestJson)
		val clientDataHash = publicKeyRequest.requestData.getByteArray("androidx.credentials.BUNDLE_KEY_CLIENT_DATA_HASH")

        val response =
          AuthenticatorAssertionResponse(
            requestOptions = requestOptions,
            credentialId = passkey.id,
            origin = origin,
            up = true,
            uv = true,
            be = true,
            bs = true,
            userHandle = passkey.user.id,
            packageName = packageName,
			clientDataHash = clientDataHash, 
          )

        val signResult = passkey.signData(response.dataToSign())

        if (signResult.isOk) {
          response.signature = signResult.getOrThrow()

          val fidoCredential =
            FidoPublicKeyCredential(
              rawId = passkey.id,
              response = response,
              authenticatorAttachment = "platform",
            )

          withContext(dispatcherProvider.main()) {
            val result = Intent()
            val passkeyCredential = PublicKeyCredential(fidoCredential.json())
            PendingIntentHandler.setGetCredentialResponse(
              result,
              GetCredentialResponse(passkeyCredential),
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

          onSuccess(lastResult.first) // pass PGP ID
          withContext(dispatcherProvider.main()) { finish() }
        } else {
          logcat(ERROR) { signResult.getError()?.asLog() ?: "" }
          MaterialAlertDialogBuilder(this@PasskeyAuthenticationActivity)
            .setIcon(R.drawable.ic_crossmark_red_24dp)
            .setTitle(R.string.passkey_sign_error_title)
            .setMessage(
              resources.getString(
                R.string.passkey_sign_error_message,
                signResult.getError()?.message ?: "",
              )
            )
            .setCancelable(false)
            .setPositiveButton(android.R.string.ok) { _, _ ->
              setResult(RESULT_CANCELED)
              finish()
            }
            .show()
        }
      } else {
        val credentialHexId = Paths.get(passkeyPath).nameWithoutExtension
        val shortenedHexId = credentialHexId.take(7)
        val displayPath =
          PasswordRepository.getParentPath(passkeyPath, repoPath) + shortenedHexId + "…"
        MaterialAlertDialogBuilder(this@PasskeyAuthenticationActivity)
          .setIcon(R.drawable.ic_crossmark_red_24dp)
          .setTitle(R.string.passkey_parse_error_title)
          .setMessage(resources.getString(R.string.passkey_parse_error_message, displayPath))
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
