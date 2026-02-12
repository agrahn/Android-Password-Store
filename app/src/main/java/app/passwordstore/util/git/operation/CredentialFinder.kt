/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.git.operation

import android.annotation.SuppressLint
import android.view.LayoutInflater
import android.view.View
import android.view.WindowManager
import androidx.annotation.StringRes
import androidx.core.content.edit
import androidx.core.widget.doOnTextChanged
import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.ui.git.base.BaseGitActivity
import app.passwordstore.util.auth.BiometricAuthenticator
import app.passwordstore.util.auth.BiometricAuthenticator.Result as BiometricResult
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.git.sshj.SshKey
import app.passwordstore.util.settings.AuthMode
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.get
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import java.security.KeyPair
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import kotlinx.coroutines.runBlocking
import net.schmizz.sshj.common.DisconnectReason
import net.schmizz.sshj.common.SSHException
import net.schmizz.sshj.userauth.UserAuthException
import net.schmizz.sshj.userauth.password.PasswordFinder
import net.schmizz.sshj.userauth.password.Resource

class CredentialFinder(
  private val callingActivity: FragmentActivity,
  private val authMode: AuthMode,
  private val dispatcherProvider: DispatcherProvider,
) : PasswordFinder {

  private val repository = (callingActivity as BaseGitActivity).repository
  private val gitSecrets = (callingActivity as BaseGitActivity).gitSecrets

  private var isRetry = false
  private var retries = 0

  private var rememberPassphraseVisible = View.VISIBLE
  private var rememberPassphrase = true
  private var cachedPassphrase: CharArray? = null

  val credentialPref: String? =
    when (authMode) {
      AuthMode.SshKey -> PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE
      AuthMode.Password -> PreferenceKeys.HTTPS_PASSWORD
      else -> null
    }

  override fun reqPassword(resource: Resource<*>?): CharArray {
    val passphrase =
      runBlocking(dispatcherProvider.main()) {
        suspendCoroutine { cont -> askForPassword(cont, isRetry) }
      }
    isRetry = true
    return passphrase ?: throw SSHException(DisconnectReason.AUTH_CANCELLED_BY_USER)
  }

  override fun shouldRetry(resource: Resource<*>?) =
    if (++retries > 2) {
      credentialPref?.let { gitSecrets.edit { remove(it) } }
      throw UserAuthException("Too many authentication attempts")
      false
    } else true

  fun unlockAuthKeyPair(): KeyPair? {
    if (SshKey.pgpLongKeyId == 0L) return null

    var kp: KeyPair? = null

    cachedPassphrase =
      runBlocking(dispatcherProvider.main()) {
        suspendCoroutine { cont ->
          decryptPassphraseWithAuthentication(
            cont,
            gitSecrets.getString(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE, null)?.toCharArray(),
          )
        }
      }

    while (retries++ < 3 && kp == null) {
      val passphrase =
        runBlocking(dispatcherProvider.main()) {
          suspendCoroutine { cont -> askForPassword(cont, isRetry) }
        }
      passphrase ?: break // user cancels
      kp = repository.unlockAuthKeyPair(passphrase, KeyId(SshKey.pgpLongKeyId)).get()
      if (
        rememberPassphrase &&
          kp != null &&
          passphrase.isNotEmpty() &&
          !passphrase.contentEquals(cachedPassphrase)
      ) {
        runBlocking(dispatcherProvider.main()) {
          suspendCoroutine { cont -> updateCachedPassphraseWithAuthentication(cont, passphrase) }
        }
      }
      isRetry = true
      cachedPassphrase?.let {
        retries--
        isRetry = false
        it.wipe()
      }
      cachedPassphrase = null
      passphrase.wipe()
    }

    // user cancelled, or too many failed attempts
    if (kp == null) gitSecrets.edit { remove(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE) }

    return kp
  }

  private fun askForPassword(cont: Continuation<CharArray?>, isRetry: Boolean) {
    @StringRes val messageRes: Int
    @StringRes val hintRes: Int
    @StringRes val rememberRes: Int
    @StringRes val errorRes: Int

    when (authMode) {
      AuthMode.SshKey -> {
        messageRes = R.string.passphrase_dialog_text
        hintRes = R.string.ssh_keygen_passphrase
        rememberRes = R.string.git_operation_remember_passphrase
        errorRes = R.string.git_operation_wrong_passphrase
      }
      AuthMode.Password -> {
        messageRes = R.string.password_dialog_text
        hintRes = R.string.git_operation_hint_password
        rememberRes = R.string.git_operation_remember_password
        errorRes = R.string.git_operation_wrong_password
      }
      else ->
        throw IllegalStateException("Only SshKey and Password connection mode ask for passwords")
    }

    if (SshKey.pgpLongKeyId == 0L) {
      // retrieve here in case of non-PGP authentication
      cachedPassphrase =
        if (isRetry) {
          gitSecrets.edit { remove(credentialPref) }
          null
        } else {
          if (AESEncryption.isHardwareBacked(KeyType.PERSISTENT)) {
            AESEncryption.decrypt(
              gitSecrets.getString(credentialPref, null)?.toCharArray(),
              keyType = KeyType.PERSISTENT,
            )
          } else {
            rememberPassphraseVisible = View.GONE
            rememberPassphrase = false
            gitSecrets.edit { remove(credentialPref) }
            null
          }
        }
    }

    if (cachedPassphrase == null) {
      val layoutInflater = LayoutInflater.from(callingActivity)

      @SuppressLint("InflateParams")
      val dialogView = layoutInflater.inflate(R.layout.git_credential_layout, null)
      val credentialLayout =
        dialogView.findViewById<TextInputLayout>(R.id.git_auth_passphrase_layout)
      val editCredential = dialogView.findViewById<TextInputEditText>(R.id.git_auth_credential)
      credentialLayout.setHint(hintRes)
      editCredential.setHint(hintRes)
      val rememberCredentialCheckBox =
        dialogView.findViewById<MaterialCheckBox>(R.id.git_auth_remember_credential)
      rememberCredentialCheckBox.setVisibility(rememberPassphraseVisible)
      rememberCredentialCheckBox.isChecked = rememberPassphrase
      rememberCredentialCheckBox.setText(rememberRes)
      if (isRetry) {
        credentialLayout.error = callingActivity.resources.getString(errorRes)
        // Reset error when user starts entering a password
        editCredential.doOnTextChanged { _, _, _, _ -> credentialLayout.error = null }
      }
      val message =
        callingActivity.resources.getString(messageRes) +
          if (SshKey.pgpLongKeyId != 0L)
            "\n${callingActivity.resources.getString(R.string.pgp_id_label)} ${repository.getEmailFromKeyId(KeyId(SshKey.pgpLongKeyId))}"
          else ""
      MaterialAlertDialogBuilder(callingActivity)
        .run {
          setTitle(R.string.passphrase_dialog_title)
          setMessage(message)
          setView(dialogView)
          setPositiveButton(R.string.dialog_ok) { _, _ ->
            val passphrase =
              editCredential.text?.let { CharArray(it.length) { i -> it[i] } } ?: charArrayOf()
            rememberPassphrase = rememberCredentialCheckBox.isChecked
            /* non-PGP authentication (server passwd, imported ssh key):
             * we need to update cached passphrase on every attempt as we cannot verify correctness here */
            if (rememberPassphrase && passphrase.isNotEmpty() && SshKey.pgpLongKeyId == 0L) {
              AESEncryption.encrypt(passphrase, keyType = KeyType.PERSISTENT)?.let { encrypted ->
                gitSecrets.edit { putString(credentialPref, String(encrypted)) }
              }
            }
            cont.resume(passphrase)
          }
          setCancelable(false)
          setNegativeButton(R.string.dialog_cancel) { _, _ -> cont.resume(null) }
          setOnDismissListener { editCredential.text?.clear() }
          create()
        }
        .run {
          window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)
          show()
        }
    } else {
      cont.resume(cachedPassphrase)
    }
  }

  private fun decryptPassphraseWithAuthentication(
    cont: Continuation<CharArray?>,
    passEncrypted: CharArray?,
  ) {
    if (
      BiometricAuthenticator.canAuthenticate(callingActivity, allowPin = true) &&
        AESEncryption.isHardwareBacked(KeyType.PERSISTENT_WITH_PIN)
    )
      if (passEncrypted != null)
        BiometricAuthenticator.authenticate(
          callingActivity,
          dialogDescriptionRes = R.string.biometric_prompt_description_unlock_authentication_key,
          allowPin = true,
        ) { result ->
          if (result is BiometricResult.Success) {
            val pass = AESEncryption.decrypt(passEncrypted, keyType = KeyType.PERSISTENT_WITH_PIN)
            cont.resume(pass)
          } else if (result !is BiometricResult.Retry) {
            cont.resume(null)
          }
        }
      else cont.resume(null)
    else {
      rememberPassphraseVisible = View.GONE
      rememberPassphrase = false
      gitSecrets.edit { remove(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE) }
      cont.resume(null)
    }
  }

  private fun updateCachedPassphraseWithAuthentication(
    cont: Continuation<Unit?>,
    passphrase: CharArray,
  ) {
    if (
      BiometricAuthenticator.canAuthenticate(callingActivity, allowPin = true) &&
        AESEncryption.isHardwareBacked(KeyType.PERSISTENT_WITH_PIN)
    )
      BiometricAuthenticator.authenticate(
        callingActivity,
        dialogDescriptionRes = R.string.biometric_prompt_description_persistently_cache_password,
        allowPin = true,
      ) { result ->
        if (result is BiometricResult.Success) {
          gitSecrets.edit {
            putString(
              PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE,
              AESEncryption.encrypt(passphrase, keyType = KeyType.PERSISTENT_WITH_PIN)
                ?.concatToString(),
            )
          }
        }
        if (result !is BiometricResult.Retry) cont.resume(null)
      }
    else cont.resume(null)
  }
}
