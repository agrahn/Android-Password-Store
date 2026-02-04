/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.git.operation

import android.annotation.SuppressLint
import android.view.LayoutInflater
import android.view.WindowManager
import androidx.annotation.StringRes
import androidx.core.content.edit
import androidx.core.widget.doOnTextChanged
import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.ui.git.base.BaseGitActivity
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import app.passwordstore.util.extensions.gitSecrets
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

  private var isRetry = false
  private var retries = 0

  val credentialPref: String? =
    when (authMode) {
      AuthMode.SshKey -> PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE
      AuthMode.Password -> PreferenceKeys.HTTPS_PASSWORD
      else -> null
    }

  override fun reqPassword(resource: Resource<*>?): CharArray {
    val password =
      runBlocking(dispatcherProvider.main()) {
        suspendCoroutine { cont -> askForPassword(cont, isRetry) }
      }
    isRetry = true
    return password ?: throw SSHException(DisconnectReason.AUTH_CANCELLED_BY_USER)
  }

  override fun shouldRetry(resource: Resource<*>?) =
    if (++retries > 2) {
      credentialPref?.let { callingActivity.gitSecrets.edit { remove(it) } }
      throw UserAuthException("Too many authentication attempts")
      false
    } else true

  fun unlockAuthKeyPair(): KeyPair? {
    if (SshKey.pgpLongKeyId == 0L) return null

    var kp: KeyPair? = null

    while (retries++ < 3 && kp == null) {
      val passphrase =
        runBlocking(dispatcherProvider.main()) {
          suspendCoroutine { cont -> askForPassword(cont, isRetry) }
        }
      passphrase ?: break // user cancels
      isRetry = true
      kp = repository.unlockAuthKeyPair(passphrase, KeyId(SshKey.pgpLongKeyId)).get()
      passphrase.wipe()
    }

    // user cancelled, or too many failed attempts
    if (kp == null)
      callingActivity.gitSecrets.edit { remove(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE) }

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

    val storedCredential =
      if (isRetry) {
        callingActivity.gitSecrets.edit { remove(credentialPref) }
        null
      } else
        AESEncryption.decrypt(
          callingActivity.gitSecrets.getString(credentialPref, null)?.toCharArray(),
          keyType = KeyType.PERSISTENT,
        )

    if (storedCredential == null) {
      val layoutInflater = LayoutInflater.from(callingActivity)

      @SuppressLint("InflateParams")
      val dialogView = layoutInflater.inflate(R.layout.git_credential_layout, null)
      val credentialLayout =
        dialogView.findViewById<TextInputLayout>(R.id.git_auth_passphrase_layout)
      val editCredential = dialogView.findViewById<TextInputEditText>(R.id.git_auth_credential)
      credentialLayout.setHint(hintRes)
      editCredential.setHint(hintRes)
      val rememberCredential =
        dialogView.findViewById<MaterialCheckBox>(R.id.git_auth_remember_credential)
      rememberCredential.setText(rememberRes)
      if (isRetry) {
        credentialLayout.error = callingActivity.resources.getString(errorRes)
        // Reset error when user starts entering a password
        editCredential.doOnTextChanged { _, _, _, _ -> credentialLayout.error = null }
      }
      MaterialAlertDialogBuilder(callingActivity)
        .run {
          setTitle(R.string.passphrase_dialog_title)
          setMessage(messageRes)
          setView(dialogView)
          setPositiveButton(R.string.dialog_ok) { _, _ ->
            val credential =
              editCredential.text?.let { CharArray(it.length) { i -> it[i] } } ?: charArrayOf()
            if (rememberCredential.isChecked) {
              AESEncryption.encrypt(credential, keyType = KeyType.PERSISTENT)?.let { encrypted ->
                callingActivity.gitSecrets.edit { putString(credentialPref, String(encrypted)) }
              }
            }
            cont.resume(credential)
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
      cont.resume(storedCredential)
    }
  }
}
