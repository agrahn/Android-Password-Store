/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.git.operation

import android.annotation.SuppressLint
import android.view.LayoutInflater
import android.view.WindowManager
import androidx.annotation.StringRes
import androidx.core.widget.doOnTextChanged
import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.git.sshj.InteractivePasswordFinder
import app.passwordstore.util.settings.AuthMode
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume

private var storedCredential: CharArray? = null

class CredentialFinder(
  private val callingActivity: FragmentActivity,
  private val authMode: AuthMode,
  dispatcherProvider: DispatcherProvider,
) : InteractivePasswordFinder(dispatcherProvider) {

  override fun askForPassword(cont: Continuation<CharArray?>, isRetry: Boolean) {
    @StringRes val messageRes: Int
    @StringRes val hintRes: Int
    @StringRes val errorRes: Int
    when (authMode) {
      AuthMode.SshKey -> {
        messageRes = R.string.passphrase_dialog_text
        hintRes = R.string.ssh_keygen_passphrase
        errorRes = R.string.git_operation_wrong_passphrase
      }
      AuthMode.Password -> {
        messageRes = R.string.password_dialog_text
        hintRes = R.string.git_operation_hint_password
        errorRes = R.string.git_operation_wrong_password
      }
      else ->
        throw IllegalStateException("Only SshKey and Password connection mode ask for passwords")
    }
    if (isRetry) storedCredential = null
    if (storedCredential == null) {
      val layoutInflater = LayoutInflater.from(callingActivity)

      @SuppressLint("InflateParams")
      val dialogView = layoutInflater.inflate(R.layout.git_credential_layout, null)
      val credentialLayout =
        dialogView.findViewById<TextInputLayout>(R.id.git_auth_passphrase_layout)
      val editCredential = dialogView.findViewById<TextInputEditText>(R.id.git_auth_credential)
      editCredential.setHint(hintRes)
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
            val credential = editCredential.text.toString().toCharArray()
            storedCredential = credential
            cont.resume(String(credential).toCharArray())
          }
          setNegativeButton(R.string.dialog_cancel) { _, _ -> cont.resume(null) }
          setOnCancelListener { cont.resume(null) }
          create()
        }
        .run {
          window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)
          show()
        }
    } else {
      val credential = storedCredential ?: charArrayOf()
      cont.resume(credential)
    }
  }
}
