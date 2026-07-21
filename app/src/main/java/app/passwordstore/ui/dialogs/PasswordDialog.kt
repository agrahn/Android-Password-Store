/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.dialogs

import android.app.Dialog
import android.content.DialogInterface
import android.os.Bundle
import android.view.KeyEvent
import android.view.View
import android.view.WindowManager
import androidx.annotation.StringRes
import androidx.core.widget.doOnTextChanged
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.setFragmentResult
import app.passwordstore.R
import app.passwordstore.databinding.DialogPasswordEntryBinding
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.extensions.finish
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.settings.PreferenceKeys
import com.google.android.material.dialog.MaterialAlertDialogBuilder

/** [DialogFragment] to request a password from the user and forward it along. */
class PasswordDialog : DialogFragment() {

  private val binding by unsafeLazy { DialogPasswordEntryBinding.inflate(layoutInflater) }
  private var isError: Boolean = false
  private var cacheEnabledChecked: Boolean = false
  private var userIds: String? = null
  // dismiss calling activity after cancelling the dialog
  private var onCancelFinish: Boolean = true

  override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
    val builder = MaterialAlertDialogBuilder(requireContext())
    builder.setView(binding.root)
    builder.setTitle(requireArguments().getInt(TITLE_RES_EXTRA))
    binding.passwordField.setHint(requireArguments().getInt(HINT_RES_EXTRA))

    userIds = requireArguments().getString(USER_IDS_EXTRA)
    userIds?.let {
      binding.userIdList.setText(userIds)
      binding.userIdList.setVisibility(View.VISIBLE)
    }

    if (requireArguments().getBoolean(CACHE_OPTION_EXTRA) && AESEncryption.isHardwareBacked())
      binding.cacheEnabled.setVisibility(View.VISIBLE)
    cacheEnabledChecked =
      requireContext().sharedPrefs.getBoolean(PreferenceKeys.CACHE_PASSPHRASE, false)
    binding.cacheEnabled.apply {
      setText(requireArguments().getInt(CACHE_LABEL_RES_EXTRA))
      isChecked = cacheEnabledChecked
      setOnCheckedChangeListener { _, isChecked -> cacheEnabledChecked = isChecked }
    }
    builder.setPositiveButton(android.R.string.ok) { _, _ -> setPasswordAndDismiss() }
    val dialog = builder.create()
    dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)
    dialog.setOnShowListener {
      if (isError) {
        binding.passwordField.error = getString(requireArguments().getInt(ERROR_RES_EXTRA))
      }
      binding.passwordEditText.apply {
        doOnTextChanged { _, _, _, _ -> binding.passwordField.error = null }
        setOnKeyListener { _, keyCode, _ ->
          if (keyCode == KeyEvent.KEYCODE_ENTER) {
            setPasswordAndDismiss()
            return@setOnKeyListener true
          }
          false
        }
      }
    }
    dialog.window?.setFlags(
      WindowManager.LayoutParams.FLAG_SECURE,
      WindowManager.LayoutParams.FLAG_SECURE,
    )
    return dialog
  }

  fun setError() {
    isError = true
  }

  override fun onCancel(dialog: DialogInterface) {
    super.onCancel(dialog)
    if (requireArguments().getBoolean(ON_CANCEL_FINISH)) finish()
  }

  private fun setPasswordAndDismiss() {
    val password = binding.passwordEditText.text?.let { CharArray(it.length) { i -> it[i] } }
    binding.passwordEditText.text?.clear()
    setFragmentResult(
      PASSWORD_RESULT_KEY,
      Bundle().also {
        it.apply {
          putCharArray(PASSWORD_PHRASE_KEY, password)
          putBoolean(PASSWORD_CACHE_KEY, cacheEnabledChecked)
        }
      },
    )
    dismissAllowingStateLoss()
  }

  companion object {

    private const val USER_IDS_EXTRA = "user_ids"
    private const val CACHE_OPTION_EXTRA = "cache_option"
    private const val TITLE_RES_EXTRA = "title_res"
    private const val HINT_RES_EXTRA = "hint_res"
    private const val ERROR_RES_EXTRA = "error_res"
    private const val CACHE_LABEL_RES_EXTRA = "cache_label_res"
    private const val ON_CANCEL_FINISH = "finish_option"

    const val PASSWORD_RESULT_KEY = "password_result"
    const val PASSWORD_PHRASE_KEY = "password_phrase"
    const val PASSWORD_CACHE_KEY = "password_cache"

    fun newInstance(
      userIds: String? = null,
      cacheOptionVisible: Boolean = false,
      onCancelFinish: Boolean = true,
      @StringRes titleRes: Int = R.string.ssh_keygen_passphrase,
      @StringRes hintRes: Int = R.string.ssh_keygen_passphrase,
      @StringRes errorRes: Int = R.string.pgp_wrong_passphrase_input,
      @StringRes cacheLabelRes: Int = R.string.cache_password_until_screen_off,
    ): PasswordDialog {
      val extras =
        Bundle().also {
          it.apply {
            putString(USER_IDS_EXTRA, userIds)
            putBoolean(CACHE_OPTION_EXTRA, cacheOptionVisible)
            putBoolean(ON_CANCEL_FINISH, onCancelFinish)
            putInt(TITLE_RES_EXTRA, titleRes)
            putInt(HINT_RES_EXTRA, hintRes)
            putInt(ERROR_RES_EXTRA, errorRes)
            putInt(CACHE_LABEL_RES_EXTRA, cacheLabelRes)
          }
        }
      val fragment = PasswordDialog()
      fragment.arguments = extras
      return fragment
    }
  }
}
