/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.crypto

import android.app.Dialog
import android.content.DialogInterface
import android.os.Bundle
import android.view.KeyEvent
import android.view.View
import android.view.WindowManager
import androidx.core.os.bundleOf
import androidx.core.widget.doOnTextChanged
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.setFragmentResult
import app.passwordstore.R
import app.passwordstore.databinding.DialogPasswordEntryBinding
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.extensions.finish
import app.passwordstore.util.extensions.unsafeLazy
import com.google.android.material.dialog.MaterialAlertDialogBuilder

/** [DialogFragment] to request a password from the user and forward it along. */
class PasswordDialog : DialogFragment() {

  private val binding by unsafeLazy { DialogPasswordEntryBinding.inflate(layoutInflater) }
  private var isError: Boolean = false
  private var cacheEnabledChecked: Boolean = false
  private var userIds: String? = null

  override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
    val builder = MaterialAlertDialogBuilder(requireContext())
    builder.setView(binding.root)
    builder.setTitle(R.string.ssh_keygen_passphrase)

    userIds = requireArguments().getString(USER_IDS_EXTRA)
    userIds?.let {
      binding.userIdList.setText(userIds)
      binding.userIdList.setVisibility(View.VISIBLE)
    }

    if (AESEncryption.isHardwareBacked()) binding.cacheEnabled.setVisibility(View.VISIBLE)
    cacheEnabledChecked = requireArguments().getBoolean(CACHE_ENABLED_EXTRA)
    binding.cacheEnabled.isChecked = cacheEnabledChecked
    binding.cacheEnabled.setOnCheckedChangeListener { _, isChecked ->
      cacheEnabledChecked = isChecked
    }

    builder.setPositiveButton(android.R.string.ok) { _, _ -> setPasswordAndDismiss() }
    val dialog = builder.create()
    dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)
    dialog.setOnShowListener {
      if (isError) {
        binding.passwordField.error = getString(R.string.pgp_wrong_passphrase_input)
      }
      binding.passwordEditText.doOnTextChanged { _, _, _, _ -> binding.passwordField.error = null }
      binding.passwordEditText.setOnKeyListener { _, keyCode, _ ->
        if (keyCode == KeyEvent.KEYCODE_ENTER) {
          setPasswordAndDismiss()
          return@setOnKeyListener true
        }
        false
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
    finish()
  }

  private fun setPasswordAndDismiss() {
    val password = binding.passwordEditText.text?.let { CharArray(it.length) { i -> it[i] } }
    setFragmentResult(
      PASSWORD_RESULT_KEY,
      bundleOf(PASSWORD_PHRASE_KEY to password, PASSWORD_CACHE_KEY to cacheEnabledChecked),
    )
    dismissAllowingStateLoss()
  }

  companion object {

    private const val CACHE_ENABLED_EXTRA = "CACHE_ENABLED"
    private const val USER_IDS_EXTRA = "USER_IDS"

    const val PASSWORD_RESULT_KEY = "password_result"
    const val PASSWORD_PHRASE_KEY = "password_phrase"
    const val PASSWORD_CACHE_KEY = "password_cache"

    fun newInstance(cacheEnabled: Boolean, userIds: String? = null): PasswordDialog {
      val extras = bundleOf(CACHE_ENABLED_EXTRA to cacheEnabled, USER_IDS_EXTRA to userIds)
      val fragment = PasswordDialog()
      fragment.arguments = extras
      return fragment
    }
  }
}
