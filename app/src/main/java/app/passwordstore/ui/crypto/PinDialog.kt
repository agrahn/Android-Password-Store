/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.crypto

import android.content.DialogInterface
import android.os.Bundle
import android.view.KeyEvent
import android.view.WindowManager
import androidx.appcompat.app.AlertDialog
import androidx.core.widget.doOnTextChanged
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.setFragmentResult
import app.passwordstore.R
import app.passwordstore.databinding.DialogPinEntryBinding
import app.passwordstore.util.extensions.unsafeLazy
import com.google.android.material.dialog.MaterialAlertDialogBuilder

/** [DialogFragment] to request a PIN from the user and forward it along. */
class PinDialog : DialogFragment() {

  private val binding by unsafeLazy { DialogPinEntryBinding.inflate(layoutInflater) }
  private var isError: Boolean = false

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    isCancelable = false // disable tapping BACK / fragment cancel
  }

  override fun onCreateDialog(savedInstanceState: Bundle?): AlertDialog {
    val builder = MaterialAlertDialogBuilder(requireContext())
    builder.setView(binding.root)

    var titleText = requireArguments().getString(TITLE_TEXT_EXTRA)
    builder.setTitle(titleText)

    var descriptionText = requireArguments().getString(DESCRIPTION_TEXT_EXTRA)
    binding.descriptionText.setText(descriptionText)

    builder.setPositiveButton(android.R.string.ok) { _, _ -> setPinAndDismiss() }
    builder.setNegativeButton(android.R.string.cancel) { d, _ -> d.cancel() }

    val dialog = builder.create()

    dialog.setCanceledOnTouchOutside(false)

    dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)
    dialog.setOnShowListener {
      var pinLength = 0
      if (isError) {
        binding.pinField.error = getString(R.string.pin_entry_wrong_input)
      }
      dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = false
      binding.pinEditText.apply {
        doOnTextChanged { s, _, _, _ ->
          s?.let {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = it.length >= 4
            pinLength = it.length
          }
          binding.pinField.error = null
        }
        setOnKeyListener { _, keyCode, _ ->
          if (keyCode == KeyEvent.KEYCODE_ENTER && pinLength >= 4) {
            setPinAndDismiss()
            return@setOnKeyListener true // return true to consume Enter
          }
          keyCode == KeyEvent.KEYCODE_BACK // return true to consume Back
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

  override fun onDismiss(dialog: DialogInterface) {
    binding.pinEditText.text?.clear()
    super.onDismiss(dialog)
  }

  override fun onCancel(dialog: DialogInterface) {
    super.onCancel(dialog)
    setFragmentResult(PIN_RESULT_KEY, Bundle().also { it.putBoolean(PIN_CANCEL, true) })
  }

  private fun setPinAndDismiss() {
    val pin = binding.pinEditText.text?.let { CharArray(it.length) { i -> it[i] } }
    setFragmentResult(
      PIN_RESULT_KEY,
      Bundle().also {
        it.putCharArray(PIN_KEY, pin)
        it.putBoolean(PIN_CANCEL, false)
      },
    )
    dismissAllowingStateLoss()
  }

  companion object {

    private const val TITLE_TEXT_EXTRA = "title_text"
    private const val DESCRIPTION_TEXT_EXTRA = "description_text"

    const val PIN_RESULT_KEY = "pin_result"
    const val PIN_KEY = "pin"
    const val PIN_CANCEL = "cancel"

    fun newInstance(
      title: String,
      description: String,
    ): PinDialog {
      val extras =
        Bundle().also {
          it.apply {
            putString(TITLE_TEXT_EXTRA, title)
            putString(DESCRIPTION_TEXT_EXTRA, description)
          }
        }
      val fragment = PinDialog()
      fragment.arguments = extras
      return fragment
    }
  }
}
