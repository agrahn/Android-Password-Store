/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.dialogs

import android.app.AlertDialog
import android.app.Dialog
import android.content.Context
import android.content.SharedPreferences
import android.graphics.Typeface
import android.os.Bundle
import androidx.core.content.edit
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.setFragmentResult
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.databinding.FragmentPwgenDicewareBinding
import app.passwordstore.passgen.diceware.DicewarePassphraseGenerator
import app.passwordstore.ui.crypto.PasswordCreationActivity
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.settings.PreferenceKeys.DICEWARE_LENGTH
import app.passwordstore.util.settings.PreferenceKeys.DICEWARE_SEPARATOR
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.launch
import reactivecircus.flowbinding.android.widget.afterTextChanges

@AndroidEntryPoint
class DicewarePasswordGeneratorDialogFragment : DialogFragment() {

  @Inject lateinit var dicewareGenerator: DicewarePassphraseGenerator
  lateinit var prefs: SharedPreferences

  override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
    prefs = requireContext().getSharedPreferences("PasswordGenerator", Context.MODE_PRIVATE)
    val builder = MaterialAlertDialogBuilder(requireContext())

    val binding = FragmentPwgenDicewareBinding.inflate(layoutInflater)
    builder.setView(binding.root)

    binding.passwordSeparatorText.setText(
      AESEncryption.decrypt(
          prefs.getString(DICEWARE_SEPARATOR, null)?.toCharArray(),
          keyType = KeyType.PERSISTENT,
        )
        ?.let { String(it) } ?: "-"
    )
    binding.passwordLengthText.setText(
      AESEncryption.decrypt(
          prefs.getString(DICEWARE_LENGTH, null)?.toCharArray(),
          keyType = KeyType.PERSISTENT,
        )
        ?.let { String(it) } ?: "5"
    )
    binding.passwordText.typeface = Typeface.MONOSPACE

    lifecycleScope.launch {
      merge(
          binding.passwordLengthText.afterTextChanges(),
          binding.passwordSeparatorText.afterTextChanges(),
        )
        .collect { _ -> generatePassword(binding) }
    }
    return builder
      .run {
        setTitle(R.string.pwgen_title)
        setPositiveButton(R.string.dialog_ok) { _, _ ->
          setFragmentResult(
            PasswordCreationActivity.PASSWORD_RESULT_REQUEST_KEY,
            Bundle().also {
              it.putCharSequence(PasswordCreationActivity.RESULT, binding.passwordText.text)
            },
          )
        }
        setNeutralButton(R.string.dialog_cancel) { _, _ -> }
        setNegativeButton(R.string.pwgen_generate, null)
        create()
      }
      .apply {
        setOnShowListener {
          generatePassword(binding)
          getButton(AlertDialog.BUTTON_NEGATIVE).setOnClickListener { generatePassword(binding) }
        }
      }
  }

  private fun generatePassword(binding: FragmentPwgenDicewareBinding) {
    val length = binding.passwordLengthText.text?.toString()?.toIntOrNull() ?: 5
    val separator = binding.passwordSeparatorText.text?.toString()?.getOrNull(0) ?: '-'
    setPreferences(length, separator)
    binding.passwordText.text = dicewareGenerator.generatePassphrase(length, separator)
  }

  private fun setPreferences(length: Int, separator: Char) {
    prefs.edit {
      putString(
        DICEWARE_LENGTH,
        AESEncryption.encrypt(length.toString().toCharArray(), keyType = KeyType.PERSISTENT)?.let {
          String(it)
        },
      )
      putString(
        DICEWARE_SEPARATOR,
        AESEncryption.encrypt(charArrayOf(separator), keyType = KeyType.PERSISTENT)?.let {
          String(it)
        },
      )
    }
  }
}
