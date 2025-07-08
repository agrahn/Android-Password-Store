/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.pgp

import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doOnTextChanged
import app.passwordstore.R
import app.passwordstore.crypto.KeyUtils.tryGetId
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.databinding.PgpKeyCreationActivityBinding
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.viewBinding
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint
class PGPKeyCreationActivity : AppCompatActivity() {

  private val binding by viewBinding(PgpKeyCreationActivityBinding::inflate)
  @Inject lateinit var keyManager: PGPKeyManager

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    supportActionBar?.setDisplayHomeAsUpEnabled(true)
    title = getString(R.string.pgp_new_pgp_key_title)
    with(binding) {
      setContentView(root)
      email.doOnTextChanged { _, _, _, _ -> emailInputLayout.error = null }
      passphrase.doOnTextChanged { _, _, _, _ ->
        passphraseInputLayout.error = null
        repeatPassphraseInputLayout.error = null
      }
      repeatPassphrase.doOnTextChanged { _, _, _, _ ->
        passphraseInputLayout.error = null
        repeatPassphraseInputLayout.error = null
      }
    }
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.pgp_key_manager_new_key, menu)
    return true
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    when (item.itemId) {
      android.R.id.home -> {
        setResult(RESULT_CANCELED)
        onBackPressedDispatcher.onBackPressed()
      }
      R.id.save_key -> {
        val email = binding.email.text.toString().trim()
        val emailIsValid =
          if (email.isEmpty()) {
            binding.emailInputLayout.error = getString(R.string.pgp_email_input_required_error)
            false
          } else if (!android.util.Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
            binding.emailInputLayout.error = getString(R.string.pgp_email_input_invalid_error)
            false
          } else true

        val passphrase =
          binding.passphrase.text?.let { CharArray(it.length) { i -> it[i] } } ?: charArrayOf()
        val repeatedPassphrase =
          binding.repeatPassphrase.text?.let { CharArray(it.length) { i -> it[i] } }
            ?: charArrayOf()
        val passphrasesMatch =
          if (passphrase contentEquals repeatedPassphrase) true
          else {
            binding.passphraseInputLayout.error = "≠"
            binding.repeatPassphraseInputLayout.error =
              getString(R.string.pgp_passphrase_input_differ_error)
            false
          }

        if (emailIsValid && passphrasesMatch) {
          if (passphrase.size >= 8) {
            createPgpKey(email, passphrase)
          } else {
            insecurePassphraseWarning(email, passphrase)
          }
        }
      }
      else -> return super.onOptionsItemSelected(item)
    }
    return true
  }

  private fun insecurePassphraseWarning(email: String, passphrase: CharArray) {
    val (title, message) =
      if (passphrase.isEmpty()) {
        Pair(
          getString(R.string.pgp_key_empty_passphrase_warning),
          getString(R.string.pgp_key_empty_passphrase_warning_message),
        )
      } else {
        Pair(
          getString(R.string.pgp_key_short_passphrase_warning),
          getString(R.string.pgp_key_short_passphrase_warning_message),
        )
      }
    MaterialAlertDialogBuilder(this)
      .setIcon(R.drawable.ic_warning_red_24dp)
      .setTitle(title)
      .setMessage(message)
      .setPositiveButton(getString(R.string.pgp_key_insecure_passphrase_warning_confirm)) { _, _ ->
        createPgpKey(email, passphrase)
      }
      .setNegativeButton(R.string.dialog_cancel, null)
      .show()
  }

  private fun createPgpKey(email: String, passphrase: CharArray) {
    val name = binding.name.text.toString().trim()
    val userId = if (name.length > 0) "${name} <${email}>" else email
    val (key, error) = keyManager.generateKey(userId, passphrase)

    if (key != null) {
      MaterialAlertDialogBuilder(this)
        .setTitle(getString(R.string.pgp_key_creation_succeeded))
        .setMessage(getString(R.string.pgp_key_creation_succeeded_message, tryGetId(key)))
        .setPositiveButton(android.R.string.ok) { _, _ ->
          setResult(RESULT_OK)
          finish()
        }
        .setCancelable(false)
        .show()
    } else {
      logcat(ERROR) { error?.asLog() ?: "unknown error" }
      MaterialAlertDialogBuilder(this)
        .setTitle(getString(R.string.pgp_key_creation_error))
        .setIcon(R.drawable.ic_crossmark_red_24dp)
        .setMessage(error?.toString() ?: "unknown error")
        .setPositiveButton(android.R.string.ok) { _, _ ->
          setResult(RESULT_CANCELED)
          finish()
        }
        .setCancelable(false)
        .show()
    }
  }
}
