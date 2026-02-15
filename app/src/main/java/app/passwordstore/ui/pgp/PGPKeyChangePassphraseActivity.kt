/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.pgp

import android.content.Context
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.res.ResourcesCompat
import androidx.core.widget.doOnTextChanged
import app.passwordstore.R
import app.passwordstore.crypto.KeyUtils.tryGetKeyId
import app.passwordstore.crypto.KeyUtils.tryGetSecretSubkeyIdsUsagesIsStripped
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.data.crypto.CryptoRepository
import app.passwordstore.databinding.PgpKeyChangePassphraseActivityBinding
import app.passwordstore.ui.compose.R as composeR
import app.passwordstore.util.extensions.enableEdgeToEdgeView
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.wipe
import com.github.michaelbull.result.get
import com.github.michaelbull.result.map
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint
class PGPKeyChangePassphraseActivity : AppCompatActivity() {

  private val binding by viewBinding(PgpKeyChangePassphraseActivityBinding::inflate)
  @Inject lateinit var keyManager: PGPKeyManager
  @Inject lateinit var cryptoRepository: CryptoRepository

  private lateinit var identifier: PGPIdentifier
  private var subkeyIdsUsagesIsStripped: List<Triple<KeyId, String, Boolean>>? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    supportActionBar?.setDisplayHomeAsUpEnabled(true)
    title = getString(R.string.pgp_change_passphrase_title)

    identifier =
      requireNotNull(
        PGPIdentifier.fromString(intent.getStringExtra(EXTRA_SELECTED_IDENTIFIER) ?: "")
      ) {
        "invalid PGP identifier"
      }

    val pgpKey =
      requireNotNull(keyManager.getKeyById(identifier).get()) {
        "invalid PGP identifier, no key found with this ID : ${intent.getStringExtra(EXTRA_SELECTED_IDENTIFIER)}"
      }

    subkeyIdsUsagesIsStripped = tryGetSecretSubkeyIdsUsagesIsStripped(pgpKey)

    val keySpinnerItems = mutableListOf(getString(R.string.pgp_change_passphrase_matching_subkeys))
    keySpinnerItems +=
      subkeyIdsUsagesIsStripped?.map { "${it.first} ${it.second}" } ?: listOf<String>()
    val disabledItems = mutableListOf<Boolean>(false)
    disabledItems += subkeyIdsUsagesIsStripped?.map { it.third } ?: listOf<Boolean>()

    val adapter = KeySpinnerAdapter(this, keySpinnerItems, disabledItems)
    adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)

    with(binding) {
      enableEdgeToEdgeView(root)
      setContentView(root)
      userid.text = cryptoRepository.getUserIdFromKeyId(identifier)

      keySpinner.adapter = adapter

      oldPassphrase.doOnTextChanged { _, _, _, _ -> oldPassphraseInputLayout.error = null }
      passphrase.doOnTextChanged { _, _, _, _ ->
        passphraseInputLayout.error = null
        repeatPassphraseInputLayout.error = null
      }
      repeatPassphrase.doOnTextChanged { _, _, _, _ ->
        passphraseInputLayout.error = null
        repeatPassphraseInputLayout.error = null
      }
      if (cryptoRepository.isPasswordProtected(listOf(identifier), anySubkey = true))
        oldPassphraseInputLayout.visibility = View.VISIBLE
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
        val selectedIndex = binding.keySpinner.selectedItemPosition

        val subkeyIdentifier =
          if (selectedIndex > 0) {
            subkeyIdsUsagesIsStripped?.get(selectedIndex - 1)?.first
          } else {
            null
          }

        val oldPassphrase =
          binding.oldPassphrase.text?.let { CharArray(it.length) { i -> it[i] } } ?: charArrayOf()
        val oldPassphraseIsCorrect =
          if (
            cryptoRepository.isPasswordCorrect(
              identifier,
              subkeyIdentifier,
              if (oldPassphrase.isEmpty()) null else oldPassphrase,
              anySubkey = subkeyIdentifier?.let { false } ?: true,
            )
          )
            true
          else {
            binding.oldPassphraseInputLayout.error = getString(R.string.pgp_wrong_passphrase_input)
            false
          }

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

        repeatedPassphrase.wipe()

        if (oldPassphraseIsCorrect && passphrasesMatch) {
          if (passphrase.size >= 8) {
            changePassphrase(
              identifier,
              subkeyIdentifier,
              if (oldPassphrase.isEmpty()) null else oldPassphrase,
              passphrase,
            )
          } else {
            insecurePassphraseWarning(
              identifier,
              subkeyIdentifier,
              if (oldPassphrase.isEmpty()) null else oldPassphrase,
              if (passphrase.isEmpty()) null else passphrase,
            )
          }
        } else {
          oldPassphrase.wipe()
          passphrase.wipe()
        }
      }
      else -> return super.onOptionsItemSelected(item)
    }
    return true
  }

  private fun insecurePassphraseWarning(
    identifier: PGPIdentifier,
    subkeyIdentifier: KeyId?,
    oldPassphrase: CharArray?,
    passphrase: CharArray?,
  ) {
    val (title, message) =
      passphrase?.let {
        Pair(
          getString(R.string.pgp_key_short_passphrase_warning),
          getString(R.string.pgp_key_short_passphrase_warning_message),
        )
      }
        ?: Pair(
          getString(R.string.pgp_key_empty_passphrase_warning),
          getString(R.string.pgp_key_empty_passphrase_warning_message),
        )
    MaterialAlertDialogBuilder(this)
      .setIcon(R.drawable.ic_warning_red_24dp)
      .setTitle(title)
      .setMessage(message)
      .setPositiveButton(getString(R.string.pgp_key_insecure_passphrase_warning_confirm)) { _, _ ->
        changePassphrase(identifier, subkeyIdentifier, oldPassphrase, passphrase)
      }
      .setNegativeButton(R.string.dialog_cancel, null)
      .setCancelable(false)
      .setOnDismissListener {
        oldPassphrase?.wipe()
        passphrase?.wipe()
      }
      .show()
  }

  private fun changePassphrase(
    identifier: PGPIdentifier,
    subkeyIdentifier: KeyId?,
    oldPassphrase: CharArray?,
    passphrase: CharArray?,
  ) {
    val (key, error) =
      keyManager.changeKeyPassphrase(identifier, subkeyIdentifier, oldPassphrase, passphrase)

    if (key != null) {
      MaterialAlertDialogBuilder(this)
        .setTitle(getString(R.string.pgp_key_change_passphrase_succeeded))
        .setMessage(
          if (subkeyIdentifier == null)
            getString(R.string.pgp_key_change_passphrase_succeeded_message, tryGetKeyId(key))
          else getString(R.string.pgp_subkey_change_passphrase_succeeded_message, subkeyIdentifier)
        )
        .setPositiveButton(android.R.string.ok) { _, _ ->
          setResult(RESULT_OK)
          finish()
        }
        .setOnDismissListener {
          oldPassphrase?.wipe()
          passphrase?.wipe()
        }
        .setCancelable(false)
        .show()
    } else {
      logcat(ERROR) { error?.asLog() ?: "unknown error" }
      MaterialAlertDialogBuilder(this)
        .setTitle(getString(R.string.pgp_key_change_passphrase_error))
        .setIcon(R.drawable.ic_crossmark_red_24dp)
        .setMessage(error?.toString() ?: "unknown error")
        .setPositiveButton(android.R.string.ok) { _, _ ->
          setResult(RESULT_CANCELED)
          finish()
        }
        .setOnDismissListener {
          oldPassphrase?.wipe()
          passphrase?.wipe()
        }
        .setCancelable(false)
        .show()
    }
  }

  companion object {

    const val EXTRA_SELECTED_IDENTIFIER = "SELECTED_IDENTIFIER"
  }
}

private class KeySpinnerAdapter(
  context: Context,
  items: List<String>,
  private val disabledItems: List<Boolean>,
) : ArrayAdapter<String>(context, android.R.layout.simple_spinner_item, items) {

  override fun isEnabled(position: Int): Boolean {
    return !disabledItems.get(position)
  }

  override fun getDropDownView(position: Int, convertView: View?, parent: ViewGroup): View {
    val view = super.getDropDownView(position, convertView, parent)
    val textView = view as? TextView
    if (position > 0)
      textView?.typeface = ResourcesCompat.getFont(context, composeR.font.jetbrainsmono_nl_regular)
    view.isEnabled = isEnabled(position)
    return view
  }

  override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
    val view = super.getView(position, convertView, parent)
    val textView = view as? TextView
    if (position > 0)
      textView?.typeface = ResourcesCompat.getFont(context, composeR.font.jetbrainsmono_nl_regular)
    return view
  }
}
