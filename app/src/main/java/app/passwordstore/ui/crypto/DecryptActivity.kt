/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.crypto

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.core.content.edit
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.password.FieldItem
import app.passwordstore.databinding.DecryptLayoutBinding
import app.passwordstore.ui.adapters.FieldItemAdapter
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.extensions.enableEdgeToEdgeView
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.toCharArray
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.getError
import com.github.michaelbull.result.getOrThrow
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@AndroidEntryPoint
class DecryptActivity : BasePGPActivity() {

  @Inject lateinit var passwordEntryFactory: PasswordEntry.Factory

  private var itemsAdapter: FieldItemAdapter? = null
  private val binding by viewBinding(DecryptLayoutBinding::inflate)
  private val relativeParentPath by unsafeLazy { getParentPath(fullPath, repoPath) }

  // temporarily AES-encrypted password entry
  private var encryptedEntryChars: CharArray? = null // AES encrypted password entry

  private fun CharArray.isBlank() = this.isEmpty() || this.all { it.isWhitespace() }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    supportActionBar?.setDisplayHomeAsUpEnabled(true)
    title = name
    with(binding) {
      enableEdgeToEdgeView(root)
      setContentView(root)
      passwordCategory.text = relativeParentPath
      passwordFile.text = name
      passwordFile.setOnLongClickListener {
        copyTextToClipboard(name.toCharArray(), isSensitive = false)
        true
      }
    }
    requireKeysExist {
      requireDecryptionKeysExist(relativeParentPath) { ids -> getPersistentAndDecrypt(ids) }
    }
  }

  override fun onDestroy() {
    encryptedEntryChars?.wipe()
    itemsAdapter?.clearItems()
    super.onDestroy()
  }

  override suspend fun decryptWithPassphrase(
    passphrases: Map<String, CharArray?>,
    identifiers: List<PGPIdentifier>,
    onSuccess: suspend (String) -> Unit,
  ) {
    val message = withContext(dispatcherProvider.io()) { File(fullPath).readBytes().inputStream() }
    val outputStream = ByteArrayOutputStream()
    val results = repository.decrypt(passphrases, identifiers, message, outputStream)
    val lastResult = results.last()
    if (lastResult.second.isOk) {
      val decryptedEntryBytes = lastResult.second.getOrThrow().toByteArray()
      lastResult.second.getOrThrow().wipe()
      val decryptedEntryChars = decryptedEntryBytes.toCharArray()
      decryptedEntryBytes.wipe()
      val entry = passwordEntryFactory.create(decryptedEntryChars)
      encryptedEntryChars = AESEncryption.encrypt(decryptedEntryChars)
      decryptedEntryChars.wipe()
      entry.clearExtraChars()
      createPasswordUI(entry)
      onSuccess(lastResult.first) // pass ID for which the entry was successfully decrypted
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
      } else {
        snackbar(message = resources.getString(R.string.password_decryption_unknown_error))
      }
    }
    if (!settings.getBoolean(PreferenceKeys.CACHE_PASSPHRASE, false)) {
      cachedPassphrases.values.forEach { it.wipe() }
      cachedPassphrases.clear()
    }
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.pgp_handler, menu)
    encryptedEntryChars?.let { encrypted ->
      menu.findItem(R.id.edit_password).isVisible = true
      AESEncryption.decrypt(encrypted)?.let { decrypted ->
        val entry = passwordEntryFactory.create(decrypted)
        decrypted.wipe()
        if (entry.password?.let { !it.isBlank() } ?: false) {
          menu.findItem(R.id.share_password_as_plaintext).isVisible = true
          menu.findItem(R.id.copy_password).isVisible = true
        }
        entry.clear()
      }
    }
    return true
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    when (item.itemId) {
      android.R.id.home -> onBackPressedDispatcher.onBackPressed()
      R.id.edit_password -> editPassword()
      R.id.share_password_as_plaintext -> shareAsPlaintext()
      R.id.copy_password -> {
        encryptedEntryChars?.let { encrypted ->
          AESEncryption.decrypt(encrypted)?.let { decrypted ->
            val entry = passwordEntryFactory.create(decrypted)
            decrypted.wipe()
            if (entry.password?.let { !it.isBlank() } ?: false) {
              clearTimer?.shutdownNow()
              clearTimer = copyPasswordToClipboard(entry?.password)
            }
            entry.clear()
          }
        }
      }
      else -> return super.onOptionsItemSelected(item)
    }
    return true
  }

  /**
   * Edit the current password and hide all the fields populated by encrypted data so that when the
   * result triggers they can be repopulated with new data.
   */
  private fun editPassword() {
    encryptedEntryChars?.let { encrypted ->
      val intent = Intent(this, PasswordCreationActivity::class.java)
      intent.action = Intent.ACTION_VIEW
      intent.putExtra("FILE_PATH", relativeParentPath)
      intent.putExtra("REPO_PATH", repoPath)
      intent.putExtra(PasswordCreationActivity.EXTRA_FILE_NAME, name)
      intent.putExtra(PasswordCreationActivity.EXTRA_ENTRY, encrypted)
      intent.putExtra(PasswordCreationActivity.EXTRA_EDITING, true)
      startActivity(intent)
      finish()
    }
  }

  private fun shareAsPlaintext() {
    encryptedEntryChars?.let { encrypted ->
      AESEncryption.decrypt(encrypted)?.let { decrypted ->
        val entry = passwordEntryFactory.create(decrypted)
        decrypted.wipe()
        if (entry.password?.let { !it.isBlank() } ?: false) {
          val sendIntent =
            Intent().apply {
              action = Intent.ACTION_SEND
              putExtra(Intent.EXTRA_TEXT, entry.password?.let { String(it) })
              type = "text/plain"
            }
          entry.clear()
          // Always show a picker to give the user a chance to cancel
          startActivity(
            Intent.createChooser(sendIntent, resources.getText(R.string.send_plaintext_password_to))
          )
        }
        entry.clear()
      }
    }
  }

  private suspend fun createPasswordUI(entry: PasswordEntry) =
    withContext(dispatcherProvider.main()) {
      val labelFormat = resources.getString(R.string.otp_label_format)
      val showPassword = settings.getBoolean(PreferenceKeys.SHOW_PASSWORD, false)
      invalidateOptionsMenu()

      entry.extraContentChars?.wipe() // not used here

      val items = arrayListOf<FieldItem>()
      if (entry.password?.let { !it.isBlank() } ?: false) {
        items.add(
          FieldItem.createPasswordField(
            getString(R.string.password),
            entry.password ?: throw NullPointerException(),
          )
        )
        if (settings.getBoolean(PreferenceKeys.COPY_ON_DECRYPT, false)) {
          entry.password?.let {
            clearTimer?.shutdownNow()
            clearTimer = copyPasswordToClipboard(it.copyOf(it.size))
          }
        }
      }

      if (entry.hasTotp()) {
        items.add(FieldItem.createOtpField(labelFormat, entry.totp.first()))
      }

      if (entry.username?.isNotEmpty() ?: false) {
        items.add(
          FieldItem.createUsernameField(
            getString(R.string.username),
            entry.username ?: throw NullPointerException(),
          )
        )
      }

      entry.extraContent.forEach { (key, value) ->
        if (key != PasswordEntry.EXTRA_CONTENT) {
          if (key.startsWith("*") && key.endsWith("*"))
            items.add(FieldItem.createPasswordField(key.substring(1, key.length - 1).trim(), value))
          else if (
            key.lowercase() in entry.unsafeKeys ||
              key.lowercase() in PasswordEntry.PASSWORD_FIELDS.map { it.dropLast(1) }
          )
            items.add(FieldItem.createPasswordField(key, value))
          else items.add(FieldItem.createFreeformField(key, value))
        }
      }

      entry.extraContent.forEach { (key, value) ->
        if (key.contentEquals(PasswordEntry.EXTRA_CONTENT))
          items.add(FieldItem.createFreeformField(getString(R.string.crypto_extra_label), value))
      }

      val adapter =
        FieldItemAdapter(items, showPassword) { text, isSensitive ->
          copyPasswordToClipboard(text, isSensitive)
        }

      itemsAdapter = adapter
      binding.recyclerView.adapter = adapter
      binding.recyclerView.itemAnimator = null

      if (entry.hasTotp()) {
        lifecycleScope.launch { entry.totp.collect { adapter.updateOTPCode(it, labelFormat) } }
      }
    }

  private companion object {}
}
