/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.crypto

import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.core.content.edit
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.password.FieldItem
import app.passwordstore.databinding.DecryptLayoutBinding
import app.passwordstore.injection.prefs.CredentialUsernames
import app.passwordstore.injection.prefs.PasswordHistory
import app.passwordstore.ui.adapters.FieldItemAdapter
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import app.passwordstore.util.crypto.OpenPgpCardPrompt
import app.passwordstore.util.crypto.OpenPgpNfcCard
import app.passwordstore.util.extensions.base64
import app.passwordstore.util.extensions.enableEdgeToEdgeView
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.toCharArray
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.settings.PreferenceKeys
import app.passwordstore.util.shortcuts.ShortcutHandler
import com.github.michaelbull.result.getError
import com.github.michaelbull.result.getOrThrow
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Paths
import javax.inject.Inject
import kotlin.io.path.pathString
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@AndroidEntryPoint
class DecryptActivity : BasePGPActivity() {

  @Inject lateinit var passwordEntryFactory: PasswordEntry.Factory
  @Inject lateinit var shortcutHandler: ShortcutHandler
  @CredentialUsernames @Inject lateinit var credentialUsernames: SharedPreferences
  @PasswordHistory @Inject lateinit var passwordHistory: SharedPreferences

  private var itemsAdapter: FieldItemAdapter? = null
  private val binding by viewBinding(DecryptLayoutBinding::inflate)

  // temporarily AES-encrypted password entry
  private var encryptedEntryChars: CharArray? = null // AES encrypted password entry

  private fun CharArray.isBlank() = this.isEmpty() || this.all { it.isWhitespace() }

  private var isPasskey: Boolean = false

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    // The entry may have been deleted since a launcher shortcut was created for it; bail out
    // gracefully (and prune the stale shortcut) instead of crashing when we try to read the file.
    if (!File(fullPath).exists()) {
      Toast.makeText(this, R.string.password_no_longer_exists, Toast.LENGTH_LONG).show()
      shortcutHandler.pruneDynamicShortcuts()
      finish()
      return
    }
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
      fab.setOnClickListener { copyPassword() }
    }
    requireKeysExist {
      requireDecryptionKeysExist(relativeParentPath) { ids -> getPersistentAndDecrypt(ids) }
    }
  }

  override fun onDestroy() {
    OpenPgpNfcCard.disableReaderMode(this)
    encryptedEntryChars?.wipe()
    itemsAdapter?.clearItems()
    super.onDestroy()
  }

  override suspend fun decryptWithPassphrase(
    passphrases: Map<String, CharArray?>,
    identifiers: List<PGPIdentifier>,
    onSuccess: suspend (String) -> Unit,
  ) {
    if (identifiers.any { repository.hasOnlyStubDecKey(it) || repository.isSmartcardBacked(it) }) {
      decryptWithSmartcard(passphrases, identifiers, onSuccess)
      return
    }
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

      passwordHistory.edit { // create/update timestamp on the current password file
        putString(
          fullPath.base64(),
          System.currentTimeMillis().toString(),
        )
      }
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

  private suspend fun decryptWithSmartcard(
    passphrases: Map<String, CharArray?>,
    identifiers: List<PGPIdentifier>,
    onSuccess: suspend (String) -> Unit,
  ) {
    val messageBytes = withContext(dispatcherProvider.io()) { File(fullPath).readBytes() }
    val outputStream = ByteArrayOutputStream()
    // Modern smartcard UX: one persistent reader, a reused present/hold-card dialog, the card
    // operation run on the card's own thread, inline PIN entry with retries (so reader mode stays
    // on across wrong PINs and never triggers the NDEF-URL popup), and reader mode released only
    // once the card is physically removed. The shared loop lives in OpenPgpCardPrompt.runWithPin.
    val prompt = OpenPgpCardPrompt(this, R.string.openpgp_nfc_decrypt_title, dispatcherProvider)
    val reader = prompt.createReader()
    if (reader == null) {
      showSmartcardError(getString(R.string.openpgp_nfc_unavailable))
      return
    }
    var readerHandedOff = false
    try {
      val outcome =
        prompt.runWithPin(
          reader = reader,
          // Namespaced so the decryption PIN cache is kept separate from the signing PIN cache.
          cacheKey = "decrypt:${identifiers.firstOrNull()}",
          pinTitleRes = R.string.openpgp_card_pin_title,
          pinHintRes = R.string.openpgp_card_pin_hint,
          identityLabel = getIdentityLabelForIdentifiers(identifiers),
          pinMode = OpenPgpCardPrompt.PinMode.USER,
          presentMessage = getString(R.string.openpgp_nfc_tap_card),
          commFailedMessage = getString(R.string.openpgp_nfc_card_comm_failed),
          // Seed the PIN from a caller-provided (e.g. biometric-unlocked) value.
          seedPin = passphrases.values.firstOrNull()?.takeIf { it.isNotEmpty() },
        ) { card, currentPin ->
          val results =
            repository.decryptWithSmartcard(
              currentPin,
              identifiers,
              messageBytes.inputStream(),
              outputStream,
              card,
            )
          // Surface a decryption failure (wrong PIN, transceive error, ...) as a thrown exception
          // so the prompt can classify it.
          results.last().second.getError()?.let { throw it }
          results
        }
      when (outcome) {
        is OpenPgpCardPrompt.CardOutcome.Success -> {
          readerHandedOff = true
          prompt.releaseReaderWhenCardRemoved(outcome.card, reader)
          val lastResult = outcome.value.last()
          val decryptedEntryBytes = lastResult.second.getOrThrow().toByteArray()
          lastResult.second.getOrThrow().wipe()
          val decryptedEntryChars = decryptedEntryBytes.toCharArray()
          decryptedEntryBytes.wipe()
          val entry = passwordEntryFactory.create(decryptedEntryChars)
          encryptedEntryChars = AESEncryption.encrypt(decryptedEntryChars)
          decryptedEntryChars.wipe()
          entry.clearExtraChars()
          createPasswordUI(entry)
          onSuccess(lastResult.first)
        }
        OpenPgpCardPrompt.CardOutcome.Cancelled -> {
          readerHandedOff = true
          prompt.releaseReaderWhenCardRemoved(null, reader)
          finish()
        }
        is OpenPgpCardPrompt.CardOutcome.Blocked -> {
          readerHandedOff = true
          prompt.releaseReaderWhenCardRemoved(outcome.card, reader)
          showSmartcardError(getString(R.string.openpgp_card_pin_blocked))
        }
        is OpenPgpCardPrompt.CardOutcome.Failed -> {
          readerHandedOff = true
          prompt.releaseReaderWhenCardRemoved(outcome.card, reader)
          showSmartcardError(friendlySmartcardError(outcome.error))
        }
      }
    } finally {
      prompt.dismissDialog()
      if (!readerHandedOff) prompt.releaseReaderWhenCardRemoved(null, reader)
    }
  }

  private fun showSmartcardError(message: String) {
    MaterialAlertDialogBuilder(this)
      .setTitle(R.string.openpgp_nfc_decrypt_failed_title)
      .setMessage(message)
      .setPositiveButton(android.R.string.ok) { _, _ ->
        // Reader mode is disabled by the removal watcher once the card is lifted; just finish.
        finish()
      }
      .setCancelable(false)
      .show()
  }

  private fun friendlySmartcardError(error: Throwable?): String =
    if (OpenPgpCardPrompt.isSmartcardPinFailure(error)) {
      resources.getString(R.string.openpgp_card_wrong_pin)
    } else {
      error?.message ?: resources.getString(R.string.password_decryption_unknown_error)
    }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.pgp_handler, menu)
    return true
  }

  override fun onPrepareOptionsMenu(menu: Menu): Boolean {
    encryptedEntryChars?.let { encrypted ->
      menu.findItem(R.id.edit_password).setVisible(true)
      AESEncryption.decrypt(encrypted)?.let { decrypted ->
        val entry = passwordEntryFactory.create(decrypted)
        decrypted.wipe()
        if (!isPasskey && entry.password?.let { !it.isBlank() } ?: false) {
          menu.findItem(R.id.share_password_as_plaintext).setVisible(true)
          menu.findItem(R.id.copy_password).setVisible(true)
          binding.fab.setVisibility(View.VISIBLE)
        }
        entry.clear()
      }
    }

    return true
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    when (item.itemId) {
      android.R.id.home -> onBackPressedDispatcher.onBackPressed()
      R.id.edit_password -> {
        if (isPasskey) editPasskey() else editPassword()
      }
      R.id.share_password_as_plaintext -> shareAsPlaintext()
      R.id.copy_password -> copyPassword()
      else -> return super.onOptionsItemSelected(item)
    }
    return true
  }

  private fun copyPassword() {
    encryptedEntryChars?.let { encrypted ->
      AESEncryption.decrypt(encrypted)?.let { decrypted ->
        val entry = passwordEntryFactory.create(decrypted)
        decrypted.wipe()
        if (entry.password?.let { !it.isBlank() } ?: false) {
          clearTimer?.shutdownNow()
          clearTimer = copyPasswordToClipboard(entry.password)
        }
        entry.clear()
      }
    }
  }

  private fun editPassword() {
    encryptedEntryChars?.let { encrypted ->
      val intent = Intent(this, PasswordCreationActivity::class.java)
      intent.action = Intent.ACTION_VIEW
      intent.putExtra(EXTRA_FILE_PATH, Paths.get(fullPath).parent.pathString)
      intent.putExtra(EXTRA_REPO_PATH, repoPath)
      intent.putExtra(PasswordCreationActivity.EXTRA_FILE_NAME, name)
      intent.putExtra(PasswordCreationActivity.EXTRA_ENTRY, encrypted)
      intent.putExtra(PasswordCreationActivity.EXTRA_EDITING, true)
      startActivity(intent)
      finish()
    }
  }

  private fun editPasskey() {
    encryptedEntryChars?.let { encrypted ->
      val intent = Intent(this, PasskeyCreationActivity::class.java)
      intent.action = Intent.ACTION_VIEW
      intent.putExtra(EXTRA_FILE_PATH, Paths.get(fullPath).parent.pathString)
      intent.putExtra(EXTRA_REPO_PATH, repoPath)
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
      entry.extraContentChars?.wipe() // not used here

      val passkey = retrievePasskey(entry, stripped = true)

      isPasskey = passkey != null

      invalidateOptionsMenu() // redraws/enables menu items in the action bar

      val items = arrayListOf<FieldItem>()

      if (passkey != null) {
        items.add(
          FieldItem.createNoCopyFreeformField(
            getString(R.string.passkey),
            "${getString(R.string.cred_algorithm_hint)}: ${passkey.getAlgorithmString()}, "
              .toCharArray() +
              getString(R.string.created_date, passkey.creationDateTimeString()).toCharArray(),
          )
        )

        items.add(
          FieldItem.createFreeformField(
            getString(R.string.rp_name_hint),
            passkey.rp.id.toCharArray(),
          )
        )

        items.add(
          FieldItem.createUsernameField(
            getString(R.string.username),
            passkey.user.name.toCharArray(),
          )
        )

        if (passkey.user.displayName != null && passkey.user.displayName != passkey.user.name) {
          items.add(
            FieldItem.createUsernameField(
              getString(R.string.fullname_hint),
              passkey.user.displayName.toCharArray(),
            )
          )
        }

        // maintain cred hex ID <-> user name map for display on passkey selector
        credentialUsernames.edit {
          if (passkey.user.revealName) {
            val displayUser =
              if (passkey.user.displayName != null && passkey.user.displayName != passkey.user.name)
                "${passkey.user.name} (${passkey.user.displayName})"
              else passkey.user.name
            putString(
              passkey.idHex(),
              AESEncryption.encrypt(displayUser.toCharArray(), keyType = KeyType.PERSISTENT)
                ?.concatToString(),
            )
          } else {
            remove(passkey.idHex())
          }
        }
      } else if (entry.password?.let { !it.isBlank() } ?: false) {
        // password
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
      val labelFormat = resources.getString(R.string.otp_label_format)
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
          if (settings.getBoolean(PreferenceKeys.SHOW_EXTRA_CONTENT, true))
            items.add(FieldItem.createFreeformField(getString(R.string.crypto_extra_label), value))
          else
            items.add(FieldItem.createPasswordField(getString(R.string.crypto_extra_label), value))
      }

      val showPassword = settings.getBoolean(PreferenceKeys.SHOW_PASSWORD, false)
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
