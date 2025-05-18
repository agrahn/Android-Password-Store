/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
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
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.password.FieldItem
import app.passwordstore.databinding.DecryptLayoutBinding
import app.passwordstore.ui.adapters.FieldItemAdapter
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.settings.PreferenceKeys
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.logcat

@AndroidEntryPoint
class DecryptActivity : BasePGPActivity() {

  @Inject lateinit var passwordEntryFactory: PasswordEntry.Factory

  private val binding by viewBinding(DecryptLayoutBinding::inflate)
  private val relativeParentPath by unsafeLazy { getParentPath(fullPath, repoPath) }
  private var passwordEntry: PasswordEntry? = null

  private fun CharArray.isBlank() = this.isEmpty() || this.all { it.isWhitespace() }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    supportActionBar?.setDisplayHomeAsUpEnabled(true)
    title = name
    with(binding) {
      setContentView(root)
      passwordCategory.text = relativeParentPath
      passwordFile.text = name
      passwordFile.setOnLongClickListener {
        copyTextToClipboard(name.toCharArray(), isSensitive = false)
        true
      }
    }
    requireKeysExist {
      val gpgIdentifiers = getPGPIdentifiers(relativeParentPath) ?: return@requireKeysExist
      getPersistentAndDecrypt(gpgIdentifiers)
    }
  }

  override suspend fun decryptWithPassphrase(
    passphrases: Map<String, CharArray>,
    identifiers: List<PGPIdentifier>,
    onSuccess: suspend (String) -> Unit,
  ) {
    val message = withContext(dispatcherProvider.io()) { File(fullPath).readBytes().inputStream() }
    val outputStream = ByteArrayOutputStream()
    val (ids, result) = repository.decrypt(passphrases, identifiers, message, outputStream)
    if (result.isOk) {
      val entry = passwordEntryFactory.create(result.value.toByteArray())
      passwordEntry = entry
      createPasswordUI(entry)
      onSuccess(ids.first())
    } else {
      logcat(ERROR) { result.error.stackTraceToString() }
      when (result.error) {
        is IncorrectPassphraseException -> {
          /**
           * None of the provided passphrases worked, so remove them from temporary and persistent
           * caches.
           */
          persistentPassphrases.edit { ids.forEach { remove(it) } }
          ids.forEach {
            cachedPassphrases[it]?.fill('\u0000')
            cachedPassphrases.remove(it)
          }
          /* Retry */
          decrypt(identifiers, isError = true)
        }
        else -> {
          snackbar(message = result.error.toString())
        }
      }
    }
    if (!settings.getBoolean(PreferenceKeys.CACHE_PASSPHRASE, false)) {
      cachedPassphrases.values.forEach { it.fill('\u0000') }
      cachedPassphrases.clear()
    }
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.pgp_handler, menu)
    passwordEntry?.let { entry ->
      menu.findItem(R.id.edit_password).isVisible = true
      if (entry.password?.let { !it.isBlank() } ?: false) {
        menu.findItem(R.id.share_password_as_plaintext).isVisible = true
        menu.findItem(R.id.copy_password).isVisible = true
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
        clearTimer?.shutdownNow()
        clearTimer = copyPasswordToClipboard(passwordEntry?.password)
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
    val intent = Intent(this, PasswordCreationActivity::class.java)
    intent.action = Intent.ACTION_VIEW
    intent.putExtra("FILE_PATH", relativeParentPath)
    intent.putExtra("REPO_PATH", repoPath)
    intent.putExtra(PasswordCreationActivity.EXTRA_FILE_NAME, name)
    intent.putExtra(PasswordCreationActivity.EXTRA_USERNAME, passwordEntry?.username)
    intent.putExtra(PasswordCreationActivity.EXTRA_PASSWORD, passwordEntry?.password)
    intent.putExtra(PasswordCreationActivity.EXTRA_EXTRA_CONTENT, passwordEntry?.extraContentString)
    intent.putExtra(PasswordCreationActivity.EXTRA_EDITING, true)
    startActivity(intent)
    finish()
  }

  private fun shareAsPlaintext() {
    val sendIntent =
      Intent().apply {
        action = Intent.ACTION_SEND
        putExtra(Intent.EXTRA_TEXT, passwordEntry?.password?.let { String(it) })
        type = "text/plain"
      }
    // Always show a picker to give the user a chance to cancel
    startActivity(
      Intent.createChooser(sendIntent, resources.getText(R.string.send_plaintext_password_to))
    )
  }

  private suspend fun createPasswordUI(entry: PasswordEntry) =
    withContext(dispatcherProvider.main()) {
      val labelFormat = resources.getString(R.string.otp_label_format)
      val showPassword = settings.getBoolean(PreferenceKeys.SHOW_PASSWORD, false)
      invalidateOptionsMenu()

      val items = arrayListOf<FieldItem>()
      if (entry.password?.let { !it.isBlank() } ?: false) {
        items.add(
          FieldItem.createPasswordField(
            getString(R.string.password),
            entry.password ?: throw NullPointerException(),
          )
        )
        if (settings.getBoolean(PreferenceKeys.COPY_ON_DECRYPT, false)) {
          clearTimer?.shutdownNow()
          clearTimer = copyPasswordToClipboard(entry.password)
        }
      }

      if (entry.hasTotp()) {
        items.add(FieldItem.createOtpField(labelFormat, entry.totp.first()))
      }

      if (!entry.username.isNullOrBlank()) {
        items.add(
          FieldItem.createUsernameField(
            getString(R.string.username),
            entry.username ?: throw NullPointerException(),
          )
        )
      }

      entry.extraContent.forEach { (key, value) ->
        items.add(FieldItem.createFreeformField(key, value))
      }

      val adapter =
        FieldItemAdapter(items, showPassword) { text, isSensitive ->
          copyPasswordToClipboard(text?.toCharArray(), isSensitive)
        }
      binding.recyclerView.adapter = adapter
      binding.recyclerView.itemAnimator = null

      if (entry.hasTotp()) {
        lifecycleScope.launch { entry.totp.collect { adapter.updateOTPCode(it, labelFormat) } }
      }
    }

  private companion object {}
}
