/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.crypto

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.core.content.edit
import androidx.fragment.app.setFragmentResultListener
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.errors.NonStandardAEAD
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.password.FieldItem
import app.passwordstore.databinding.DecryptLayoutBinding
import app.passwordstore.ui.adapters.FieldItemAdapter
import app.passwordstore.ui.dialogs.BasicBottomSheet
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.features.Features
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.runCatching
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint
class DecryptActivity : BasePGPActivity() {

  @Inject lateinit var passwordEntryFactory: PasswordEntry.Factory
  @Inject lateinit var features: Features

  private val binding by viewBinding(DecryptLayoutBinding::inflate)
  private val relativeParentPath by unsafeLazy { getParentPath(fullPath, repoPath) }
  private var passwordEntry: PasswordEntry? = null
  private var retries = 0
  private var cacheEnabled = false

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    supportActionBar?.setDisplayHomeAsUpEnabled(true)
    title = name
    with(binding) {
      setContentView(root)
      passwordCategory.text = relativeParentPath
      passwordFile.text = name
      passwordFile.setOnLongClickListener {
        copyTextToClipboard(name)
        true
      }
    }
    requireKeysExist { decrypt(isError = false) }
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.pgp_handler, menu)
    passwordEntry?.let { entry ->
      menu.findItem(R.id.edit_password).isVisible = true
      if (!entry.password.isNullOrBlank()) {
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
      R.id.copy_password -> copyPasswordToClipboard(passwordEntry?.password)
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
    intent.putExtra(
      PasswordCreationActivity.EXTRA_EXTRA_CONTENT,
      passwordEntry?.extraContentWithoutUsername,
    )
    intent.putExtra(PasswordCreationActivity.EXTRA_EDITING, true)
    startActivity(intent)
    finish()
  }

  private fun shareAsPlaintext() {
    val sendIntent =
      Intent().apply {
        action = Intent.ACTION_SEND
        putExtra(Intent.EXTRA_TEXT, passwordEntry?.password)
        type = "text/plain"
      }
    // Always show a picker to give the user a chance to cancel
    startActivity(
      Intent.createChooser(sendIntent, resources.getText(R.string.send_plaintext_password_to))
    )
  }

  private fun decrypt(isError: Boolean) {
    val gpgIdentifiers = getPGPIdentifiers(relativeParentPath) ?: return
    val passphrase = cachedPassphrase
    lifecycleScope.launch(dispatcherProvider.main()) {
      passphrase?.let { decryptWithPassphrase(passphrase, gpgIdentifiers) }
        ?: askPassphrase(isError, gpgIdentifiers)
    }
  }

  private suspend fun askPassphrase(isError: Boolean, gpgIdentifiers: List<PGPIdentifier>) {
    if (retries < MAX_RETRIES) {
      retries += 1
    } else {
      finish()
    }
    if (!repository.isPasswordProtected(gpgIdentifiers)) {
      decryptWithPassphrase(passphrase = null, gpgIdentifiers)
      return
    }
    val dialog =
      PasswordDialog.newInstance(
        cacheEnabled = settings.getBoolean(PreferenceKeys.CACHE_PASSPHRASE, false)
      )
    if (isError) {
      dialog.setError()
    }
    dialog.show(supportFragmentManager, "PASSWORD_DIALOG")
    dialog.setFragmentResultListener(PasswordDialog.PASSWORD_RESULT_KEY) { key, bundle ->
      if (key == PasswordDialog.PASSWORD_RESULT_KEY) {
        val passphrase =
          bundle.getCharSequence(PasswordDialog.PASSWORD_PHRASE_KEY)?.toString()?.toCharArray()
            ?: throw NullPointerException()
        cacheEnabled = bundle.getBoolean(PasswordDialog.PASSWORD_CACHE_KEY)
        lifecycleScope.launch(dispatcherProvider.main()) {
          decryptWithPassphrase(passphrase, gpgIdentifiers) {
            runCatching {
                cachedPassphrase = if (cacheEnabled) passphrase else null
                settings.edit { putBoolean(PreferenceKeys.CACHE_PASSPHRASE, cacheEnabled) }
              }
              .onFailure { e -> logcat { e.asLog() } }
          }
        }
      }
    }
  }

  private suspend fun decryptWithPassphrase(
    passphrase: CharArray?,
    identifiers: List<PGPIdentifier>,
    onSuccess: suspend () -> Unit = {},
  ) {
    val message = withContext(dispatcherProvider.io()) { File(fullPath).readBytes().inputStream() }
    val outputStream = ByteArrayOutputStream()
    val result = repository.decrypt(passphrase, identifiers, message, outputStream)
    if (result.isOk) {
      val entry = passwordEntryFactory.create(result.value.toByteArray())
      passwordEntry = entry
      createPasswordUI(entry)
      startAutoDismissTimer()
      onSuccess()
    } else {
      logcat(ERROR) { result.error.stackTraceToString() }
      when (result.error) {
        is NonStandardAEAD -> {
          BasicBottomSheet.Builder(this)
            .setTitle(getString(R.string.aead_detect_title))
            .setMessage(getString(R.string.aead_detect_message, result.error.message))
            .setPositiveButtonClickListener(getString(R.string.dialog_ok)) {
              setResult(RESULT_CANCELED)
              finish()
            }
            .setOnDismissListener {
              setResult(RESULT_CANCELED)
              finish()
            }
            .build()
            .show(supportFragmentManager, "AEAD_INFO_SHEET")
        }
        else -> decrypt(isError = true)
      }
    }
  }

  private suspend fun createPasswordUI(entry: PasswordEntry) =
    withContext(dispatcherProvider.main()) {
      val labelFormat = resources.getString(R.string.otp_label_format)
      val showPassword = settings.getBoolean(PreferenceKeys.SHOW_PASSWORD, true)
      invalidateOptionsMenu()

      val items = arrayListOf<FieldItem>()
      if (!entry.password.isNullOrBlank()) {
        items.add(
          FieldItem.createPasswordField(
            getString(R.string.password),
            entry.password ?: throw NullPointerException(),
          )
        )
        if (settings.getBoolean(PreferenceKeys.COPY_ON_DECRYPT, false)) {
          copyPasswordToClipboard(entry.password)
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

      val adapter = FieldItemAdapter(items, showPassword) { text -> copyTextToClipboard(text) }
      binding.recyclerView.adapter = adapter
      binding.recyclerView.itemAnimator = null

      if (entry.hasTotp()) {
        lifecycleScope.launch { entry.totp.collect { adapter.updateOTPCode(it, labelFormat) } }
      }
    }

  private companion object {
    private const val MAX_RETRIES = 3
  }
}
