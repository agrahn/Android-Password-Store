/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("BlockingMethodInNonBlockingContext")

package app.passwordstore.ui.pgp

import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts.GetContent
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.setFragmentResultListener
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.KeyUtils.isCertificateOrKey
import app.passwordstore.crypto.KeyUtils.tryGetKeyId
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.crypto.errors.KeyAlreadyExistsException
import app.passwordstore.crypto.errors.UnusableKeyException
import app.passwordstore.data.crypto.CryptoRepository
import app.passwordstore.ui.dialogs.TextInputDialog
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.snackbar
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getError
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.inject.Inject
import kotlinx.coroutines.launch
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint
class PGPKeyImportActivity : AppCompatActivity() {

  /**
   * A [ByteArray] containing the contents of the previously selected file. This is necessary for
   * the replacement case where we do not want users to have to pick the file again.
   */
  private var lastBytes: ByteArray? = null
  @Inject lateinit var keyManager: PGPKeyManager
  @Inject lateinit var repository: CryptoRepository
  @Inject lateinit var dispatcherProvider: DispatcherProvider

  private val MAX_RETRIES = 3
  private var retries = 0

  private val pgpKeyImportAction =
    registerForActivityResult(GetContent()) { uri ->
      runCatching {
        if (uri == null) {
          finish()
          return@runCatching
        }
        val keyInputStream =
          contentResolver.openInputStream(uri)
            ?: throw IllegalStateException("Failed to open selected file")
        val bytes = keyInputStream.use { `is` -> `is`.readBytes() }
        if (isCertificateOrKey(PGPKey(bytes))) {
          runCatching { importKey(bytes, false) }.run(::handleImportResult)
        } else {
          // incoming material may be a symmetrically encrypted key backup
          lifecycleScope.launch(dispatcherProvider.main()) { askBackupCode(bytes, isError = false) }
        }
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    runCatching { pgpKeyImportAction.launch("*/*") }
      .onFailure { e ->
        logcat(ERROR) { e.asLog() }
        e.message?.let { message -> snackbar(message = message) }
      }
  }

  override fun onDestroy() {
    lastBytes = null
    super.onDestroy()
  }

  private fun importKey(bytes: ByteArray, replace: Boolean): PGPKey? {
    lastBytes = bytes
    val (key, error) = keyManager.addKey(PGPKey(bytes), replace = replace)
    if (replace) {
      lastBytes = null
    }
    if (error != null) throw error
    return key
  }

  private suspend fun askBackupCode(bytes: ByteArray, isError: Boolean) {
    if (++retries > MAX_RETRIES) finish()
    val dialog = TextInputDialog.newInstance(getString(R.string.pgp_key_backupcode_title))
    if (isError && retries > 1) dialog.setError()
    dialog.show(supportFragmentManager, "BACKUPCODE_INPUT_DIALOG")
    dialog.setFragmentResultListener(TextInputDialog.REQUEST_KEY) { key, bundle ->
      if (key == TextInputDialog.REQUEST_KEY) {
        val backupCode =
          requireNotNull(bundle.getString(TextInputDialog.BUNDLE_KEY_TEXT)?.toCharArray()) {
            "returned backup code is null"
          }
        lifecycleScope.launch(dispatcherProvider.main()) {
          decryptWithBackupCode(backupCode, bytes)
        }
      }
    }
  }

  suspend fun decryptWithBackupCode(backupCode: CharArray, bytes: ByteArray) {
    val message = ByteArrayInputStream(bytes)
    val outputStream = ByteArrayOutputStream()
    val result = repository.decryptSym(backupCode, message, outputStream)
    if (result.isOk) {
      val decryptedBytes = result.getOrThrow().toByteArray()
      runCatching { importKey(decryptedBytes, false) }.run(::handleImportResult)
    } else {
      result.getError()?.let { logcat { it.asLog() } }
      askBackupCode(bytes, isError = true) // retry
    }
  }

  private fun handleImportResult(result: Result<PGPKey?, Throwable>) {
    if (result.isOk) {
      val key = result.get()
      if (key == null) {
        setResult(RESULT_CANCELED)
        finish()
        /* This return convinces Kotlin that the control flow for `key == null` definitely
        terminates here and allows for a smart cast below. */
        return
      }
      MaterialAlertDialogBuilder(this)
        .setTitle(getString(R.string.pgp_key_import_succeeded))
        .setMessage(getString(R.string.pgp_key_import_succeeded_message, tryGetKeyId(key)))
        .setPositiveButton(android.R.string.ok) { _, _ ->
          setResult(RESULT_OK)
          finish()
        }
        .setCancelable(false)
        .show()
    } else {
      val dialog =
        MaterialAlertDialogBuilder(this)
          .setTitle(getString(R.string.pgp_key_import_failed))
          .setCancelable(false)

      val error = result.getError()
      if (error is KeyAlreadyExistsException && lastBytes != null) {
        dialog
          .setMessage(getString(R.string.pgp_key_import_failed_replace_message))
          .setPositiveButton(R.string.dialog_yes) { _, _ ->
            handleImportResult(
              runCatching { importKey(lastBytes ?: throw NullPointerException(), replace = true) }
            )
          }
          .setNegativeButton(R.string.dialog_no) { _, _ -> finish() }
      } else {
        val errMessage =
          if (error is UnusableKeyException) {
            getString(R.string.pgp_key_import_failed_unusable_message)
          } else error?.message
        dialog.setMessage(errMessage).setPositiveButton(android.R.string.ok) { _, _ -> finish() }
      }

      dialog.show()
    }
  }
}
