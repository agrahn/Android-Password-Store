/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("BlockingMethodInNonBlockingContext")

package app.passwordstore.ui.pgp

import android.content.Intent
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts.GetContent
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.setFragmentResultListener
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.KeyUtils.isCertificateOrKey
import app.passwordstore.crypto.KeyUtils.parseAllCertificatesOrKeys
import app.passwordstore.crypto.KeyUtils.tryGetKeyId
import app.passwordstore.crypto.PGPIdentifier
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
import com.github.michaelbull.result.onErr
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

  @Inject lateinit var pgpKeyManager: PGPKeyManager
  @Inject lateinit var repository: CryptoRepository
  @Inject lateinit var dispatcherProvider: DispatcherProvider

  private val MAX_RETRIES = 3
  private var retries = 0

  /** Keys parsed from the picked file that are still waiting to be processed. */
  private val pendingImports = mutableListOf<PGPKey>()
  /** [PGPIdentifier.KeyId]s of keys that were successfully stored. */
  private val importedKeyIds = mutableListOf<PGPIdentifier.KeyId>()
  /** Keys that ultimately failed to import along with the reason. */
  private val importFailures = mutableListOf<Pair<PGPKey, Throwable>>()

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
          importAllKeys(bytes)
        } else {
          // incoming material may be a symmetrically encrypted key backup
          lifecycleScope.launch(dispatcherProvider.main()) { askBackupCode(bytes, isError = false) }
        }
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    runCatching { pgpKeyImportAction.launch("*/*") }
      .onErr { e ->
        logcat(ERROR) { e.asLog() }
        e.message?.let { message -> snackbar(message = message) }
      }
  }

  /**
   * Splits [bytes] into one [PGPKey] per certificate/key block found and processes them
   * sequentially. A multi-key armored file (e.g. produced by `gpg --export A B C`) yields several
   * blocks; each is imported via [pgpKeyManager] independently, so partial failures
   * (already-exists, unusable) are reported per key without aborting the rest.
   */
  private fun importAllKeys(bytes: ByteArray) {
    pendingImports.clear()
    importedKeyIds.clear()
    importFailures.clear()
    parseAllCertificatesOrKeys(PGPKey(bytes)).forEach {
      pendingImports.add(PGPKey(it.getEncoded()))
    }
    processNextImport()
  }

  private fun processNextImport() {
    if (pendingImports.isEmpty()) {
      showImportSummary()
      return
    }
    val key = pendingImports.removeAt(0)
    val result = runCatching { addKeyOrThrow(key, replace = false) }
    handleSingleImportResult(result, key)
  }

  private fun handleSingleImportResult(result: Result<PGPKey?, Throwable>, sourceKey: PGPKey) {
    if (result.isOk) {
      result.get()?.let { tryGetKeyId(it)?.let(importedKeyIds::add) }
      processNextImport()
      return
    }
    val error = result.getError()
    if (error is KeyAlreadyExistsException) {
      val keyId = tryGetKeyId(sourceKey)
      MaterialAlertDialogBuilder(this)
        .setTitle(getString(R.string.pgp_key_import_failed))
        .setMessage(getString(R.string.pgp_key_import_failed_replace_message, keyId))
        .setPositiveButton(R.string.dialog_yes) { _, _ ->
          val retry = runCatching { addKeyOrThrow(sourceKey, replace = true) }
          if (retry.isOk) {
            retry.get()?.let { tryGetKeyId(it)?.let(importedKeyIds::add) }
          } else {
            importFailures.add(sourceKey to (retry.getError() ?: error))
          }
          processNextImport()
        }
        .setNegativeButton(R.string.dialog_no) { _, _ ->
          importFailures.add(sourceKey to error)
          processNextImport()
        }
        .setCancelable(false)
        .show()
    } else {
      importFailures.add(sourceKey to (error ?: NullPointerException()))
      processNextImport()
    }
  }

  private fun addKeyOrThrow(key: PGPKey, replace: Boolean): PGPKey? {
    val (stored, error) = pgpKeyManager.addKey(key, replace = replace)
    if (error != null) throw error
    return stored
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
      importAllKeys(decryptedBytes)
    } else {
      result.getError()?.let { logcat { it.asLog() } }
      askBackupCode(bytes, isError = true) // retry
    }
  }

  private fun showImportSummary() {
    if (importedKeyIds.isEmpty() && importFailures.isEmpty()) {
      setResult(RESULT_CANCELED)
      finish()
      return
    }

    val successText =
      resources.getQuantityString(
        R.plurals.pgp_key_import_success_message,
        importedKeyIds.size,
        importedKeyIds.size,
      ) + "\n\n" + importedKeyIds.joinToString(prefix = "\t", separator = "\n\t")

    val failureText =
      resources.getQuantityString(
        R.plurals.pgp_key_import_failure_message,
        importFailures.size,
        importFailures.size,
      ) +
        "\n\n" +
        importFailures.joinToString("\n") { (k, e) ->
          val id = tryGetKeyId(k)?.toString() ?: "?"
          val reason =
            when (e) {
              is KeyAlreadyExistsException -> getString(R.string.pgp_key_import_skipped_existing)
              is UnusableKeyException -> getString(R.string.pgp_key_import_failed_unusable_message)
              else -> e.message ?: e::class.simpleName ?: "error"
            }
          "$id: $reason"
        }

    val titleAndMessage =
      if (importFailures.isEmpty()) { // all succeeded
        resources.getQuantityString(
          R.plurals.pgp_key_import_success_title,
          importedKeyIds.size,
          importedKeyIds.size,
        ) to successText
      } else if (importedKeyIds.isEmpty()) { // all failed
        resources.getQuantityString(
          R.plurals.pgp_key_import_failure_title,
          importFailures.size,
          importFailures.size,
        ) to failureText
      } else { // partial success
        getString(R.string.pgp_key_import_partial_success_title) to
          successText + "\n\n" + failureText
      }

    val builder =
      MaterialAlertDialogBuilder(this)
        .setCancelable(false)
        .setTitle(titleAndMessage.first)
        .setMessage(titleAndMessage.second)
        .setPositiveButton(android.R.string.ok) { _, _ ->
          if (importedKeyIds.isNotEmpty()) {
            setResult(
              RESULT_OK,
              Intent().putExtra("PGP_KEY_IDS", importedKeyIds.map { it.id }.toLongArray()),
            )
          } else {
            setResult(RESULT_CANCELED)
          }
          finish()
        }
        .show()
  }
}
