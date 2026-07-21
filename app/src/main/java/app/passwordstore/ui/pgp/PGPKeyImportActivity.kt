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
import app.passwordstore.crypto.KeyUtils.containsAnyFingerprint
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
import app.passwordstore.util.crypto.OpenPgpCardInfo
import app.passwordstore.util.crypto.OpenPgpNfcCard
import app.passwordstore.util.crypto.OpenPgpSmartcardStore
import app.passwordstore.util.extensions.snackbar
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getError
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.onOk
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URL
import javax.inject.Inject
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint
class PGPKeyImportActivity : AppCompatActivity() {

  @Inject lateinit var pgpKeyManager: PGPKeyManager
  @Inject lateinit var repository: CryptoRepository
  @Inject lateinit var dispatcherProvider: DispatcherProvider
  @Inject lateinit var smartcardStore: OpenPgpSmartcardStore

  private val MAX_RETRIES = 3
  private var retries = 0

  /** Keys parsed from the picked file that are still waiting to be processed. */
  private val pendingImports = mutableListOf<PGPKey>()
  /** [PGPIdentifier.KeyId]s of keys that were successfully stored. */
  private val importedKeyIds = mutableListOf<PGPIdentifier.KeyId>()
  /** Keys that ultimately failed to import along with the reason. */
  private val importFailures = mutableListOf<Pair<PGPKey, Throwable>>()
  private var pendingSmartcardInfo: OpenPgpCardInfo? = null

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
          importAllKeys(bytes, pendingSmartcardInfo?.fingerprints)
        } else {
          // incoming material may be a symmetrically encrypted key backup
          lifecycleScope.launch(dispatcherProvider.main()) { askBackupCode(bytes, isError = false) }
        }
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    if (intent.getBooleanExtra(EXTRA_IMPORT_FROM_NFC, false)) {
      importFromNfc()
      return
    }
    runCatching { pgpKeyImportAction.launch("*/*") }
      .onErr { e ->
        logcat(ERROR) { e.asLog() }
        e.message?.let { message -> snackbar(message = message) }
      }
  }

  override fun onDestroy() {
    OpenPgpNfcCard.disableReaderMode(this)
    super.onDestroy()
  }

  private fun importFromNfc() {
    val progressDialog =
      MaterialAlertDialogBuilder(this)
        .setTitle(R.string.openpgp_nfc_setup_title)
        .setMessage(R.string.openpgp_nfc_tap_card)
        .setNegativeButton(R.string.dialog_cancel, null)
        .setCancelable(true)
        .show()
    val cancelSignal = CompletableDeferred<Unit>()
    var canceled = false
    fun cancelNfcDialog() {
      if (cancelSignal.complete(Unit)) {
        canceled = true
        OpenPgpNfcCard.disableReaderMode(this)
        progressDialog.dismiss()
        setResult(RESULT_CANCELED)
        finish()
      }
    }
    progressDialog.setCanceledOnTouchOutside(true)
    progressDialog.setOnCancelListener { cancelNfcDialog() }
    progressDialog.getButton(android.app.AlertDialog.BUTTON_NEGATIVE).setOnClickListener {
      cancelNfcDialog()
    }
    lifecycleScope.launch(dispatcherProvider.main()) {
      while (!canceled) {
        progressDialog.setTitle(R.string.openpgp_nfc_setup_title)
        progressDialog.setMessage(getString(R.string.openpgp_nfc_tap_card))
        runCatching {
            val card =
              OpenPgpNfcCard.waitForCardOrNull(
                this@PGPKeyImportActivity,
                cancelSignal,
                disableReaderModeOnError = false,
                disableReaderModeOnClose = false,
                onCardDetected = {
                  progressDialog.setTitle(R.string.openpgp_nfc_hold_card_title)
                  progressDialog.setMessage(getString(R.string.openpgp_nfc_hold_card))
                },
              ) ?: return@launch
            card.use { it.readCardInfo() }
          }
          .onOk { cardInfo ->
            progressDialog.dismiss()
            setupSmartcardKey(cardInfo)
            return@launch
          }
          .onErr { e ->
            if (OpenPgpNfcCard.isTransceiveFailure(e)) {
              logcat(ERROR) { e.asLog() }
            } else {
              progressDialog.dismiss()
              logcat(ERROR) { e.asLog() }
              showNfcErrorDialog(e.message ?: getString(R.string.pgp_key_import_failed))
              return@launch
            }
          }
      }
    }
  }

  private suspend fun setupSmartcardKey(cardInfo: OpenPgpCardInfo) {
    if (cardInfo.fingerprints.isEmpty()) {
      showNfcErrorDialog(getString(R.string.openpgp_nfc_no_fingerprints))
      return
    }

    val localKey =
      withContext(dispatcherProvider.io()) {
        pgpKeyManager.getAllKeys().get()?.firstOrNull {
          containsAnyFingerprint(it, cardInfo.fingerprints)
        }
      }

    if (localKey != null) {
      associateSmartcardKey(localKey, cardInfo)
      return
    }

    if (cardInfo.url.isNullOrBlank()) {
      showNfcSetupDialog(cardInfo)
      return
    }

    val downloadResult = runCatching {
      withContext(dispatcherProvider.io()) { downloadKeyFromUrl(cardInfo.url) }
    }
    val bytes = downloadResult.get()
    if (bytes == null) {
      showNfcSetupDialog(cardInfo)
      return
    }
    if (!isCertificateOrKey(PGPKey(bytes))) {
      showNfcErrorDialog(getString(R.string.openpgp_nfc_url_no_openpgp_key))
      return
    }
    pendingSmartcardInfo = cardInfo
    importAllKeys(bytes, cardInfo.fingerprints)
  }

  /**
   * Fetches the public key advertised by the card's URL data object. The URL comes from the card
   * (potentially attacker-controlled), so only HTTPS is honored -- a plain-HTTP URL is trivially
   * MITM-able and schemes such as file:// would read local files -- and the download is capped so a
   * hostile endpoint cannot exhaust memory. A non-HTTPS URL simply falls back to manual import.
   */
  private fun downloadKeyFromUrl(url: String): ByteArray {
    val parsed = URL(url)
    if (!parsed.protocol.equals("https", ignoreCase = true)) {
      throw IOException("Refusing to fetch OpenPGP key over non-HTTPS URL")
    }
    parsed.openStream().use { stream ->
      val buffer = ByteArray(MAX_KEY_DOWNLOAD_BYTES)
      var total = 0
      while (total < buffer.size) {
        val read = stream.read(buffer, total, buffer.size - total)
        if (read == -1) break
        total += read
      }
      if (total == buffer.size && stream.read() != -1) {
        throw IOException("OpenPGP key at URL exceeds $MAX_KEY_DOWNLOAD_BYTES bytes")
      }
      return buffer.copyOf(total)
    }
  }

  private fun showNfcSetupDialog(cardInfo: OpenPgpCardInfo) {
    MaterialAlertDialogBuilder(this)
      .setTitle(R.string.openpgp_nfc_setup_detected_title)
      .setMessage(
        if (cardInfo.url.isNullOrBlank()) R.string.openpgp_nfc_setup_detected_no_url_message
        else R.string.openpgp_nfc_setup_detected_fetch_failed_message
      )
      .setPositiveButton(R.string.bottom_sheet_import_pgp_key) { _, _ ->
        pendingSmartcardInfo = cardInfo
        pgpKeyImportAction.launch("*/*")
      }
      .setNegativeButton(R.string.dialog_cancel) { _, _ ->
        OpenPgpNfcCard.disableReaderMode(this)
        setResult(RESULT_CANCELED)
        finish()
      }
      .setCancelable(false)
      .show()
  }

  private fun showNfcErrorDialog(message: String) {
    MaterialAlertDialogBuilder(this)
      .setTitle(R.string.openpgp_nfc_setup_failed_title)
      .setMessage(message)
      .setPositiveButton(android.R.string.ok) { _, _ ->
        OpenPgpNfcCard.disableReaderMode(this)
        setResult(RESULT_CANCELED)
        finish()
      }
      .setCancelable(false)
      .show()
  }

  /**
   * Splits [bytes] into one [PGPKey] per certificate/key block found and processes them
   * sequentially. A multi-key armored file (e.g. produced by `gpg --export A B C`) yields several
   * blocks; each is imported via [pgpKeyManager] independently, so partial failures
   * (already-exists, unusable) are reported per key without aborting the rest.
   */
  private fun importAllKeys(bytes: ByteArray, matchingFingerprints: List<ByteArray>? = null) {
    pendingImports.clear()
    importedKeyIds.clear()
    importFailures.clear()
    parseAllCertificatesOrKeys(PGPKey(bytes))
      .filter { cert ->
        matchingFingerprints == null ||
          containsAnyFingerprint(PGPKey(cert.getEncoded()), matchingFingerprints)
      }
      .forEach {
        pendingImports.add(PGPKey(it.getEncoded()))
      }
    if (pendingImports.isEmpty() && matchingFingerprints != null) {
      showNfcErrorDialog(getString(R.string.openpgp_nfc_fingerprint_mismatch))
      return
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
      result.get()?.let {
        tryGetKeyId(it)?.let(importedKeyIds::add)
        pendingSmartcardInfo?.let { cardInfo ->
          associateSmartcardKey(it, cardInfo, showDialog = false)
        }
      }
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
            retry.get()?.let {
              tryGetKeyId(it)?.let(importedKeyIds::add)
              pendingSmartcardInfo?.let { cardInfo ->
                associateSmartcardKey(it, cardInfo, showDialog = false)
              }
            }
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

  private fun associateSmartcardKey(
    key: PGPKey,
    cardInfo: OpenPgpCardInfo,
    showDialog: Boolean = true,
  ) {
    if (!containsAnyFingerprint(key, cardInfo.fingerprints)) {
      showNfcErrorDialog(getString(R.string.openpgp_nfc_fingerprint_mismatch))
      return
    }
    val keyId =
      tryGetKeyId(key)
        ?: run {
          showNfcErrorDialog(getString(R.string.pgp_key_import_failed))
          return
        }
    smartcardStore.associate(keyId, cardInfo.fingerprints, cardInfo.url)
    if (showDialog) {
      importedKeyIds.clear()
      importedKeyIds.add(keyId)
      showImportSummary()
    }
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

  companion object {
    const val EXTRA_IMPORT_FROM_NFC = "app.passwordstore.extra.IMPORT_FROM_NFC"

    // OpenPGP public keys are a few KiB at most; cap the card-URL download well above that.
    private const val MAX_KEY_DOWNLOAD_BYTES = 1 * 1024 * 1024
  }
}
