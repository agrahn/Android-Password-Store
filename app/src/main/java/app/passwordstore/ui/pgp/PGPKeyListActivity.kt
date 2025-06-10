/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.pgp

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.CheckBox
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.contract.ActivityResultContracts.CreateDocument
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.fragment.app.setFragmentResultListener
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.data.crypto.CryptoRepository
import app.passwordstore.ui.APSAppBar
import app.passwordstore.ui.compose.theme.APSTheme
import app.passwordstore.ui.dialogs.PasswordDialog
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.viewmodel.PGPKeyListViewModel
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.onSuccess
import com.github.michaelbull.result.runCatching
import com.github.michaelbull.result.unwrap
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.SecureRandom
import javax.inject.Inject
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint
class PGPKeyListActivity : AppCompatActivity() {

  @Inject lateinit var cryptoRepository: CryptoRepository
  @Inject lateinit var pgpKeyManager: PGPKeyManager

  /* Counter for the user's passphrase attempts */
  private var retries = 0

  private val viewModel: PGPKeyListViewModel by viewModels()
  private val keyImportAction =
    registerForActivityResult(StartActivityForResult()) {
      if (it.resultCode == RESULT_OK) {
        viewModel.updateKeySet()
      }
    }

  private var keyNumericId: String? = null
  private var keyContentsWithArmor: ByteArray? = null

  private val keyExportAction =
    registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) {
      uri ->
      if (uri != null) {
        writeBytesToUri(uri, keyContentsWithArmor)
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val isSelecting = intent.extras?.getBoolean(EXTRA_KEY_SELECTION) ?: false
    setContent {
      APSTheme {
        Scaffold(
          topBar = {
            APSAppBar(
              title =
                if (isSelecting) stringResource(R.string.activity_label_pgp_key_select)
                else stringResource(R.string.activity_label_pgp_key_manager),
              navigationIcon = painterResource(R.drawable.ic_arrow_back_black_24dp),
              onNavigationIconClick = { finish() },
              backgroundColor = MaterialTheme.colorScheme.surface,
            )
          },
          floatingActionButton = {
            FloatingActionButton(
              onClick = { keyImportAction.launch(Intent(this, PGPKeyImportActivity::class.java)) }
            ) {
              Icon(
                painter = painterResource(R.drawable.ic_add_48dp),
                stringResource(R.string.pref_import_pgp_key_title),
              )
            }
          },
        ) { paddingValues ->
          KeyList(
            identifiers = viewModel.keys,
            onDeleteItemClick = viewModel::deleteKey,
            onExportItemClick = ::exportKey,
            onExportPublicClick = ::exportPublicKey,
            modifier = Modifier.padding(paddingValues),
            onKeySelected =
              if (isSelecting) {
                { identifier ->
                  val keyId = runBlocking { // ensure numeric key ID
                    val key = pgpKeyManager.getKeyById(identifier).unwrap()
                    pgpKeyManager.getKeyId(key) ?: throw NullPointerException()
                  }
                  val result = Intent()
                  result.putExtra(EXTRA_SELECTED_KEY, keyId.toString())
                  setResult(RESULT_OK, result)
                  finish()
                }
              } else null,
          )
        }
      }
    }
  }

  private fun exportKey(identifier: PGPIdentifier) {
    retries = 0
    lifecycleScope.launch {
      if (cryptoRepository.isPasswordProtected(listOf(identifier))) {
        // export as symmetrically encrypted file after passphrase verification
        askPassphrase(identifier)
      } else if (cryptoRepository.hasSecretKey(identifier)) {
        // a secret key without passphrase is encrypted and exported without verification
        confirmBackupCode(identifier, generateBackupCode())
      } else {
        // write public key to file unencrypted
        writeBackupFile(identifier)
      }
    }
  }

  private fun exportPublicKey(identifier: PGPIdentifier) {
    lifecycleScope.launch { writeBackupFile(identifier) }
  }

  private fun askPassphrase(identifier: PGPIdentifier, isError: Boolean = false) {
    if (++retries > MAX_RETRIES) return

    val shortUserId = cryptoRepository.getEmailFromKeyId(identifier) ?: return
    val label = "${resources.getString(R.string.pgp_id_label)} ${shortUserId}"
    val dialog = PasswordDialog.newInstance(label, onCancelFinish = false)
    if (isError) dialog.setError()
    dialog.show(supportFragmentManager, "PASSWORD_DIALOG")
    dialog.setFragmentResultListener(PasswordDialog.PASSWORD_RESULT_KEY) { key, bundle ->
      if (key == PasswordDialog.PASSWORD_RESULT_KEY) {
        val passphrase =
          requireNotNull(bundle.getCharArray(PasswordDialog.PASSWORD_PHRASE_KEY)) {
            "returned passphrase is null"
          }
        lifecycleScope.launch {
          if (cryptoRepository.isPasswordCorrect(identifier, passphrase)) {
            confirmBackupCode(identifier, generateBackupCode())
          } else {
            askPassphrase(identifier, isError = true)
          }
        }
      }
    }
  }

  private fun generateBackupCode(numberOfGroups: Int = 9, digitsPerGroup: Int = 4) =
    List(numberOfGroups) { SecureRandom().nextInt(Math.pow(10.0, 1.0 * digitsPerGroup).toInt()) }
      .map { "$it".padStart(digitsPerGroup, '0') }
      .joinToString(separator = "-")

  private fun confirmBackupCode(identifier: PGPIdentifier, code: String) {
    val dialogView = layoutInflater.inflate(R.layout.dialog_with_ckeckbox, null)
    val checkBox = dialogView.findViewById<CheckBox>(R.id.checkbox)

    val dialog =
      MaterialAlertDialogBuilder(this)
        .setTitle(R.string.pgp_key_backupcode_title)
        .setView(dialogView)
        .setMessage(code)
        .setPositiveButton(R.string.dialog_ok) { _, _ ->
          lifecycleScope.launch { writeBackupFile(identifier, code) }
        }
        .create()

    dialog.setOnShowListener {
      val positiveButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
      positiveButton.isEnabled = false // start disabled
      checkBox.setText(R.string.pgp_key_backupcode_confirmation)
      checkBox.setOnCheckedChangeListener { _, isChecked -> positiveButton.isEnabled = isChecked }
    }

    dialog.show()
  }

  private fun writeBackupFile(identifier: PGPIdentifier, code: String? = null) {
    val keyIdAndContent = runBlocking {
      val key = pgpKeyManager.getKeyById(identifier).unwrap()
      val contents =
        if (code != null) { // encrypt secret keys symmetrically
          val keyContents = ByteArrayOutputStream()
          val result =
            cryptoRepository.encryptSym(
              code.toCharArray(),
              key.contents.inputStream(),
              keyContents,
              withArmor = true,
            )
          if (result.isOk) result.value.toByteArray() else null
        } else {
          KeyUtils.extractPublicKeyData(key)
        }
      Pair(pgpKeyManager.getKeyId(key), contents)
    }

    keyNumericId = keyIdAndContent.first?.toString()
    keyContentsWithArmor = keyIdAndContent.second

    if (keyContentsWithArmor != null) {
      val fileName = "keyID-${keyNumericId}." + (code?.let { "sec" } ?: "pub") + ".pgp"
      keyExportAction.launch(fileName)
    } else {
      snackbar(message = resources.getString(R.string.pgp_key_export_failed))
    }
  }

  private fun writeBytesToUri(uri: Uri, source: ByteArray?) {
    runCatching {
        val outputStream = contentResolver.openOutputStream(uri) ?: throw IOException()
        source?.inputStream().use { src -> outputStream.use { dest -> src?.copyTo(dest) } }
      }
      .onSuccess { snackbar(message = resources.getString(R.string.pgp_key_export_succeeded)) }
      .onFailure { e ->
        logcat(ERROR) { e.asLog() }
        snackbar(message = resources.getString(R.string.pgp_key_export_failed))
      }
  }

  companion object {
    const val MAX_RETRIES = 3

    const val EXTRA_SELECTED_KEY = "SELECTED_KEY"
    const val EXTRA_KEY_SELECTION = "KEY_SELECTION_MODE"

    fun newSelectionActivity(context: Context): Intent {
      val intent = Intent(context, PGPKeyListActivity::class.java)
      intent.putExtra(EXTRA_KEY_SELECTION, true)
      return intent
    }
  }
}
