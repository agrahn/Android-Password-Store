/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
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
import app.passwordstore.ui.dialogs.AddPgpKeyBottomSheet
import app.passwordstore.ui.dialogs.PasswordDialog
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.viewmodel.PGPKeyListViewModel
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.onSuccess
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.SecureRandom
import javax.inject.Inject
import kotlinx.coroutines.launch
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

  private val keyAction =
    registerForActivityResult(StartActivityForResult()) {
      if (it.resultCode == RESULT_OK) {
        if (isAddingKeys) keysAdded = true
        viewModel.updateKeySet()
      }
    }

  private var keyNumericId: String? = null
  private var keyContentsWithArmor: ByteArray? = null

  var keysAdded = false
  var isAddingKeys = false

  private val keyExportAction =
    registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) {
      uri ->
      if (uri != null) {
        writeBytesToUri(uri, keyContentsWithArmor)
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    val singleSelection = intent.extras?.getBoolean(EXTRA_KEY_FOR_SSH) ?: false
    val isSelectingKeys = intent.extras?.getBoolean(EXTRA_KEY_SELECTION) ?: false
    val selectedKeyIds = mutableSetOf<String>()

    supportFragmentManager.setFragmentResultListener(PGP_KEY_ADD_REQUEST_KEY, this) { _, bundle ->
      when (bundle.getString(ACTION_KEY)) {
        ACTION_IMPORT_FILE -> {
          keyAction.launch(Intent(this, PGPKeyImportActivity::class.java))
          isAddingKeys = true
        }
        ACTION_NEW_PGP_KEY -> {
          keyAction.launch(Intent(this, PGPKeyCreationActivity::class.java))
          isAddingKeys = true
        }
      }
    }

    setContent {
      APSTheme {
        Scaffold(
          topBar = {
            APSAppBar(
              title =
                if (isSelectingKeys) {
                  if(singleSelection)  
                    stringResource(R.string.activity_label_pgp_key_single_select)
                  else  
                    stringResource(R.string.activity_label_pgp_key_select)
                }    
                else stringResource(R.string.activity_label_pgp_key_manager),
              navigationIcon = painterResource(R.drawable.ic_arrow_back_24dp),
              onNavigationIconClick = {
                if (isSelectingKeys && selectedKeyIds.isNotEmpty()) {
                  val result = Intent()
                  result.putExtra(EXTRA_SELECTED_KEY, selectedKeyIds.joinToString(separator = "\n"))
                  val gpgIdDest = intent.getStringExtra("SUB_PATH")
                  gpgIdDest?.let { result.putExtra("SUB_PATH", it) }
                  setResult(RESULT_OK, result)
                } else if (isAddingKeys && keysAdded) {
                  setResult(RESULT_OK, Intent())
                }
                finish()
              },
              backgroundColor = MaterialTheme.colorScheme.surface,
            )
          },
          floatingActionButton = {
            FloatingActionButton(
              onClick = {
                AddPgpKeyBottomSheet().show(supportFragmentManager, "ADD_PGP_KEY_BOTTOM_SHEET")
              }
            ) {
              Icon(
                painter = painterResource(R.drawable.ic_add_48dp),
                stringResource(R.string.pref_import_pgp_key_title),
              )
            }
          },
        ) { paddingValues ->
          KeyList(
            identifiers = viewModel.keys, // Pair<KeyId,UserId>
            isSecretKey = ::isSecretKey,
            onChangePassphraseClick = ::changeKeyPassphrase,
            onDeleteItemClick = ::deleteKey,
            onExportItemClick = ::exportKey,
            onExportPublicClick = ::exportPublicKey,
            modifier = Modifier.padding(paddingValues),
            onKeySelected =
              if (isSelectingKeys) {
                { identifier, isSelected ->
                  val keyId = run { // ensure numeric key ID
                    val key = pgpKeyManager.getKeyById(identifier).getOrThrow()
                    KeyUtils.tryGetKeyId(key) ?: throw NullPointerException()
                  }
                  if (singleSelection) selectedKeyIds.clear()
                  if (isSelected) selectedKeyIds.add(keyId.toString())
                  else selectedKeyIds.remove(keyId.toString())
                }
              } else null,
            singleSelection = singleSelection,
          )
        }
      }
    }
  }

  private fun isSecretKey(identifier: PGPIdentifier): Boolean =
    cryptoRepository.isSecretKey(identifier)

  private fun changeKeyPassphrase(identifier: PGPIdentifier) {
    val intent = Intent(this, PGPKeyChangePassphraseActivity::class.java)
    intent.putExtra(PGPKeyChangePassphraseActivity.EXTRA_SELECTED_IDENTIFIER, identifier.toString())
    keyAction.launch(intent)
  }

  private fun deleteKey(identifier: PGPIdentifier) {
    val keyIdPassedIn =
      KeyUtils.tryGetKeyId(pgpKeyManager.getKeyById(identifier).getOrThrow())
        ?: throw NullPointerException()
    viewModel.deleteKey(keyIdPassedIn)
  }

  private fun exportKey(identifier: PGPIdentifier) {
    retries = 0
    lifecycleScope.launch {
      if (cryptoRepository.isPasswordProtected(listOf(identifier), anySubkey = true)) {
        // export as symmetrically encrypted file after passphrase verification
        askPassphrase(identifier)
      } else if (isSecretKey(identifier)) {
        // a secret key without passphrase is symm. encrypted and exported without verification
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
        val passphrase = bundle.getCharArray(PasswordDialog.PASSWORD_PHRASE_KEY) ?: charArrayOf()
        lifecycleScope.launch {
          if (cryptoRepository.isPasswordCorrect(identifier, passphrase, anySubkey = true)) {
            confirmBackupCode(identifier, generateBackupCode())
          } else {
            askPassphrase(identifier, isError = true)
          }
          passphrase.wipe()
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
        .setNegativeButton(R.string.dialog_cancel, null)
        .setCancelable(false)
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
    val keyIdAndContent = run {
      val key = pgpKeyManager.getKeyById(identifier, withArmor = true).getOrThrow()
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
          if (result.isOk) {
            val encrypted = result.getOrThrow().toByteArray()
            val firstNewline = encrypted.indexOf('\n'.code.toByte())
            val firstLine = encrypted.copyOfRange(0, firstNewline + 1)
            val remainingLines = encrypted.copyOfRange(firstNewline + 1, encrypted.size)
            // OpenKeychain backup format
            firstLine +
              "Passphrase-Format: numeric9x4\n".toByteArray(Charsets.UTF_8) +
              remainingLines
          } else null
        } else {
          KeyUtils.extractPublicKeyData(key)
        }
      Pair(KeyUtils.tryGetKeyId(key), contents)
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
    const val EXTRA_KEY_FOR_SSH = "EXTRA_KEY_FOR_SSH"

    const val PGP_KEY_ADD_REQUEST_KEY = "add_pgp_key"
    const val ACTION_KEY = "action"
    const val ACTION_IMPORT_FILE = "from_file"
    const val ACTION_NEW_PGP_KEY = "generate_new"

    fun newIntent(
      context: Context,
      keySelection: Boolean = false,
      singleSelection: Boolean = false,
    ): Intent {
      val intent = Intent(context, PGPKeyListActivity::class.java)
      intent.putExtra(EXTRA_KEY_SELECTION, singleSelection || keySelection)
      intent.putExtra(EXTRA_KEY_FOR_SSH, singleSelection)
      return intent
    }
  }
}
