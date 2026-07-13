/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.sshkeygen

import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.appcompat.app.AppCompatActivity
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.git.sshj.SshKey
import com.github.michaelbull.result.fold
import com.github.michaelbull.result.get
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint // required for dependency injection to work
class PgpAuthKeySelectionActivity : AppCompatActivity() {

  @Inject lateinit var pgpKeyManager: PGPKeyManager

  private val pgpKeySelectionAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == RESULT_OK) {
        runCatching {
            val data = result.data ?: throw NullPointerException("result data is null")
            val keyId =
              data.getStringExtra(PGPKeyListActivity.EXTRA_SELECTED_KEY)?.let {
                PGPIdentifier.fromString(it)
              } ?: throw NullPointerException("key ID is null")
            val key =
              pgpKeyManager.getKeyById(keyId).get()
                ?: throw NullPointerException("returned key ${keyId} is null")
            SshKey.usePgpAuthKey(key)
          }
          .fold(
            success = {
              setResult(RESULT_OK)
              var dialog = ShowSshKeyFragment()
              dialog.setCancelable(false)
              dialog.show(supportFragmentManager, "public_key")
            },
            failure = { e ->
              e.printStackTrace()
              MaterialAlertDialogBuilder(this)
                .setCancelable(false)
                .setTitle(R.string.error)
                .setMessage(e.message)
                .setPositiveButton(R.string.dialog_ok) { _, _ -> finish() }
                .show()
            },
          )
      } else {
        finish()
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    if (SshKey.exists && SshKey.type != SshKey.Type.ImportedPGP) {
      MaterialAlertDialogBuilder(this).run {
        setCancelable(false)
        setTitle(R.string.ssh_keygen_existing_title)
        setMessage(R.string.ssh_keygen_replace_with_pgp_key_message)
        setPositiveButton(R.string.ssh_keygen_replace_with_pgp_key) { _, _ -> selectPgpKey() }
        setNegativeButton(R.string.ssh_keygen_existing_keep) { _, _ ->
          setResult(RESULT_CANCELED)
          finish()
        }
        show()
      }
    } else {
      selectPgpKey()
    }
  }

  private fun selectPgpKey() {
    runCatching {
      pgpKeySelectionAction.launch(
        PGPKeyListActivity.newIntent(this, keySelection = true, singleSelection = true)
      )
    }
      .onErr { e ->
        logcat(ERROR) { e.asLog() }
        e.message?.let { message -> snackbar(message = message) }
      }
  }
}
