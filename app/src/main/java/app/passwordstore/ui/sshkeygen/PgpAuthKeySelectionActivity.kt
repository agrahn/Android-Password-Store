/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.sshkeygen

import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import app.passwordstore.R
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.git.sshj.SshKey
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat
import javax.inject.Inject
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPIdentifier.KeyId
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import app.passwordstore.ui.pgp.PGPKeyListActivity
import logcat.logcat
import dagger.hilt.android.AndroidEntryPoint
import app.passwordstore.injection.prefs.GitSecrets
import android.content.SharedPreferences
import androidx.core.content.edit
import app.passwordstore.util.settings.PreferenceKeys

@AndroidEntryPoint // required for dependency injection to work
class PgpAuthKeySelectionActivity : AppCompatActivity() {

  @Inject lateinit var pgpKeyManager: PGPKeyManager
 
  private val pgpKeySelectionAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == RESULT_OK) {
        runCatching {
          val data = result.data ?: return@registerForActivityResult
          val keyId = 
            data.getLongArrayExtra(PGPKeyListActivity.EXTRA_SELECTED_KEY)?.let {
              if(it.isNotEmpty()) KeyId(it.last()) else null
		    } ?: return@registerForActivityResult
          val key = pgpKeyManager.getKeyById(keyId).get() ?: return@registerForActivityResult
          SshKey.usePgpAuthKey(key)
        }
        .onFailure { e ->
          logcat(ERROR) { e.asLog() }
          e.message?.let { message -> snackbar(message = message) }
        }
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    if (SshKey.exists) {
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
    runCatching { pgpKeySelectionAction.launch(PGPKeyListActivity.newIntent(this, keySelection = true, singleSelection = true)) }
      .onFailure { e ->
        logcat(ERROR) { e.asLog() }
        e.message?.let { message -> snackbar(message = message) }
      }
  }
}
