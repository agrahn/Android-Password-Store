/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.os.Build
import android.os.Bundle
import android.view.autofill.AutofillManager
import androidx.core.content.edit
import androidx.fragment.app.setFragmentResultListener
import androidx.lifecycle.lifecycleScope
import app.passwordstore.Application.Companion.cachedPassphrase
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.ui.crypto.PasswordDialog
import app.passwordstore.util.autofill.AutofillPreferences
import app.passwordstore.util.autofill.AutofillResponseBuilder
import app.passwordstore.util.extensions.asLog
import app.passwordstore.util.features.Features
import app.passwordstore.util.settings.DirectoryStructure
import app.passwordstore.util.settings.PreferenceKeys
import com.github.androidpasswordstore.autofillparser.AutofillAction
import com.github.androidpasswordstore.autofillparser.Credentials
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.onSuccess
import com.github.michaelbull.result.runCatching
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint
class AutofillDecryptActivity : BasePGPActivity() {

  @Inject lateinit var passwordEntryFactory: PasswordEntry.Factory
  @Inject lateinit var features: Features

  private lateinit var directoryStructure: DirectoryStructure
  private var cacheEnabled = false

  override fun onStart() {
    super.onStart()
    val filePath =
      intent?.getStringExtra(EXTRA_FILE_PATH)
        ?: run {
          logcat(ERROR) { "AutofillDecryptActivity started without EXTRA_FILE_PATH" }
          finish()
          return
        }
    val clientState =
      intent?.getBundleExtra(AutofillManager.EXTRA_CLIENT_STATE)
        ?: run {
          logcat(ERROR) { "AutofillDecryptActivity started without EXTRA_CLIENT_STATE" }
          finish()
          return
        }
    val isSearchAction =
      intent?.getBooleanExtra(EXTRA_SEARCH_ACTION, true) ?: throw NullPointerException()
    val action = if (isSearchAction) AutofillAction.Search else AutofillAction.Match
    directoryStructure = AutofillPreferences.directoryStructure(this)
    logcat { action.toString() }
    requireKeysExist { decrypt(filePath, clientState, action) }
  }

  private fun decrypt(filePath: String, clientState: Bundle, action: AutofillAction) {
    val gpgIdentifiers =
      getPGPIdentifiers(
        getParentPath(filePath, PasswordRepository.getRepositoryDirectory().toString())
      ) ?: return
    val passphrase = cachedPassphrase
    lifecycleScope.launch(dispatcherProvider.main()) {
      passphrase?.let {
        decryptWithPassphrase(File(filePath), gpgIdentifiers, clientState, action, passphrase)
      } ?: askPassphrase(filePath, gpgIdentifiers, clientState, action)
    }
  }

  private suspend fun askPassphrase(
    filePath: String,
    identifiers: List<PGPIdentifier>,
    clientState: Bundle,
    action: AutofillAction,
  ) {
    if (!repository.isPasswordProtected(identifiers)) {
      decryptWithPassphrase(File(filePath), identifiers, clientState, action, passphrase = null)
      return
    }
    val dialog =
      PasswordDialog.newInstance(
        cacheEnabled = settings.getBoolean(PreferenceKeys.CACHE_PASSPHRASE, false)
      )
    dialog.show(supportFragmentManager, "PASSWORD_DIALOG")
    dialog.setFragmentResultListener(PasswordDialog.PASSWORD_RESULT_KEY) { key, bundle ->
      if (key == PasswordDialog.PASSWORD_RESULT_KEY) {
        val passphrase =
          bundle.getCharSequence(PasswordDialog.PASSWORD_PHRASE_KEY)?.toString()?.toCharArray()
            ?: throw NullPointerException()
        cacheEnabled = bundle.getBoolean(PasswordDialog.PASSWORD_CACHE_KEY)
        lifecycleScope.launch(dispatcherProvider.main()) {
          decryptWithPassphrase(File(filePath), identifiers, clientState, action, passphrase)
        }
      }
    }
  }

  private suspend fun decryptWithPassphrase(
    filePath: File,
    identifiers: List<PGPIdentifier>,
    clientState: Bundle,
    action: AutofillAction,
    passphrase: CharArray?,
  ) {
    val credentials = decryptCredential(filePath, passphrase, identifiers)
    if (credentials == null) {
      setResult(RESULT_CANCELED)
    } else {
      val fillInDataset =
        AutofillResponseBuilder.makeFillInDataset(
          this@AutofillDecryptActivity,
          credentials,
          clientState,
          action,
        )
      withContext(dispatcherProvider.main()) {
        setResult(
          RESULT_OK,
          Intent().apply { putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, fillInDataset) },
        )
      }
    }
    withContext(dispatcherProvider.main()) { finish() }
  }

  private suspend fun decryptCredential(
    file: File,
    passphrase: CharArray?,
    identifiers: List<PGPIdentifier>,
  ): Credentials? {
    runCatching { file.readBytes().inputStream() }
      .onFailure { e ->
        logcat(ERROR) { e.asLog("File to decrypt not found") }
        return null
      }
      .onSuccess { encryptedInput ->
        val outputStream = ByteArrayOutputStream()
        repository
          .decrypt(passphrase, identifiers, encryptedInput, outputStream)
          .onFailure { e ->
            logcat(ERROR) { e.asLog("Decryption failed") }
            return null
          }
          .onSuccess { result ->
            return runCatching {
                runCatching {
                    cachedPassphrase = if (cacheEnabled) passphrase else null
                    settings.edit { putBoolean(PreferenceKeys.CACHE_PASSPHRASE, cacheEnabled) }
                  }
                  .onFailure { e -> logcat { e.asLog() } }
                val entry = passwordEntryFactory.create(result.toByteArray())
                AutofillPreferences.credentialsFromStoreEntry(this, file, entry, directoryStructure)
              }
              .getOrElse { e ->
                logcat(ERROR) { e.asLog("Failed to parse password entry") }
                return null
              }
          }
      }
    return null
  }

  companion object {

    private const val EXTRA_FILE_PATH = "app.passwordstore.autofill.oreo.EXTRA_FILE_PATH"
    private const val EXTRA_SEARCH_ACTION = "app.passwordstore.autofill.oreo.EXTRA_SEARCH_ACTION"

    private var decryptFileRequestCode = 1

    fun makeDecryptFileIntent(file: File, forwardedExtras: Bundle, context: Context): Intent {
      return Intent(context, AutofillDecryptActivity::class.java).apply {
        putExtras(forwardedExtras)
        putExtra(EXTRA_SEARCH_ACTION, true)
        putExtra(EXTRA_FILE_PATH, file.absolutePath)
      }
    }

    fun makeDecryptFileIntentSender(file: File, context: Context): IntentSender {
      val intent =
        Intent(context, AutofillDecryptActivity::class.java).apply {
          putExtra(EXTRA_SEARCH_ACTION, false)
          putExtra(EXTRA_FILE_PATH, file.absolutePath)
        }
      return PendingIntent.getActivity(
          context,
          decryptFileRequestCode++,
          intent,
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE
          } else {
            PendingIntent.FLAG_CANCEL_CURRENT
          },
        )
        .intentSender
    }
  }
}
