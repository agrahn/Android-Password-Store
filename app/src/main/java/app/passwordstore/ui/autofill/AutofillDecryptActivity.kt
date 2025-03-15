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
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.util.autofill.AutofillPreferences
import app.passwordstore.util.autofill.AutofillResponseBuilder
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.settings.PreferenceKeys
import com.github.androidpasswordstore.autofillparser.AutofillAction
import com.github.michaelbull.result.onSuccess
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.logcat

@AndroidEntryPoint
class AutofillDecryptActivity : BasePGPActivity() {

  @Inject lateinit var passwordEntryFactory: PasswordEntry.Factory

  private lateinit var filePath: String
  private lateinit var repositoryPath: String
  private lateinit var clientState: Bundle
  private lateinit var action: AutofillAction

  override fun onStart() {
    super.onStart()
    filePath =
      intent?.getStringExtra(EXTRA_FILE_PATH)
        ?: run {
          logcat(ERROR) { "AutofillDecryptActivity started without EXTRA_FILE_PATH" }
          finish()
          return
        }
    repositoryPath = PasswordRepository.getRepositoryDirectory().toString()
    clientState =
      intent?.getBundleExtra(AutofillManager.EXTRA_CLIENT_STATE)
        ?: run {
          logcat(ERROR) { "AutofillDecryptActivity started without EXTRA_CLIENT_STATE" }
          finish()
          return
        }
    val isSearchAction =
      intent?.getBooleanExtra(EXTRA_SEARCH_ACTION, true) ?: throw NullPointerException()
    action = if (isSearchAction) AutofillAction.Search else AutofillAction.Match
    logcat { action.toString() }
    requireKeysExist {
      val gpgIdentifiers =
        getPGPIdentifiers(getParentPath(filePath, repositoryPath)) ?: return@requireKeysExist
      getPersistentAndDecrypt(gpgIdentifiers)
    }
  }

  override suspend fun decryptWithPassphrase(
    passphrases: Map<String, CharArray>,
    identifiers: List<PGPIdentifier>,
    onSuccess: suspend (String) -> Unit,
  ) {
    val encryptedFile = File(filePath)
    val message = withContext(dispatcherProvider.io()) { encryptedFile.readBytes().inputStream() }
    val outputStream = ByteArrayOutputStream()
    val (ids, result) = repository.decrypt(passphrases, identifiers, message, outputStream)
    if (result.isOk) {
      val entry = passwordEntryFactory.create(result.value.toByteArray())
      val directoryStructure = AutofillPreferences.directoryStructure(this)
      val credentials =
        AutofillPreferences.credentialsFromStoreEntry(
          this,
          encryptedFile,
          entry,
          directoryStructure,
        )
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
        if (entry.hasTotp()) {
          val otp = entry.currentOtp
          val remainingTime = otp.remainingTime.inWholeSeconds
          copyTextToClipboard(otp.value.toCharArray(), isSensitive = false)
          otpTimer?.shutdownNow()
          val otpTimerNew = Executors.newSingleThreadScheduledExecutor()
          otpTimer = otpTimerNew
          otpTimerNew.schedule( // refresh otp once
            { copyTextToClipboard(entry.currentOtp.value.toCharArray(), isSensitive = false) },
            remainingTime,
            TimeUnit.SECONDS,
          )
        }
      }
      onSuccess(ids.first())
      withContext(dispatcherProvider.main()) { finish() }
    } else {
      logcat(ERROR) { result.error.stackTraceToString() }
      when (result.error) {
        is IncorrectPassphraseException -> {
          persistentPassphrases.edit { ids.forEach { remove(it) } }
          ids.forEach {
            cachedPassphrases[it]?.fill('\u0000')
            cachedPassphrases.remove(it)
          }
          decrypt(identifiers, isError = true)
        }
        else -> {
          snackbar(message = result.error.toString())
          val timer = Executors.newSingleThreadScheduledExecutor()
          timer.schedule({ finish() }, 4.toLong(), TimeUnit.SECONDS)
        }
      }
    }
    if (!settings.getBoolean(PreferenceKeys.CACHE_PASSPHRASE, false)) {
      cachedPassphrases.values.forEach { it.fill('\u0000') }
      cachedPassphrases.clear()
    }
  }

  companion object {

    private const val EXTRA_FILE_PATH = "app.passwordstore.autofill.oreo.EXTRA_FILE_PATH"
    private const val EXTRA_SEARCH_ACTION = "app.passwordstore.autofill.oreo.EXTRA_SEARCH_ACTION"

    private var decryptFileRequestCode = 1
    private var otpTimer: ScheduledExecutorService? = null

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
