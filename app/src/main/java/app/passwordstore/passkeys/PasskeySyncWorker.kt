/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import app.passwordstore.Application
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.fold
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent
import java.util.concurrent.TimeUnit
import logcat.LogPriority
import logcat.logcat

/** Durable, one-shot passkey Git sync. This is event-driven and does not schedule periodic work. */
class PasskeySyncWorker(
  appContext: Context,
  params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

  private val entryPoint by unsafeLazy {
    EntryPointAccessors.fromApplication(appContext, PasskeySyncWorkerEntryPoint::class.java)
  }

  override suspend fun doWork(): Result {
    if (!Application.instance.sharedPrefs.getBoolean(PreferenceKeys.PASSKEY_AUTO_GIT_SYNC, true)) {
      return Result.success()
    }

    // WorkManager may restart the application process before running queued work. Reopen the
    // repository in that case so the sync remains durable across process death.
    if (PasswordRepository.repository == null) {
      PasswordRepository.initialize()
    }

    return entryPoint
      .syncEngine()
      .sync()
      .fold(
        success = {
          logcat { "Passkey auto-sync completed" }
          Result.success()
        },
        failure = { error ->
          logcat(LogPriority.WARN) { "Passkey auto-sync failed: $error" }
          val retryable = (error as? PasskeySyncException)?.retryable ?: true
          if (retryable && runAttemptCount + 1 < MAX_ATTEMPTS) {
            Result.retry()
          } else {
            Result.failure()
          }
        },
      )
  }

  companion object {
    private const val WORK_NAME = "passkey_auto_sync"
    private const val MAX_ATTEMPTS = 3

    fun enqueue(context: Context) {
      val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()
      val request =
        OneTimeWorkRequestBuilder<PasskeySyncWorker>()
          .setConstraints(constraints)
          .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
          .build()

      WorkManager.getInstance(context.applicationContext)
        .enqueueUniqueWork(
          WORK_NAME,
          ExistingWorkPolicy.APPEND_OR_REPLACE,
          request,
        )
    }
  }

  @EntryPoint
  @InstallIn(SingletonComponent::class)
  interface PasskeySyncWorkerEntryPoint {
    fun syncEngine(): PasskeyGitSyncEngine
  }
}
