/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import logcat.LogPriority
import logcat.logcat

public class SignatureCounterTransaction(
  private val storage: PasskeyStorage,
  private val highWaterMark: SignatureCounterHighWaterMark,
  private val repositoryState: PasskeyRepositoryState,
) {

  private val credentialMutexes = ConcurrentHashMap<String, Mutex>()

  private fun mutexFor(credentialId: ByteArray): Mutex {
    val key = credentialId.joinToString("") { byte -> "%02x".format(byte) }
    return credentialMutexes.getOrPut(key) { Mutex() }
  }

  public suspend fun executeMonotonicAssertion(
    credentialId: ByteArray,
    sensitiveCredential: SensitivePasskeyCredential,
    preSignVersion: SourceVersionResult,
    lockTimeoutMs: Long = 5_000L,
  ): Result<ULong, SignatureCounterError> {
    val mutex = mutexFor(credentialId)
    return withTimeoutOrNull(lockTimeoutMs) {
      mutex.withLock {
        executeMonotonicAssertionLocked(credentialId, sensitiveCredential, preSignVersion)
      }
    } ?: Err(SignatureCounterError.LockAcquisitionFailed)
  }

  public suspend fun executeMonotonicAssertionExact(
    ref: PasskeyFileRef,
    sensitiveCredential: SensitivePasskeyCredential,
    preSignVersion: SourceVersionResult,
    lockTimeoutMs: Long = 5_000L,
  ): Result<ULong, SignatureCounterError> {
    val mutex = mutexFor(ref.credentialId)
    return withTimeoutOrNull(lockTimeoutMs) {
      mutex.withLock {
        executeMonotonicAssertionLockedExact(ref, sensitiveCredential, preSignVersion)
      }
    } ?: Err(SignatureCounterError.LockAcquisitionFailed)
  }

  private suspend fun executeMonotonicAssertionLocked(
    credentialId: ByteArray,
    sensitiveCredential: SensitivePasskeyCredential,
    preSignVersion: SourceVersionResult,
  ): Result<ULong, SignatureCounterError> {
    if (repositoryState.isInMergeConflict()) {
      return Err(SignatureCounterError.MergeConflict)
    }

    val preSignStable =
      preSignVersion
        .toStableOrError()
        .fold(
          success = { it },
          failure = {
            return Err(it)
          },
        )

    val currentStable =
      requireStableVersion(credentialId)
        .fold(
          success = { it },
          failure = {
            return Err(it)
          },
        )

    if (preSignStable != currentStable) {
      return Err(SignatureCounterError.FileChangedSinceSelection)
    }

    val freshCredential =
      storage
        .loadForSigning(credentialId)
        .fold(
          success = { it },
          failure = {
            return Err(SignatureCounterError.PersistenceFailed)
          },
        )

    return finalizeAssertion(credentialId, freshCredential)
  }

  private suspend fun executeMonotonicAssertionLockedExact(
    ref: PasskeyFileRef,
    sensitiveCredential: SensitivePasskeyCredential,
    preSignVersion: SourceVersionResult,
  ): Result<ULong, SignatureCounterError> {
    if (repositoryState.isInMergeConflict()) {
      return Err(SignatureCounterError.MergeConflict)
    }

    val preSignStable =
      preSignVersion
        .toStableOrError()
        .fold(
          success = { it },
          failure = {
            return Err(it)
          },
        )

    val currentStable =
      requireStableVersionExact(ref)
        .fold(
          success = { it },
          failure = {
            return Err(it)
          },
        )

    if (preSignStable != currentStable) {
      return Err(SignatureCounterError.FileChangedSinceSelection)
    }

    val freshCredential =
      storage
        .loadForSigningExact(ref, currentStable)
        .fold(
          success = { it },
          failure = {
            return Err(SignatureCounterError.PersistenceFailed)
          },
        )

    return finalizeAssertion(ref.credentialId, freshCredential)
  }

  private suspend fun requireStableVersion(
    credentialId: ByteArray
  ): Result<CredentialSourceVersion, SignatureCounterError> =
    storage
      .resolveSourceVersion(credentialId)
      .fold(
        success = { it.toStableOrError() },
        failure = { Err(SignatureCounterError.PersistenceFailed) },
      )

  private suspend fun requireStableVersionExact(
    ref: PasskeyFileRef
  ): Result<CredentialSourceVersion, SignatureCounterError> =
    storage
      .resolveSourceVersionExact(ref)
      .fold(
        success = { it.toStableOrError() },
        failure = { Err(SignatureCounterError.PersistenceFailed) },
      )

  private fun SourceVersionResult.toStableOrError():
    Result<CredentialSourceVersion, SignatureCounterError> =
    when (this) {
      is SourceVersionResult.Stable -> Ok(version)
      is SourceVersionResult.Missing -> Err(SignatureCounterError.FileChangedSinceSelection)
      is SourceVersionResult.Unavailable -> Err(SignatureCounterError.PersistenceFailed)
    }

  private suspend fun finalizeAssertion(
    credentialId: ByteArray,
    freshCredential: SensitivePasskeyCredential,
  ): Result<ULong, SignatureCounterError> {
    val currentCounter = freshCredential.signCount

    if (highWaterMark.detectRollback(credentialId, currentCounter)) {
      val hwm = highWaterMark.getHighWaterMark(credentialId)
      freshCredential.close()
      return Err(
        SignatureCounterError.RollbackDetected(diskCounter = currentCounter, highWaterMark = hwm)
      )
    }

    val nextCounter =
      try {
        currentCounter + 1u
      } catch (_: ArithmeticException) {
        freshCredential.close()
        return Err(SignatureCounterError.CounterOverflow)
      }

    if (nextCounter == 0uL) {
      freshCredential.close()
      return Err(SignatureCounterError.CounterOverflow)
    }

    val persistResult = storage.updateSignCount(credentialId, nextCounter)
    freshCredential.close()

    return persistResult.fold(
      success = {
        highWaterMark.updateHighWaterMark(credentialId, nextCounter)
        repositoryState.onCredentialUpdated()
        Ok(nextCounter)
      },
      failure = {
        logcat(LogPriority.ERROR) { "Monotonic counter persistence failed: $it" }
        Err(SignatureCounterError.PersistenceFailed)
      },
    )
  }

  public fun resetHighWaterMark(credentialId: ByteArray) {
    highWaterMark.reset(credentialId)
  }

  public fun resetAllHighWaterMarks() {
    highWaterMark.resetAll()
  }
}
