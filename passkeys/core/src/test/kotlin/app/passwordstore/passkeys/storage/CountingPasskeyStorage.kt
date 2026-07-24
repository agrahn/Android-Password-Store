/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import com.github.michaelbull.result.Result
import java.util.concurrent.atomic.AtomicInteger

class CountingPasskeyStorage : PasskeyStorage {

  val decryptCount = AtomicInteger(0)
  val metadataCount = AtomicInteger(0)
  val updateSignCountCount = AtomicInteger(0)
  val touchedRpIds = mutableSetOf<String>()

  private val delegate = InMemoryPasskeyStorage()

  fun resetCounters() {
    decryptCount.set(0)
    metadataCount.set(0)
    updateSignCountCount.set(0)
    touchedRpIds.clear()
  }

  override suspend fun listMetadata(rpId: String?): Result<List<PasskeyMetadata>, Throwable> {
    metadataCount.incrementAndGet()
    if (rpId != null) {
      synchronized(touchedRpIds) { touchedRpIds.add(rpId) }
    }
    return delegate.listMetadata(rpId)
  }

  override suspend fun loadForSigning(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable> {
    decryptCount.incrementAndGet()
    return delegate.loadForSigning(credentialId)
  }

  override suspend fun saveCredential(
    credential: PasskeyCredential,
    privateKey: ByteArray,
  ): Result<Unit, Throwable> {
    return delegate.saveCredential(credential, privateKey)
  }

  override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> {
    return delegate.deleteCredential(credentialId)
  }

  override suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable> {
    updateSignCountCount.incrementAndGet()
    return delegate.updateSignCount(credentialId, newSignCount)
  }

  override suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): Result<SourceVersionResult, Throwable> {
    return delegate.resolveSourceVersion(credentialId)
  }

  override suspend fun listMetadataWithRefs(
    rpId: String?
  ): Result<List<PasskeyMetadataWithRef>, Throwable> {
    return delegate.listMetadataWithRefs(rpId)
  }

  fun clear() {
    delegate.clear()
  }
}
