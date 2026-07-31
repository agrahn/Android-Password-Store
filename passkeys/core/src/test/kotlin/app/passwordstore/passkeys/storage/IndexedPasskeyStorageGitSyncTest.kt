/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.getOrElse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Instant
import kotlinx.coroutines.runBlocking

class IndexedPasskeyStorageGitSyncTest {

  @Test
  fun `Git sync reconciles changed passkey directly without rescanning index`() = runBlocking {
    val delegate = TrackingStorage()
    val generationProvider = FakeGenerationProvider()
    val storage = IndexedPasskeyStorage(delegate, generationProvider)

    assertTrue(storage.listMetadata().isOk)
    assertEquals(1, delegate.fullScanCount)

    val credentialId = byteArrayOf(0x01, 0x02)
    val relativePath = "example.com/0102.gpg"
    delegate.remoteMetadata =
      PasskeyMetadata(
        credentialId = credentialId,
        rpId = "example.com",
        userName = "alice",
        userDisplayName = "Alice",
        createdAt = Instant.fromEpochMilliseconds(1_000),
      )
    delegate.remoteVersion = version(generation = 1)
    generationProvider.head = "new"
    generationProvider.worktreeGeneration = 1

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "old",
        newHead = "new",
        worktreeChanged = true,
        conflicts = emptyList(),
        changedPaths = setOf("fido2/$relativePath"),
      )
    )

    val metadata = storage.listMetadata("example.com").getOrElse { emptyList() }
    assertEquals(1, metadata.size)
    assertTrue(metadata.single().credentialId.contentEquals(credentialId))
    assertEquals(1, delegate.fullScanCount)
    assertEquals(1, delegate.exactMetadataLoadCount)
  }

  @Test
  fun `Git deletion removes passkey directly without rescanning index`() = runBlocking {
    val delegate = TrackingStorage()
    val generationProvider = FakeGenerationProvider()
    val storage = IndexedPasskeyStorage(delegate, generationProvider)
    val credentialId = byteArrayOf(0x01, 0x02)
    val changedPath = "fido2/example.com/0102.gpg"

    assertTrue(storage.listMetadata().isOk)
    delegate.remoteMetadata =
      PasskeyMetadata(
        credentialId = credentialId,
        rpId = "example.com",
        userName = "alice",
        userDisplayName = "Alice",
        createdAt = Instant.fromEpochMilliseconds(1_000),
      )
    delegate.remoteVersion = version(generation = 1)
    generationProvider.head = "new"
    generationProvider.worktreeGeneration = 1
    storage.onGitSyncCompleted(GitSyncResult("old", "new", true, emptyList(), setOf(changedPath)))

    delegate.remoteMetadata = null
    delegate.remoteVersion = null
    generationProvider.head = "newer"
    generationProvider.worktreeGeneration = 2
    storage.onGitSyncCompleted(GitSyncResult("new", "newer", true, emptyList(), setOf(changedPath)))

    assertTrue(storage.listMetadata("example.com").getOrElse { emptyList() }.isEmpty())
    assertEquals(1, delegate.fullScanCount)
  }

  private fun version(generation: Long): CredentialSourceVersion {
    return CredentialSourceVersion(
      repositoryGeneration = RepositoryGeneration("repo", null, generation),
      canonicalPath = "/repo/fido2/example.com/0102.gpg",
      fileSize = 128,
      modifiedAtMillis = generation,
      ciphertextDigest = byteArrayOf(generation.toByte()),
    )
  }

  private class FakeGenerationProvider : RepositoryGenerationProvider {
    var head: String? = "old"
    var worktreeGeneration: Long = 0

    override suspend fun currentGitHead(): String? = head

    override fun currentWorktreeGeneration(): Long = worktreeGeneration

    override fun bumpWorktreeGeneration() {
      worktreeGeneration++
    }

    override fun repositoryIdentity(): String = "repo"

    override fun isInMergeOrRebaseState(): Boolean = false
  }

  private class TrackingStorage : PasskeyStorage {
    var fullScanCount = 0
    var exactMetadataLoadCount = 0
    var remoteMetadata: PasskeyMetadata? = null
    var remoteVersion: CredentialSourceVersion? = null

    override suspend fun listMetadata(rpId: String?): Result<List<PasskeyMetadata>, Throwable> =
      Ok(emptyList())

    override suspend fun listMetadataWithRefs(
      rpId: String?
    ): Result<List<PasskeyMetadataWithRef>, Throwable> {
      fullScanCount++
      return Ok(emptyList())
    }

    override suspend fun resolveSourceVersionExact(
      ref: PasskeyFileRef
    ): Result<SourceVersionResult, Throwable> {
      val version = remoteVersion
      return if (version == null) {
        Ok(SourceVersionResult.Missing)
      } else {
        Ok(SourceVersionResult.Stable(version))
      }
    }

    override suspend fun loadCredentialMetadata(
      ref: PasskeyFileRef,
      expectedVersion: CredentialSourceVersion?,
    ): Result<PasskeyMetadata, Throwable> {
      exactMetadataLoadCount++
      return remoteMetadata?.let(::Ok) ?: Err(IllegalArgumentException("Credential not found"))
    }

    override suspend fun loadForSigning(
      credentialId: ByteArray
    ): Result<SensitivePasskeyCredential, Throwable> = Err(UnsupportedOperationException())

    override suspend fun saveCredential(
      credential: PasskeyCredential,
      privateKey: ByteArray,
    ): Result<Unit, Throwable> = Err(UnsupportedOperationException())

    override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> =
      Err(UnsupportedOperationException())

    override suspend fun updateSignCount(
      credentialId: ByteArray,
      newSignCount: ULong,
    ): Result<Unit, Throwable> = Err(UnsupportedOperationException())
  }
}
