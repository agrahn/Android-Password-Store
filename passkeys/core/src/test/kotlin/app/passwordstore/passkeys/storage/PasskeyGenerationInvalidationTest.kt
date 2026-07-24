/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import com.github.michaelbull.result.getOrElse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

class PasskeyGenerationInvalidationTest {

  private class TestGenerationProvider(private val identity: String = "test-repo") :
    RepositoryGenerationProvider {
    var head: String? = "abc123"
    var worktreeGen: Long = 1L
    var isMerging: Boolean = false

    override suspend fun currentGitHead(): String? = head

    override fun currentWorktreeGeneration(): Long = worktreeGen

    override fun bumpWorktreeGeneration() {
      worktreeGen++
    }

    override fun repositoryIdentity(): String = identity

    override fun isInMergeOrRebaseState(): Boolean = isMerging
  }

  private fun createTestCredential(
    rpId: String = "example.com",
    userName: String = "testuser",
    credentialId: ByteArray = "test-cred-id".toByteArray(),
    privateKey: ByteArray = ByteArray(32) { it.toByte() },
  ): Pair<PasskeyCredential, ByteArray> {
    val credential =
      PasskeyCredential(
        credentialId = credentialId,
        publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
        rpId = rpId,
        user = FidoUser(id = "user-id".toByteArray(), name = userName, displayName = "Test User"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
      )
    return Pair(credential, privateKey)
  }

  @Test
  fun `deleted credential disappears after invalidation`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    delegate.saveCredential(cred, privateKey)
    indexed.invalidate(InvalidationReason.EXPLICIT_REQUEST)

    val listBefore = indexed.listMetadata()
    assertTrue(listBefore.isOk)
    assertEquals(1, listBefore.getOrElse { emptyList() }.size)

    delegate.deleteCredential(cred.credentialId)
    indexed.invalidate(InvalidationReason.LOCAL_DELETE)

    val listAfter = indexed.listMetadata()
    assertTrue(listAfter.isOk)
    assertEquals(0, listAfter.getOrElse { emptyList() }.size)
  }

  @Test
  fun `git sync with head change invalidates index`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    delegate.saveCredential(cred, privateKey)
    indexed.invalidate(InvalidationReason.EXPLICIT_REQUEST)

    val listBefore = indexed.listMetadata()
    assertEquals(1, listBefore.getOrElse { emptyList() }.size)

    delegate.deleteCredential(cred.credentialId)
    provider.head = "def456"
    val syncResult =
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    indexed.onGitSyncCompleted(syncResult)

    val listAfter = indexed.listMetadata()
    assertTrue(listAfter.isOk)
    assertEquals(0, listAfter.getOrElse { emptyList() }.size)
  }

  @Test
  fun `source version changes when credential content changes`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val indexed = IndexedPasskeyStorage(delegate)

    val (cred, privateKey1) =
      createTestCredential(
        credentialId = "c1".toByteArray(),
        privateKey = ByteArray(32) { it.toByte() },
      )
    delegate.saveCredential(cred, privateKey1)

    val version1 = delegate.resolveSourceVersion(cred.credentialId).getOrElse { null }
    assertIs<SourceVersionResult.Stable>(version1)

    delegate.deleteCredential(cred.credentialId)
    val (cred2, privateKey2) =
      createTestCredential(
        credentialId = "c1".toByteArray(),
        privateKey = ByteArray(32) { (it + 100).toByte() },
      )
    delegate.saveCredential(cred2, privateKey2)

    val version2 = delegate.resolveSourceVersion(cred.credentialId).getOrElse { null }
    assertIs<SourceVersionResult.Stable>(version2)

    assertFalse(version1.version.ciphertextDigest.contentEquals(version2.version.ciphertextDigest))
  }

  @Test
  fun `onClearCredentialState clears index`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    delegate.saveCredential(cred, privateKey)
    indexed.listMetadata()
    assertEquals(1, indexed.indexedCredentialCount())

    indexed.invalidate(InvalidationReason.CLEAR_CREDENTIAL_STATE)

    assertEquals(0, indexed.indexedCredentialCount())

    val listAfter = indexed.listMetadata()
    assertTrue(listAfter.isOk)
    assertEquals(1, listAfter.getOrElse { emptyList() }.size)
    Unit
  }

  @Test
  fun `merge conflict causes fail closed`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    delegate.saveCredential(cred, privateKey)
    indexed.listMetadata()

    assertFalse(indexed.isInMergeConflict())

    provider.isMerging = true
    val syncResult =
      GitSyncResult(
        oldHead = "abc123",
        newHead = "abc123",
        worktreeChanged = false,
        conflicts = listOf("fido2/example.com/c1.gpg"),
      )
    indexed.onGitSyncCompleted(syncResult)

    assertTrue(indexed.isInMergeConflict())
    Unit
  }

  @Test
  fun `repository reinitialization invalidates all entries`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    delegate.saveCredential(cred, privateKey)
    indexed.listMetadata()
    assertEquals(1, indexed.indexedCredentialCount())

    delegate.clear()
    provider.head = "new-head"
    provider.worktreeGen = 999L
    indexed.onRepositoryReinitialized()

    assertEquals(0, indexed.indexedCredentialCount())
    Unit
  }

  @Test
  fun `gpg id change invalidates index`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    delegate.saveCredential(cred, privateKey)
    indexed.listMetadata()
    assertEquals(1, indexed.indexedCredentialCount())

    indexed.onGpgIdChanged()

    assertEquals(0, indexed.indexedCredentialCount())

    val listAfter = indexed.listMetadata()
    assertTrue(listAfter.isOk)
    assertEquals(1, listAfter.getOrElse { emptyList() }.size)
    Unit
  }

  @Test
  fun `concurrent assertion and sync use stable generation`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    delegate.saveCredential(cred, privateKey)
    indexed.invalidate(InvalidationReason.EXPLICIT_REQUEST)

    withContext(Dispatchers.Default) {
      val assertionJob = async {
        indexed.listMetadata("example.com")
      }
      val syncJob = async {
        provider.head = "new-head"
        val syncResult =
          GitSyncResult(
            oldHead = "abc123",
            newHead = "new-head",
            worktreeChanged = true,
            conflicts = emptyList(),
          )
        indexed.onGitSyncCompleted(syncResult)
      }
      val results = awaitAll(assertionJob, syncJob)
      @Suppress("UNCHECKED_CAST")
      val metadataResult =
        results[0] as com.github.michaelbull.result.Result<List<PasskeyMetadata>, Throwable>
      assertTrue(metadataResult.isOk)
    }
  }

  @Test
  fun `sync failure with unchanged disk preserves metadata`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    delegate.saveCredential(cred, privateKey)
    indexed.listMetadata()
    assertEquals(1, indexed.indexedCredentialCount())

    val syncResult =
      GitSyncResult(
        oldHead = "abc123",
        newHead = "abc123",
        worktreeChanged = false,
        conflicts = emptyList(),
      )
    indexed.onGitSyncCompleted(syncResult)

    assertEquals(1, indexed.indexedCredentialCount())
    Unit
  }

  @Test
  fun `generation change triggers index rebuild`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    delegate.saveCredential(cred, privateKey)
    indexed.invalidate(InvalidationReason.EXPLICIT_REQUEST)

    val list1 = indexed.listMetadata()
    assertEquals(1, list1.getOrElse { emptyList() }.size)

    delegate.deleteCredential(cred.credentialId)
    provider.head = "new-head-after-delete"
    provider.worktreeGen = 42L

    val list2 = indexed.listMetadata()
    assertTrue(list2.isOk)
    assertEquals(0, list2.getOrElse { emptyList() }.size)
  }

  @Test
  fun `repository identity change invalidates index`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider(identity = "repo-A")
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    delegate.saveCredential(cred, privateKey)
    indexed.listMetadata()
    assertEquals(1, indexed.indexedCredentialCount())

    val newProvider = TestGenerationProvider(identity = "repo-B")
    val indexed2 = IndexedPasskeyStorage(delegate, newProvider)

    assertEquals(0, indexed2.indexedCredentialCount())

    val list = indexed2.listMetadata()
    assertTrue(list.isOk)
    assertEquals(1, list.getOrElse { emptyList() }.size)
    Unit
  }

  @Test
  fun `sync with passkey conflicts sets merge conflict flag`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val syncResult =
      GitSyncResult(
        oldHead = "abc",
        newHead = "def",
        worktreeChanged = true,
        conflicts = listOf("fido2/example.com/cred.gpg"),
      )
    indexed.onGitSyncCompleted(syncResult)

    assertTrue(indexed.isInMergeConflict())
  }

  @Test
  fun `sync with non-passkey conflicts does not set merge conflict`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val syncResult =
      GitSyncResult(
        oldHead = "abc",
        newHead = "def",
        worktreeChanged = true,
        conflicts = listOf("some/other/file.txt"),
      )
    indexed.onGitSyncCompleted(syncResult)

    assertFalse(indexed.isInMergeConflict())
  }

  @Test
  fun `currentGeneration returns provider generation`() = runBlocking {
    val provider = TestGenerationProvider()
    provider.head = "test-head"
    provider.worktreeGen = 42L
    val delegate = InMemoryPasskeyStorage()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val gen = indexed.currentGeneration()
    assertEquals("test-head", gen.gitHead)
    assertEquals(42L, gen.worktreeGeneration)
    assertEquals("test-repo", gen.repositoryIdentity)
  }

  @Test
  fun `credential saved after invalidation is indexed with version`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    indexed.saveCredential(cred, privateKey)

    assertEquals(1, indexed.indexedCredentialCount())

    val version = indexed.getSourceVersion(cred.credentialId)
    assertNotNull(version)
    Unit
  }

  @Test
  fun `credential deleted via indexed storage removes from index`() = runBlocking {
    val delegate = InMemoryPasskeyStorage()
    val provider = TestGenerationProvider()
    val indexed = IndexedPasskeyStorage(delegate, provider)

    val (cred, privateKey) = createTestCredential(credentialId = "c1".toByteArray())
    indexed.saveCredential(cred, privateKey)
    assertEquals(1, indexed.indexedCredentialCount())

    indexed.deleteCredential(cred.credentialId)
    assertEquals(0, indexed.indexedCredentialCount())
  }

  @Test
  fun `GitSyncResult detects passkey-affecting changes`() {
    val noChange = GitSyncResult("a", "a", false, emptyList())
    assertFalse(noChange.affectsPasskeys())

    val headChange = GitSyncResult("a", "b", true, emptyList())
    assertTrue(headChange.affectsPasskeys())

    val passkeyConflict = GitSyncResult("a", "b", true, listOf("fido2/test.gpg"))
    assertTrue(passkeyConflict.affectsPasskeys())

    val gpgIdConflict = GitSyncResult("a", "b", true, listOf(".gpg-id"))
    assertTrue(gpgIdConflict.affectsPasskeys())

    val otherConflict = GitSyncResult("a", "b", true, listOf("other/file.txt"))
    assertTrue(otherConflict.affectsPasskeys())
  }

  @Test
  fun `CredentialSourceVersion equality considers digest`() {
    val gen = RepositoryGeneration("repo", "head", 1L)
    val v1 = CredentialSourceVersion(gen, "/path", 100L, 1000L, byteArrayOf(1, 2, 3))
    val v2 = CredentialSourceVersion(gen, "/path", 100L, 1000L, byteArrayOf(4, 5, 6))
    val v3 = CredentialSourceVersion(gen, "/path", 100L, 1000L, byteArrayOf(1, 2, 3))

    assertNotEquals(v1, v2)
    assertEquals(v1, v3)
  }
}
