/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.unwrapError
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Clock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

class SignatureCounterPolicyTest {

  private lateinit var storage: InMemoryPasskeyStorage
  private lateinit var indexedStorage: IndexedPasskeyStorage
  private lateinit var highWaterMark: SignatureCounterHighWaterMark
  private lateinit var repositoryState: PasskeyRepositoryState

  @BeforeTest
  fun setup() {
    storage = InMemoryPasskeyStorage()
    indexedStorage = IndexedPasskeyStorage(storage)
    highWaterMark = SignatureCounterHighWaterMark()
    repositoryState = indexedStorage
  }

  @AfterTest
  fun tearDown() {
    indexedStorage.clearIndex()
    storage.clear()
    highWaterMark.resetAll()
  }

  @Test
  fun `syncable credential ten assertions all encode zero`() = runBlocking {
    createAndSaveCredential("example.com", "user1")

    val policy = SignatureCounterPolicy.ZERO_FOR_SYNCABLE

    repeat(10) { i ->
      val signCount =
        when (policy) {
          SignatureCounterPolicy.ZERO_FOR_SYNCABLE -> 0u
          SignatureCounterPolicy.MONOTONIC_LOCAL -> fail("unexpected policy")
        }
      assertEquals(0u, signCount, "Assertion $i should have zero sign count")
    }

    val metaResult = storage.listMetadata("example.com")
    assertTrue(metaResult.isOk)
    val metadata = metaResult.getOrElse { emptyList() }.first()
    assertEquals(
      0u,
      metadata.signCount,
      "Storage sign count should remain 0 after syncable assertions",
    )
  }

  @Test
  fun `syncable credential performs zero writes`() = runBlocking {
    val (credential, privateKey) = createCredentialPair("example.com", "user1")
    val countingStorage = CountingPasskeyStorage()
    countingStorage.saveCredential(credential, privateKey)

    val policy = SignatureCounterPolicy.ZERO_FOR_SYNCABLE

    repeat(10) {
      when (policy) {
        SignatureCounterPolicy.ZERO_FOR_SYNCABLE -> {}
        SignatureCounterPolicy.MONOTONIC_LOCAL -> fail("unexpected policy")
      }
    }

    assertEquals(
      0,
      countingStorage.updateSignCountCount.get(),
      "Syncable policy should not call updateSignCount",
    )
  }

  @Test
  fun `monotonic local values increase strictly across assertions`() = runBlocking {
    val credential = createAndSaveCredential("example.com", "user1")
    val transaction = SignatureCounterTransaction(storage, highWaterMark, repositoryState)
    val counters = mutableListOf<ULong>()

    repeat(5) {
      val sensitive = loadSensitive(credential)
      val result =
        transaction.executeMonotonicAssertion(
          credentialId = credential.credentialId,
          sensitiveCredential = sensitive,
          preSignVersion = resolveStableVersion(credential),
        )
      assertTrue(result.isOk, "Monotonic assertion $it should succeed")
      counters.add(result.getOrElse { _: SignatureCounterError -> fail("should not fail") })
      sensitive.close()
    }

    assertEquals(listOf<ULong>(1u, 2u, 3u, 4u, 5u), counters, "Counters should increase strictly")
  }

  @Test
  fun `injected write failure returns no assertion response`() =
    runBlocking<Unit> {
      val credential = createAndSaveCredential("example.com", "user1")
      val failingStorage = FailingUpdateSignCountStorage(storage)
      val transaction = SignatureCounterTransaction(failingStorage, highWaterMark, repositoryState)

      val sensitive = loadSensitive(credential)
      val result =
        transaction.executeMonotonicAssertion(
          credentialId = credential.credentialId,
          sensitiveCredential = sensitive,
          preSignVersion = resolveStableVersion(credential),
        )
      sensitive.close()

      assertTrue(result.isErr)
      val error = result.unwrapError()
      assertIs<SignatureCounterError.PersistenceFailed>(error)
    }

  @Test
  fun `two concurrent assertions produce distinct ordered counters`() = runBlocking {
    val credential = createAndSaveCredential("example.com", "user1")
    val transaction = SignatureCounterTransaction(storage, highWaterMark, repositoryState)

    val results =
      withContext(Dispatchers.Default) {
        val deferreds =
          (1..2).map {
            async {
              val sensitive = loadSensitive(credential)
              val result =
                transaction.executeMonotonicAssertion(
                  credentialId = credential.credentialId,
                  sensitiveCredential = sensitive,
                  preSignVersion = resolveStableVersion(credential),
                )
              sensitive.close()
              result
            }
          }
        deferreds.awaitAll()
      }

    val values = results.mapNotNull { it.getOrElse { null } }.sorted()
    assertEquals(2, values.size, "Both assertions should succeed")
    assertEquals(1u, values[0])
    assertEquals(2u, values[1])
    assertTrue(values[0] < values[1], "Counters should be strictly ordered")
  }

  @Test
  fun `counter at maximum value produces overflow failure`() =
    runBlocking<Unit> {
      val credential = createAndSaveCredentialWithSignCount("example.com", "user1", ULong.MAX_VALUE)
      val transaction = SignatureCounterTransaction(storage, highWaterMark, repositoryState)

      val sensitive = loadSensitive(credential)
      val result =
        transaction.executeMonotonicAssertion(
          credentialId = credential.credentialId,
          sensitiveCredential = sensitive,
          preSignVersion = resolveStableVersion(credential),
        )
      sensitive.close()

      assertTrue(result.isErr)
      val error = result.unwrapError()
      assertIs<SignatureCounterError.CounterOverflow>(error)
    }

  @Test
  fun `disk counter below high-water mark produces rollback failure`() = runBlocking {
    val credential = createAndSaveCredential("example.com", "user1")
    val transaction = SignatureCounterTransaction(storage, highWaterMark, repositoryState)

    highWaterMark.updateHighWaterMark(credential.credentialId, 10u)

    val sensitive = loadSensitive(credential)
    val result =
      transaction.executeMonotonicAssertion(
        credentialId = credential.credentialId,
        sensitiveCredential = sensitive,
        preSignVersion = resolveStableVersion(credential),
      )
    sensitive.close()

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<SignatureCounterError.RollbackDetected>(error)
    val rollbackError = error as SignatureCounterError.RollbackDetected
    assertEquals(0u, rollbackError.diskCounter)
    assertEquals(10u, rollbackError.highWaterMark)
  }

  @Test
  fun `merge conflict prevents monotonic assertion`() =
    runBlocking<Unit> {
      val credential = createAndSaveCredential("example.com", "user1")
      val transaction = SignatureCounterTransaction(storage, highWaterMark, repositoryState)

      indexedStorage.onGitSyncCompleted(
        GitSyncResult(
          oldHead = "abc",
          newHead = "def",
          worktreeChanged = true,
          conflicts = listOf("fido2/example.com/somefile.gpg"),
        )
      )

      val sensitive = loadSensitive(credential)
      val result =
        transaction.executeMonotonicAssertion(
          credentialId = credential.credentialId,
          sensitiveCredential = sensitive,
          preSignVersion = resolveStableVersion(credential),
        )
      sensitive.close()

      assertTrue(result.isErr)
      val error = result.unwrapError()
      assertIs<SignatureCounterError.MergeConflict>(error)
    }

  @Test
  fun `process restart resumes from durable disk state`() = runBlocking {
    val credential = createAndSaveCredential("example.com", "user1")
    val transaction1 = SignatureCounterTransaction(storage, highWaterMark, repositoryState)

    val sensitive1 = loadSensitive(credential)
    val result1 =
      transaction1.executeMonotonicAssertion(
        credentialId = credential.credentialId,
        sensitiveCredential = sensitive1,
        preSignVersion = resolveStableVersion(credential),
      )
    sensitive1.close()
    assertTrue(result1.isOk)
    assertEquals(1u, result1.getOrElse { _: SignatureCounterError -> fail("should succeed") })

    val freshHighWaterMark = SignatureCounterHighWaterMark()
    val transaction2 = SignatureCounterTransaction(storage, freshHighWaterMark, repositoryState)

    val sensitive2 = loadSensitive(credential)
    val result2 =
      transaction2.executeMonotonicAssertion(
        credentialId = credential.credentialId,
        sensitiveCredential = sensitive2,
        preSignVersion = resolveStableVersion(credential),
      )
    sensitive2.close()
    assertTrue(result2.isOk)
    assertEquals(2u, result2.getOrElse { _: SignatureCounterError -> fail("should succeed") })
  }

  @Test
  fun `migration of existing git credential uses zero policy without parse failure`() =
    runBlocking {
      val privateKey = ByteArray(32) { it.toByte() }
      val credential =
        PasskeyCredential(
          credentialId = "migrated-cred".toByteArray(),
          publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
          rpId = "example.com",
          user =
            FidoUser(
              id = "user-id".toByteArray(),
              name = "migrated",
              displayName = "Migrated User",
            ),
          signCount = 42u,
          createdAt = Clock.System.now(),
          transports = listOf("internal"),
          uvInitialized = true,
          backupEligible = true,
          backupState = false,
        )
      storage.saveCredential(credential, privateKey)

      val policy = SignatureCounterPolicy.ZERO_FOR_SYNCABLE
      val signCount =
        when (policy) {
          SignatureCounterPolicy.ZERO_FOR_SYNCABLE -> 0u
          SignatureCounterPolicy.MONOTONIC_LOCAL -> fail("unexpected")
        }
      assertEquals(0u, signCount)

      val loaded = storage.loadForSigning(credential.credentialId)
      assertTrue(loaded.isOk)
    }

  @Test
  fun `high water mark detects rollback`() {
    val credId = "test-cred".toByteArray()
    highWaterMark.updateHighWaterMark(credId, 5u)

    assertTrue(highWaterMark.detectRollback(credId, 3u))
    assertTrue(!highWaterMark.detectRollback(credId, 5u))
    assertTrue(!highWaterMark.detectRollback(credId, 7u))
  }

  @Test
  fun `high water mark_reset clears state`() {
    val credId = "test-cred".toByteArray()
    highWaterMark.updateHighWaterMark(credId, 5u)
    assertEquals(5u, highWaterMark.getHighWaterMark(credId))

    highWaterMark.reset(credId)
    assertEquals(0u, highWaterMark.getHighWaterMark(credId))
  }

  @Test
  fun `monotonic local credential near max value succeeds`() = runBlocking {
    val credential =
      createAndSaveCredentialWithSignCount("example.com", "user1", ULong.MAX_VALUE - 2u)
    val transaction = SignatureCounterTransaction(storage, highWaterMark, repositoryState)

    val sensitive = loadSensitive(credential)
    val result =
      transaction.executeMonotonicAssertion(
        credentialId = credential.credentialId,
        sensitiveCredential = sensitive,
        preSignVersion = resolveStableVersion(credential),
      )
    sensitive.close()

    assertTrue(result.isOk)
    assertEquals(
      ULong.MAX_VALUE - 1u,
      result.getOrElse { _: SignatureCounterError -> fail("should succeed") },
    )
  }

  @Test
  fun `monotonic local credential at ULong MAX_VALUE overflows`() =
    runBlocking<Unit> {
      val credential = createAndSaveCredentialWithSignCount("example.com", "user1", ULong.MAX_VALUE)
      val transaction = SignatureCounterTransaction(storage, highWaterMark, repositoryState)

      val sensitive = loadSensitive(credential)
      val result =
        transaction.executeMonotonicAssertion(
          credentialId = credential.credentialId,
          sensitiveCredential = sensitive,
          preSignVersion = resolveStableVersion(credential),
        )
      sensitive.close()

      assertTrue(result.isErr)
      val error = result.unwrapError()
      assertIs<SignatureCounterError.CounterOverflow>(error)
    }

  private suspend fun createAndSaveCredential(rpId: String, userName: String): PasskeyCredential {
    val (credential, privateKey) = createCredentialPair(rpId, userName)
    storage.saveCredential(credential, privateKey)
    return credential
  }

  private fun createCredentialPair(
    rpId: String,
    userName: String,
    signCount: ULong = 0u,
  ): Pair<PasskeyCredential, ByteArray> {
    val privateKey = ByteArray(32) { it.toByte() }
    val credential =
      PasskeyCredential(
        credentialId = "$userName-cred-id".toByteArray(),
        publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
        rpId = rpId,
        user = FidoUser(id = "$userName-id".toByteArray(), name = userName, displayName = userName),
        signCount = signCount,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
      )
    return Pair(credential, privateKey)
  }

  private suspend fun createAndSaveCredentialWithSignCount(
    rpId: String,
    userName: String,
    signCount: ULong,
  ): PasskeyCredential {
    val (credential, privateKey) = createCredentialPair(rpId, userName, signCount)
    storage.saveCredential(credential, privateKey)
    return credential
  }

  @Test
  fun `file changes between selection and transaction are rejected`() =
    runBlocking<Unit> {
      val credential = createAndSaveCredential("example.com", "user1")
      val mutatingStorage = VersionMutatingPasskeyStorage(storage)
      val transaction = SignatureCounterTransaction(mutatingStorage, highWaterMark, repositoryState)

      val preSignVersion =
        mutatingStorage.resolveSourceVersion(credential.credentialId).getOrElse { null }
      assertIs<SourceVersionResult.Stable>(preSignVersion)

      val sensitive = loadSensitive(credential)
      val result =
        transaction.executeMonotonicAssertion(
          credentialId = credential.credentialId,
          sensitiveCredential = sensitive,
          preSignVersion = preSignVersion,
        )
      sensitive.close()

      assertTrue(result.isErr)
      val error = result.unwrapError()
      assertIs<SignatureCounterError.FileChangedSinceSelection>(error)
    }

  @Test
  fun `monotonic mode not allowed for syncable repository with remote`() = runBlocking {
    val credential = createAndSaveCredential("example.com", "user1")
    val hasRemote = true
    val policy =
      if (hasRemote) {
        SignatureCounterPolicy.ZERO_FOR_SYNCABLE
      } else {
        SignatureCounterPolicy.MONOTONIC_LOCAL
      }
    assertEquals(
      SignatureCounterPolicy.ZERO_FOR_SYNCABLE,
      policy,
      "Syncable repository must use zero-counter policy",
    )

    val signCount =
      when (policy) {
        SignatureCounterPolicy.ZERO_FOR_SYNCABLE -> 0u
        SignatureCounterPolicy.MONOTONIC_LOCAL -> credential.signCount + 1u
      }
    assertEquals(0u, signCount)

    val metaResult = storage.listMetadata("example.com")
    assertTrue(metaResult.isOk)
    val metadata = metaResult.getOrElse { emptyList() }.first()
    assertEquals(0u, metadata.signCount)
  }

  private suspend fun loadSensitive(credential: PasskeyCredential): SensitivePasskeyCredential {
    val result = storage.loadForSigning(credential.credentialId)
    assertTrue(result.isOk)
    return result.getOrElse { _: Throwable -> fail("should be ok") as SensitivePasskeyCredential }
  }

  private suspend fun resolveStableVersion(credential: PasskeyCredential): SourceVersionResult {
    val result = storage.resolveSourceVersion(credential.credentialId).getOrElse { null }
    return result ?: SourceVersionResult.Missing
  }
}

private class VersionMutatingPasskeyStorage(private val delegate: InMemoryPasskeyStorage) :
  PasskeyStorage {
  private var versionCounter = 0L

  override suspend fun listMetadata(
    rpId: String?
  ): com.github.michaelbull.result.Result<
    List<app.passwordstore.passkeys.model.PasskeyMetadata>,
    Throwable,
  > = delegate.listMetadata(rpId)

  override suspend fun loadForSigning(
    credentialId: ByteArray
  ): com.github.michaelbull.result.Result<SensitivePasskeyCredential, Throwable> =
    delegate.loadForSigning(credentialId)

  override suspend fun saveCredential(
    credential: app.passwordstore.passkeys.model.PasskeyCredential,
    privateKey: ByteArray,
  ): com.github.michaelbull.result.Result<Unit, Throwable> =
    delegate.saveCredential(credential, privateKey)

  override suspend fun deleteCredential(
    credentialId: ByteArray
  ): com.github.michaelbull.result.Result<Boolean, Throwable> =
    delegate.deleteCredential(credentialId)

  override suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): com.github.michaelbull.result.Result<Unit, Throwable> =
    delegate.updateSignCount(credentialId, newSignCount)

  override suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): com.github.michaelbull.result.Result<SourceVersionResult, Throwable> {
    versionCounter++
    val base =
      when (val result = delegate.resolveSourceVersion(credentialId).getOrElse { null }) {
        is SourceVersionResult.Stable -> result.version
        else -> return com.github.michaelbull.result.Ok(SourceVersionResult.Missing)
      }
    return com.github.michaelbull.result.Ok(
      SourceVersionResult.Stable(
        base.copy(
          repositoryGeneration = base.repositoryGeneration.copy(worktreeGeneration = versionCounter)
        )
      )
    )
  }
}

private class FailingUpdateSignCountStorage(private val delegate: PasskeyStorage) : PasskeyStorage {
  override suspend fun listMetadata(
    rpId: String?
  ): com.github.michaelbull.result.Result<
    List<app.passwordstore.passkeys.model.PasskeyMetadata>,
    Throwable,
  > = delegate.listMetadata(rpId)

  override suspend fun loadForSigning(
    credentialId: ByteArray
  ): com.github.michaelbull.result.Result<SensitivePasskeyCredential, Throwable> =
    delegate.loadForSigning(credentialId)

  override suspend fun saveCredential(
    credential: app.passwordstore.passkeys.model.PasskeyCredential,
    privateKey: ByteArray,
  ): com.github.michaelbull.result.Result<Unit, Throwable> =
    delegate.saveCredential(credential, privateKey)

  override suspend fun deleteCredential(
    credentialId: ByteArray
  ): com.github.michaelbull.result.Result<Boolean, Throwable> =
    delegate.deleteCredential(credentialId)

  override suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): com.github.michaelbull.result.Result<Unit, Throwable> =
    Err(IllegalStateException("Injected write failure"))

  override suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): com.github.michaelbull.result.Result<SourceVersionResult, Throwable> =
    delegate.resolveSourceVersion(credentialId)
}
