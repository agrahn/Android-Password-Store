/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.unwrapError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlinx.coroutines.runBlocking

class SourceVersionFailClosedTest {

  @Test
  fun `Missing source version aborts monotonic assertion`() =
    runBlocking<Unit> {
      val storage = InMemoryPasskeyStorage()
      val highWaterMark = SignatureCounterHighWaterMark()
      val repositoryState = IndexedPasskeyStorage(storage)
      val transaction = SignatureCounterTransaction(storage, highWaterMark, repositoryState)

      val credential = createCredential()
      storage.saveCredential(credential.first, credential.second)

      val sensitive =
        storage.loadForSigning(credential.first.credentialId).getOrElse { throw AssertionError() }
      val result =
        transaction.executeMonotonicAssertion(
          credentialId = credential.first.credentialId,
          sensitiveCredential = sensitive,
          preSignVersion = SourceVersionResult.Missing,
        )
      sensitive.close()

      assertTrue(result.isErr)
      assertIs<SignatureCounterError.FileChangedSinceSelection>(result.unwrapError())
    }

  @Test
  fun `Unavailable source version aborts monotonic assertion`() =
    runBlocking<Unit> {
      val storage = InMemoryPasskeyStorage()
      val highWaterMark = SignatureCounterHighWaterMark()
      val repositoryState = IndexedPasskeyStorage(storage)
      val transaction = SignatureCounterTransaction(storage, highWaterMark, repositoryState)

      val credential = createCredential()
      storage.saveCredential(credential.first, credential.second)

      val sensitive =
        storage.loadForSigning(credential.first.credentialId).getOrElse { throw AssertionError() }
      val result =
        transaction.executeMonotonicAssertion(
          credentialId = credential.first.credentialId,
          sensitiveCredential = sensitive,
          preSignVersion = SourceVersionResult.Unavailable(SourceVersionError.IoError),
        )
      sensitive.close()

      assertTrue(result.isErr)
      assertIs<SignatureCounterError.PersistenceFailed>(result.unwrapError())
    }

  @Test
  fun `deleted credential returns Missing from resolveSourceVersion`() = runBlocking {
    val storage = InMemoryPasskeyStorage()
    val credential = createCredential()
    storage.saveCredential(credential.first, credential.second)

    val beforeDelete =
      storage.resolveSourceVersion(credential.first.credentialId).getOrElse { null }
    assertIs<SourceVersionResult.Stable>(beforeDelete)

    storage.deleteCredential(credential.first.credentialId)

    val afterDelete = storage.resolveSourceVersion(credential.first.credentialId).getOrElse { null }
    assertEquals(SourceVersionResult.Missing, afterDelete)
  }

  @Test
  fun `stable version allows monotonic assertion to proceed`() = runBlocking {
    val storage = InMemoryPasskeyStorage()
    val highWaterMark = SignatureCounterHighWaterMark()
    val repositoryState = IndexedPasskeyStorage(storage)
    val transaction = SignatureCounterTransaction(storage, highWaterMark, repositoryState)

    val credential = createCredential()
    storage.saveCredential(credential.first, credential.second)

    val version = storage.resolveSourceVersion(credential.first.credentialId).getOrElse { null }
    assertIs<SourceVersionResult.Stable>(version)

    val sensitive =
      storage.loadForSigning(credential.first.credentialId).getOrElse { throw AssertionError() }
    val result =
      transaction.executeMonotonicAssertion(
        credentialId = credential.first.credentialId,
        sensitiveCredential = sensitive,
        preSignVersion = version,
      )
    sensitive.close()

    assertTrue(result.isOk)
    assertEquals(1u, result.getOrElse { throw AssertionError() })
  }

  @Test
  fun `exact-ref monotonic assertion fails closed on Missing`() =
    runBlocking<Unit> {
      val storage = InMemoryPasskeyStorage()
      val highWaterMark = SignatureCounterHighWaterMark()
      val repositoryState = IndexedPasskeyStorage(storage)
      val transaction = SignatureCounterTransaction(storage, highWaterMark, repositoryState)

      val credential = createCredential()
      storage.saveCredential(credential.first, credential.second)

      val ref =
        PasskeyFileRef(
          canonicalRpId = credential.first.rpId,
          credentialId = credential.first.credentialId,
          relativePath =
            "example.com/${credential.first.credentialId.joinToString("") { "%02x".format(it) }}.gpg",
        )

      val sensitive =
        storage.loadForSigning(credential.first.credentialId).getOrElse { throw AssertionError() }
      val result =
        transaction.executeMonotonicAssertionExact(
          ref = ref,
          sensitiveCredential = sensitive,
          preSignVersion = SourceVersionResult.Missing,
        )
      sensitive.close()

      assertTrue(result.isErr)
      assertIs<SignatureCounterError.FileChangedSinceSelection>(result.unwrapError())
    }

  private fun createCredential(): Pair<PasskeyCredential, ByteArray> {
    val privateKey = ByteArray(32) { it.toByte() }
    val credential =
      PasskeyCredential(
        credentialId = "test-cred-id".toByteArray(),
        publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
        rpId = "example.com",
        user = FidoUser(id = "user-id".toByteArray(), name = "testuser", displayName = "Test User"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
      )
    return credential to privateKey
  }
}
