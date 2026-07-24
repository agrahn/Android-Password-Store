/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.integration

import app.passwordstore.passkeys.crypto.ES256CryptoHandler
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.storage.InMemoryPasskeyStorage
import app.passwordstore.passkeys.storage.IndexedPasskeyStorage
import com.github.michaelbull.result.getOrElse
import kotlin.system.measureTimeMillis
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class PasskeyIntegrationTest {

  private lateinit var storage: IndexedPasskeyStorage
  private lateinit var cryptoHandler: ES256CryptoHandler

  @BeforeTest
  fun setup() {
    storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    cryptoHandler = ES256CryptoHandler()
  }

  @AfterTest
  fun tearDown() {
    storage.clearIndex()
  }

  @Test
  fun `full credential lifecycle`() = runBlocking {
    val created =
      cryptoHandler
        .createCredential(
          rpId = "example.com",
          userId = "user-123".toByteArray(),
          userName = "testuser",
          userDisplayName = "Test User",
          challenge = ByteArray(32) { it.toByte() },
        )
        .getOrElse { throw AssertionError("Create failed") }
    val credential = created.credential

    val saveResult = created.usePrivateKeySuspend { privateKey ->
      storage.saveCredential(credential, privateKey)
    }
    assertTrue(saveResult.isOk, "Save should succeed")

    val listResult = storage.listMetadata("example.com")
    assertTrue(listResult.isOk)
    val metadata = listResult.getOrElse { emptyList() }
    assertEquals(1, metadata.size, "Should have one credential")

    val loadResult = storage.loadForSigning(credential.credentialId)
    assertTrue(loadResult.isOk)
    loadResult
      .getOrElse { null }
      ?.use { sensitive ->
        assertEquals(
          credential.credentialIdBase64(),
          java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(sensitive.credentialId),
        )
      }

    val deleteResult = storage.deleteCredential(credential.credentialId)
    assertTrue(deleteResult.isOk && deleteResult.getOrElse { false }, "Delete should succeed")

    val afterDelete = storage.loadForSigning(credential.credentialId)
    assertTrue(afterDelete.isErr, "Should fail after delete")
  }

  @Test
  fun `multiple credentials for same rpId`() = runBlocking {
    createAndSaveCredential("example.com", "user1")
    createAndSaveCredential("example.com", "user2")
    createAndSaveCredential("example.com", "user3")

    val listResult = storage.listMetadata("example.com")
    assertTrue(listResult.isOk)
    val metadata = listResult.getOrElse { emptyList() }
    assertEquals(3, metadata.size, "Should have three credentials")

    val allResult = storage.listMetadata(null)
    assertTrue(allResult.isOk)
    assertEquals(3, allResult.getOrElse { emptyList() }.size, "Should list all without rpId filter")
  }

  @Test
  fun `credentials isolated by rpId`() = runBlocking {
    createAndSaveCredential("example.com", "user1")
    createAndSaveCredential("other.com", "user2")

    val exampleResult = storage.listMetadata("example.com")
    assertTrue(exampleResult.isOk)
    val exampleCreds = exampleResult.getOrElse { emptyList() }
    assertEquals(1, exampleCreds.size)
    assertEquals("example.com", exampleCreds[0].rpId)

    val otherResult = storage.listMetadata("other.com")
    assertTrue(otherResult.isOk)
    val otherCreds = otherResult.getOrElse { emptyList() }
    assertEquals(1, otherCreds.size)
    assertEquals("other.com", otherCreds[0].rpId)
  }

  @Test
  fun `sign count tracking`() = runBlocking {
    val credential = createAndSaveCredential("example.com", "user1")
    assertEquals(0u, credential.signCount)

    storage.updateSignCount(credential.credentialId, 1u)
    val afterOne = storage.listMetadata("example.com").getOrElse { emptyList() }.first()
    assertEquals(1u, afterOne.signCount)

    storage.updateSignCount(credential.credentialId, 42u)
    val afterFortyTwo = storage.listMetadata("example.com").getOrElse { emptyList() }.first()
    assertEquals(42u, afterFortyTwo.signCount)
  }

  @Test
  fun `assertion with stored credential`() = runBlocking {
    val credential = createAndSaveCredential("example.com", "testuser")
    val challenge = ByteArray(32) { it.toByte() }

    storage
      .loadForSigning(credential.credentialId)
      .getOrElse { throw AssertionError("Load failed") }
      .use { sensitive ->
        val credForSigning = sensitive.toPublicCredential()
        val assertion = sensitive.usePrivateKey { privateKey ->
          cryptoHandler
            .getAssertion(
              credential = credForSigning,
              privateKey = privateKey,
              rpId = "example.com",
              challenge = challenge,
              origin = "https://example.com",
            )
            .getOrElse { throw AssertionError("Assertion failed") }
        }

        assertEquals(
          credential.credentialIdBase64(),
          java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(assertion.credentialId),
        )
        assertTrue(
          assertion.signature.size in 70..72,
          "Signature should be DER-encoded (typically 70-72 bytes)",
        )
        assertEquals(37, assertion.authenticatorData.size, "Auth data should be 37 bytes")
      }
  }

  @Test
  fun `indexed storage provides fast lookups`() = runBlocking {
    for (i in 1..100) {
      createAndSaveCredential("example.com", "user$i")
    }

    val duration = measureTimeMillis { repeat(1000) { storage.listMetadata("example.com") } }

    assertTrue(
      duration < 1000,
      "1000 lookups should complete in under 1 second, took ${duration}ms",
    )
  }

  @Test
  fun `indexed storage credential count by rpId`() = runBlocking {
    for (i in 1..10) {
      createAndSaveCredential("example.com", "ex$i")
    }
    for (i in 1..5) {
      createAndSaveCredential("other.com", "ot$i")
    }

    assertEquals(10, storage.credentialCountForRp("example.com"))
    assertEquals(5, storage.credentialCountForRp("other.com"))
    assertEquals(0, storage.credentialCountForRp("nonexistent.com"))
    assertTrue(storage.hasRpId("example.com"))
    assertFalse(storage.hasRpId("nonexistent.com"))
  }

  @Test
  fun `credential rotation`() = runBlocking {
    val oldCred = createAndSaveCredential("example.com", "old-user")

    storage.deleteCredential(oldCred.credentialId)

    createAndSaveCredential("example.com", "new-user")

    val listResult = storage.listMetadata("example.com")
    assertTrue(listResult.isOk)
    val metadata = listResult.getOrElse { emptyList() }
    assertEquals(1, metadata.size)
    assertEquals("new-user", metadata[0].userName)
  }

  @Test
  fun `concurrent access safety`() = runBlocking {
    repeat(10) { i -> createAndSaveCredential("example.com", "user$i") }

    val listResult = storage.listMetadata("example.com")
    assertTrue(listResult.isOk)
    assertEquals(10, listResult.getOrElse { emptyList() }.size)
  }

  private suspend fun createAndSaveCredential(rpId: String, userName: String): PasskeyCredential {
    val created =
      cryptoHandler
        .createCredential(
          rpId = rpId,
          userId = "$userName-id".toByteArray(),
          userName = userName,
          userDisplayName = userName,
          challenge = ByteArray(32) { it.toByte() },
        )
        .getOrElse { throw AssertionError("Create failed") }

    created.usePrivateKeySuspend { privateKey ->
      storage.saveCredential(created.credential, privateKey)
    }
    return created.credential
  }
}
