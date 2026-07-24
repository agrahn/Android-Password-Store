/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.getOrElse
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlinx.coroutines.runBlocking

class InMemoryPasskeyStorageTest {

  private lateinit var storage: InMemoryPasskeyStorage

  @BeforeTest
  fun setup() {
    storage = InMemoryPasskeyStorage()
  }

  @AfterTest
  fun tearDown() {
    storage.clear()
  }

  @Test
  fun `listMetadata returns empty list when empty`() = runBlocking {
    val result = storage.listMetadata()
    assertTrue(result.isOk)
    val metadata = result.getOrElse { emptyList() }
    assertTrue(metadata.isEmpty())
  }

  @Test
  fun `saveCredential and loadForSigning work correctly`() = runBlocking {
    val (credential, privateKey) = createTestCredential()

    val saveResult = storage.saveCredential(credential, privateKey)
    assertTrue(saveResult.isOk)

    val loadResult = storage.loadForSigning(credential.credentialId)
    assertTrue(loadResult.isOk)
    val sensitive = loadResult.getOrElse { null }
    assertNotNull(sensitive)
    sensitive.use {
      assertEquals(credential.rpId, sensitive.rpId)
      assertEquals(credential.user.name, sensitive.user.name)
    }
  }

  @Test
  fun `loadForSigning returns error for non-existent id`() = runBlocking {
    val result = storage.loadForSigning("non-existent".toByteArray())
    assertTrue(result.isErr)
  }

  @Test
  fun `listMetadata filters by rpId`() = runBlocking {
    val cred1 =
      createTestCredential(
        rpId = "example.com",
        userName = "user1",
        credentialId = "cred1".toByteArray(),
      )
    val cred2 =
      createTestCredential(
        rpId = "example.com",
        userName = "user2",
        credentialId = "cred2".toByteArray(),
      )
    val cred3 =
      createTestCredential(
        rpId = "other.com",
        userName = "user3",
        credentialId = "cred3".toByteArray(),
      )

    storage.saveCredential(cred1.first, cred1.second)
    storage.saveCredential(cred2.first, cred2.second)
    storage.saveCredential(cred3.first, cred3.second)

    val result = storage.listMetadata("example.com")
    assertTrue(result.isOk)
    val metadata = result.getOrElse { emptyList() }
    assertEquals(2, metadata.size)
    assertTrue(metadata.all { it.rpId == "example.com" })
  }

  @Test
  fun `listMetadata returns all when rpId is null`() = runBlocking {
    val cred1 = createTestCredential(rpId = "example.com", credentialId = "cred1".toByteArray())
    val cred2 = createTestCredential(rpId = "other.com", credentialId = "cred2".toByteArray())

    storage.saveCredential(cred1.first, cred1.second)
    storage.saveCredential(cred2.first, cred2.second)

    val result = storage.listMetadata(null)
    assertTrue(result.isOk)
    val metadata = result.getOrElse { emptyList() }
    assertEquals(2, metadata.size)
  }

  @Test
  fun `deleteCredential removes credential`() = runBlocking {
    val (credential, privateKey) = createTestCredential()
    storage.saveCredential(credential, privateKey)

    val deleteResult = storage.deleteCredential(credential.credentialId)
    assertTrue(deleteResult.isOk)
    assertTrue(deleteResult.getOrElse { false })

    val loadResult = storage.loadForSigning(credential.credentialId)
    assertTrue(loadResult.isErr)
  }

  @Test
  fun `deleteCredential returns false for non-existent`() = runBlocking {
    val result = storage.deleteCredential("non-existent".toByteArray())
    assertTrue(result.isOk)
    assertFalse(result.getOrElse { true })
  }

  @Test
  fun `updateSignCount updates sign count`() = runBlocking {
    val (credential, privateKey) = createTestCredential()
    storage.saveCredential(credential, privateKey)

    val updateResult = storage.updateSignCount(credential.credentialId, 5u)
    assertTrue(updateResult.isOk)

    val metaResult = storage.listMetadata()
    assertTrue(metaResult.isOk)
    val metadata = metaResult.getOrElse { emptyList() }
    assertNotNull(metadata.firstOrNull())
    assertEquals(5u, metadata.first().signCount)
  }

  @Test
  fun `updateSignCount fails for non-existent credential`() = runBlocking {
    val result = storage.updateSignCount("non-existent".toByteArray(), 1u)
    assertTrue(result.isErr)
  }

  @Test
  fun `count tracks stored credentials`() = runBlocking {
    assertEquals(0, storage.count())

    val c1 = createTestCredential(credentialId = "cred1".toByteArray())
    storage.saveCredential(c1.first, c1.second)
    assertEquals(1, storage.count())

    val c2 = createTestCredential(credentialId = "cred2".toByteArray())
    storage.saveCredential(c2.first, c2.second)
    assertEquals(2, storage.count())

    storage.clear()
    assertEquals(0, storage.count())
  }

  @Test
  fun `saveCredential overwrites existing with same id`() = runBlocking {
    val (credential, privateKey) = createTestCredential()
    storage.saveCredential(credential, privateKey)

    val updated = credential.copy(signCount = 10u)
    storage.saveCredential(updated, privateKey)

    val result = storage.listMetadata()
    assertTrue(result.isOk)
    val metadata = result.getOrElse { emptyList() }
    assertNotNull(metadata.firstOrNull())
    assertEquals(10u, metadata.first().signCount)
    assertEquals(1, storage.count())
  }

  private fun createTestCredential(
    rpId: String = "example.com",
    userName: String = "testuser",
    credentialId: ByteArray = "test-cred-id".toByteArray(),
  ): Pair<PasskeyCredential, ByteArray> {
    val privateKey = ByteArray(32) { it.toByte() }
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
}
