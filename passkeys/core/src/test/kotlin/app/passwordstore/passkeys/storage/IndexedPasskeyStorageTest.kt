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

class IndexedPasskeyStorageTest {

  private lateinit var delegateStorage: InMemoryPasskeyStorage
  private lateinit var indexedStorage: IndexedPasskeyStorage

  @BeforeTest
  fun setup() {
    delegateStorage = InMemoryPasskeyStorage()
    indexedStorage = IndexedPasskeyStorage(delegateStorage)
  }

  @AfterTest
  fun tearDown() {
    indexedStorage.clearIndex()
    delegateStorage.clear()
  }

  @Test
  fun `index starts empty`() {
    assertEquals(0, indexedStorage.indexedCredentialCount())
    assertFalse(indexedStorage.hasRpId("example.com"))
  }

  @Test
  fun `saveCredential indexes metadata`() = runBlocking {
    val (credential, privateKey) = createTestCredential()

    indexedStorage.saveCredential(credential, privateKey)

    assertEquals(1, indexedStorage.indexedCredentialCount())
    assertTrue(indexedStorage.hasRpId(credential.rpId))
    assertEquals(1, indexedStorage.credentialCountForRp(credential.rpId))
  }

  @Test
  fun `loadForSigning returns credential after save`() = runBlocking {
    val (credential, privateKey) = createTestCredential()
    indexedStorage.saveCredential(credential, privateKey)

    val result = indexedStorage.loadForSigning(credential.credentialId)

    assertTrue(result.isOk)
    val sensitive = result.getOrElse { null }
    assertNotNull(sensitive)
    sensitive.use {
      assertEquals(
        credential.credentialIdBase64(),
        sensitive.credentialId.let {
          java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(it)
        },
      )
    }
  }

  @Test
  fun `listMetadata filters by rpId from index`() = runBlocking {
    val cred1 = createTestCredential(rpId = "example.com", credentialId = "cred1".toByteArray())
    val cred2 = createTestCredential(rpId = "example.com", credentialId = "cred2".toByteArray())
    val cred3 = createTestCredential(rpId = "other.com", credentialId = "cred3".toByteArray())

    indexedStorage.saveCredential(cred1.first, cred1.second)
    indexedStorage.saveCredential(cred2.first, cred2.second)
    indexedStorage.saveCredential(cred3.first, cred3.second)

    val result = indexedStorage.listMetadata("example.com")

    assertTrue(result.isOk)
    val metadata = result.getOrElse { emptyList() }
    assertEquals(2, metadata.size)
    assertTrue(metadata.all { it.rpId == "example.com" })
  }

  @Test
  fun `deleteCredential removes from index`() = runBlocking {
    val (credential, privateKey) = createTestCredential()
    indexedStorage.saveCredential(credential, privateKey)

    indexedStorage.deleteCredential(credential.credentialId)

    assertEquals(0, indexedStorage.indexedCredentialCount())
    assertFalse(indexedStorage.hasRpId(credential.rpId))
  }

  @Test
  fun `updateSignCount updates index`() = runBlocking {
    val (credential, privateKey) = createTestCredential()
    indexedStorage.saveCredential(credential, privateKey)

    indexedStorage.updateSignCount(credential.credentialId, 42u)

    val result = indexedStorage.listMetadata()
    assertTrue(result.isOk)
    val metadata = result.getOrElse { emptyList() }
    assertEquals(42u, metadata.first().signCount)
  }

  @Test
  fun `indexedRpIds returns all rp ids`() = runBlocking {
    val cred1 = createTestCredential(rpId = "example.com")
    val cred2 = createTestCredential(rpId = "other.com")
    indexedStorage.saveCredential(cred1.first, cred1.second)
    indexedStorage.saveCredential(cred2.first, cred2.second)

    val rpIds = indexedStorage.indexedRpIds()

    assertEquals(setOf("example.com", "other.com"), rpIds)
  }

  @Test
  fun `clearIndex resets everything`() = runBlocking {
    val (credential, privateKey) = createTestCredential()
    indexedStorage.saveCredential(credential, privateKey)

    indexedStorage.clearIndex()

    assertEquals(0, indexedStorage.indexedCredentialCount())
    assertTrue(indexedStorage.indexedRpIds().isEmpty())
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
