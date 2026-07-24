/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.provider

import app.passwordstore.passkeys.crypto.AssertionResult
import app.passwordstore.passkeys.crypto.CallerType
import app.passwordstore.passkeys.crypto.ClientDataBinding
import app.passwordstore.passkeys.crypto.ES256CryptoHandler
import app.passwordstore.passkeys.crypto.VerifiedWebAuthnContext
import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.storage.InMemoryPasskeyStorage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json

class PasskeyProviderUtilsTest {

  private val json = Json { ignoreUnknownKeys = true }
  private val cryptoHandler = ES256CryptoHandler()

  @Test
  fun `selectCredentials returns all credentials when allow list is empty`() {
    val credentials = listOf(sampleCredential("one").first, sampleCredential("two").first)

    val selected = PasskeyProviderUtils.selectCredentials(credentials, emptyList())

    assertEquals(credentials, selected)
  }

  @Test
  fun `discoverable accounts retain distinct usernames when display names match`() {
    val first = sampleMetadata("pando85", "Same Person", byteArrayOf(1))
    val second = sampleMetadata("forkline", "Same Person", byteArrayOf(2))

    assertEquals("pando85", PasskeyProviderUtils.credentialEntryIdentity(first).username)
    assertEquals("forkline", PasskeyProviderUtils.credentialEntryIdentity(second).username)
  }

  @Test
  fun `multiple discoverable accounts cannot be auto selected`() {
    assertTrue(PasskeyProviderUtils.isAutoSelectAllowed(1))
    assertFalse(PasskeyProviderUtils.isAutoSelectAllowed(0))
    assertFalse(PasskeyProviderUtils.isAutoSelectAllowed(2))
  }

  @Test
  fun `each credential has a unique pending intent identity`() {
    assertNotEquals(
      PasskeyProviderUtils.credentialIntentUri(byteArrayOf(1)),
      PasskeyProviderUtils.credentialIntentUri(byteArrayOf(2)),
    )
  }

  @Test
  fun `file-only metadata loads account identity without changing credential`() = runBlocking {
    val storage = InMemoryPasskeyStorage()
    val (credential, privateKey) = sampleCredential("forkline")
    assertTrue(storage.saveCredential(credential, privateKey).isOk)
    val fileOnlyMetadata = sampleMetadata("", "", credential.credentialId)

    val hydrated = PasskeyProviderUtils.loadStoredIdentity(storage, fileOnlyMetadata)

    assertEquals("forkline", hydrated.userName)
    assertEquals("forkline", hydrated.userDisplayName)
    assertEquals(fileOnlyMetadata.credentialId.toList(), hydrated.credentialId.toList())
  }

  @Test
  fun `selectCredentials filters by allow credential ids`() {
    val first = sampleCredential("one")
    val second = sampleCredential("two")

    val selected =
      PasskeyProviderUtils.selectCredentials(
        listOf(first.first, second.first),
        listOf(
          PublicKeyCredentialDescriptor(
            type = "public-key",
            id = PasskeyProviderUtils.encodeBase64Url(second.first.credentialId),
          )
        ),
      )

    assertEquals(listOf(second.first), selected)
  }

  @Test
  fun `buildAssertionResponse preserves assertion and request metadata`() {
    val (credential, _) = sampleCredential("alice")
    val assertion =
      AssertionResult(
        credentialId = credential.credentialId,
        authenticatorData = ByteArray(37) { it.toByte() },
        signature = ByteArray(64) { (it + 1).toByte() },
        userHandle = credential.user.id,
        clientDataJSON =
          """{"type":"webauthn.get","challenge":"Y2hhbGxlbmdl","origin":"https://example.com","crossOrigin":false}"""
            .toByteArray(),
      )

    val responseJson =
      PasskeyProviderUtils.buildAssertionResponse(
        assertion,
        credential,
        """
        {
          "challenge": "Y2hhbGxlbmdl",
          "origin": "https://example.com",
          "allowCredentials": []
        }
        """
          .trimIndent(),
      )

    val response = json.decodeFromString(AssertionResponseJson.serializer(), responseJson)
    val clientDataJson =
      PasskeyProviderUtils.decodeBase64Url(response.response.clientDataJSON).decodeToString()

    assertEquals(PasskeyProviderUtils.encodeBase64Url(assertion.credentialId), response.id)
    assertEquals(
      PasskeyProviderUtils.encodeBase64Url(assertion.authenticatorData),
      response.response.authenticatorData,
    )
    assertEquals(
      PasskeyProviderUtils.encodeBase64Url(assertion.signature),
      response.response.signature,
    )
    assertEquals(
      PasskeyProviderUtils.encodeBase64Url(assertion.userHandle ?: credential.user.id),
      response.response.userHandle,
    )
    assertTrue(clientDataJson.contains("\"type\":\"webauthn.get\""))
    assertTrue(clientDataJson.contains("\"challenge\":\"Y2hhbGxlbmdl\""))
    assertTrue(clientDataJson.contains("\"origin\":\"https://example.com\""))
  }

  @Test
  fun `buildAttestationResponse encodes none attestation with auth data`() {
    val (credential, _) = sampleCredential("alice")
    val verifiedContext =
      VerifiedWebAuthnContext(
        callingPackage = "com.test.app",
        origin = "https://example.com",
        callerType = CallerType.NATIVE_APP,
        signingCertificateDigests = setOf("testdigest"),
        clientDataBinding = ClientDataBinding.ProviderConstructed,
      )

    val responseJson =
      PasskeyProviderUtils.buildAttestationResponse(
        credential,
        """
        {
          "rp": { "id": "example.com", "name": "Example" },
          "user": { "id": "dXNlcg", "name": "alice", "displayName": "Alice" },
          "challenge": "Y2hhbGxlbmdl"
        }
        """
          .trimIndent(),
        verifiedContext,
      )

    val response = json.decodeFromString(AttestationResponseJson.serializer(), responseJson)
    val clientDataJson =
      PasskeyProviderUtils.decodeBase64Url(response.response.clientDataJSON).decodeToString()
    val attestationObject =
      PasskeyProviderUtils.decodeBase64Url(response.response.attestationObject)

    assertEquals(PasskeyProviderUtils.encodeBase64Url(credential.credentialId), response.id)
    assertTrue(clientDataJson.contains("\"type\":\"webauthn.create\""))
    assertTrue(attestationObject.isNotEmpty())
    assertEquals(0xA3, attestationObject.first().toInt() and 0xFF)
    assertTrue(attestationObject.decodeToString().contains("none"))
    assertTrue(attestationObject.indexOfSubsequence(credential.credentialId) >= 0)
    assertTrue(attestationObject.indexOfSubsequence(credential.publicKey.copyOfRange(1, 33)) >= 0)
    assertTrue(attestationObject.indexOfSubsequence(credential.publicKey.copyOfRange(33, 65)) >= 0)
  }

  private fun sampleCredential(userName: String): Pair<PasskeyCredential, ByteArray> {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    val credential =
      PasskeyCredential(
        credentialId = "credential-$userName".toByteArray(),
        publicKey = publicKey,
        rpId = "example.com",
        user =
          FidoUser(id = "user-$userName".toByteArray(), name = userName, displayName = userName),
        createdAt = Clock.System.now(),
      )
    return Pair(credential, privateKey)
  }

  private fun sampleMetadata(
    userName: String,
    displayName: String,
    credentialId: ByteArray,
  ): PasskeyMetadata =
    PasskeyMetadata(
      credentialId = credentialId,
      rpId = "github.com",
      userName = userName,
      userDisplayName = displayName,
      createdAt = Clock.System.now(),
    )

  private fun ByteArray.indexOfSubsequence(other: ByteArray): Int {
    if (other.isEmpty() || other.size > size) return -1
    for (index in 0..size - other.size) {
      if (copyOfRange(index, index + other.size).contentEquals(other)) {
        return index
      }
    }
    return -1
  }
}
