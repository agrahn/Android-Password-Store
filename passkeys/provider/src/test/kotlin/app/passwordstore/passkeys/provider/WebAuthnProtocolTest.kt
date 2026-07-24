/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.provider

import app.passwordstore.passkeys.crypto.CallerType
import app.passwordstore.passkeys.crypto.ClientDataBinding
import app.passwordstore.passkeys.crypto.ES256CryptoHandler
import app.passwordstore.passkeys.crypto.VerifiedWebAuthnContext
import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.getOrElse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock

class WebAuthnProtocolTest {

  private val cryptoHandler = ES256CryptoHandler()

  @Test
  fun `authenticator data has correct structure for assertion`() {
    val (credential, privateKey) = createTestCredential()
    val assertion =
      cryptoHandler
        .getAssertion(
          credential = credential,
          privateKey = privateKey,
          rpId = credential.rpId,
          challenge = ByteArray(32) { it.toByte() },
          origin = "https://${credential.rpId}",
        )
        .getOrElse { throw AssertionError("Assertion failed") }

    val authData = assertion.authenticatorData

    assertEquals(37, authData.size, "Authenticator data should be 37 bytes")

    val rpIdHash = authData.sliceArray(0..31)
    assertEquals(32, rpIdHash.size, "RP ID hash should be 32 bytes")

    val flags = authData[32].toInt() and 0xFF
    assertTrue(flags and 0x01 != 0, "UP flag should be set")
    assertTrue(flags and 0x04 != 0, "UV flag should be set")
    assertTrue(flags and 0x40 == 0, "AT flag should NOT be set for assertions")

    val signCount = authData.sliceArray(33..36)
    assertEquals(4, signCount.size, "Sign count should be 4 bytes")
  }

  @Test
  fun `attestation object has correct CBOR structure`() {
    val (credential, _) = createTestCredential()
    val requestJson =
      """
      {
        "rp": {"id": "${credential.rpId}", "name": "Test"},
        "user": {"id": "dXNlcg", "name": "test", "displayName": "Test User"},
        "challenge": "Y2hhbGxlbmdl"
      }
    """
        .trimIndent()
    val verifiedContext =
      VerifiedWebAuthnContext(
        callingPackage = "com.test",
        origin = "https://${credential.rpId}",
        callerType = CallerType.NATIVE_APP,
        signingCertificateDigests = setOf("test"),
        clientDataBinding = ClientDataBinding.ProviderConstructed,
      )

    val responseJson =
      PasskeyProviderUtils.buildAttestationResponse(credential, requestJson, verifiedContext)
    val response =
      PasskeyProviderUtils.json.decodeFromString(AttestationResponseJson.serializer(), responseJson)

    assertEquals("public-key", response.type)
    assertEquals(response.id, response.rawId)

    val attestationObject =
      PasskeyProviderUtils.decodeBase64Url(response.response.attestationObject)

    assertTrue(attestationObject.size > 37, "Attestation object should contain auth data")

    val firstByte = attestationObject[0].toInt() and 0xFF
    assertTrue(firstByte in 0xA0..0xBF, "First byte should be CBOR map indicator")

    val attestationString = attestationObject.decodeToString()
    assertTrue(attestationString.contains("fmt"), "Should contain fmt field")
    assertTrue(attestationString.contains("none"), "Should use none attestation")
    assertTrue(attestationString.contains("authData"), "Should contain authData field")
  }

  @Test
  fun `attested credential data is included in attestation`() {
    val (credential, _) = createTestCredential()
    val requestJson =
      """
      {
        "rp": {"id": "${credential.rpId}", "name": "Test"},
        "user": {"id": "dXNlcg", "name": "test", "displayName": "Test User"},
        "challenge": "Y2hhbGxlbmdl"
      }
    """
        .trimIndent()
    val verifiedContext =
      VerifiedWebAuthnContext(
        callingPackage = "com.test",
        origin = "https://${credential.rpId}",
        callerType = CallerType.NATIVE_APP,
        signingCertificateDigests = setOf("test"),
        clientDataBinding = ClientDataBinding.ProviderConstructed,
      )

    val responseJson =
      PasskeyProviderUtils.buildAttestationResponse(credential, requestJson, verifiedContext)
    val response =
      PasskeyProviderUtils.json.decodeFromString(AttestationResponseJson.serializer(), responseJson)

    val attestationObject =
      PasskeyProviderUtils.decodeBase64Url(response.response.attestationObject)

    val authDataStart = findAuthDataInCbor(attestationObject)
    assertTrue(authDataStart >= 0, "Should find authData in attestation object")

    val flags = attestationObject[authDataStart + 32].toInt() and 0xFF
    assertTrue(flags and 0x40 != 0, "AT flag should be set for attestation")
  }

  @Test
  fun `client data JSON has correct format`() {
    val (credential, _) = createTestCredential()
    val requestJson =
      """
      {
        "rp": {"id": "${credential.rpId}", "name": "Test"},
        "user": {"id": "dXNlcg", "name": "test", "displayName": "Test User"},
        "challenge": "test-challenge-base64"
      }
    """
        .trimIndent()
    val verifiedContext =
      VerifiedWebAuthnContext(
        callingPackage = "com.test",
        origin = "https://${credential.rpId}",
        callerType = CallerType.NATIVE_APP,
        signingCertificateDigests = setOf("test"),
        clientDataBinding = ClientDataBinding.ProviderConstructed,
      )

    val responseJson =
      PasskeyProviderUtils.buildAttestationResponse(credential, requestJson, verifiedContext)
    val response =
      PasskeyProviderUtils.json.decodeFromString(AttestationResponseJson.serializer(), responseJson)

    val clientDataJson =
      PasskeyProviderUtils.decodeBase64Url(response.response.clientDataJSON).decodeToString()

    assertTrue(clientDataJson.contains("\"type\":\"webauthn.create\""), "Should have correct type")
    assertTrue(
      clientDataJson.contains("\"challenge\":\"test-challenge-base64\""),
      "Should preserve challenge",
    )
    assertTrue(
      clientDataJson.contains("\"origin\":\"https://${credential.rpId}\""),
      "Should have correct origin",
    )
    assertTrue(clientDataJson.contains("\"crossOrigin\":false"), "Should have crossOrigin field")
  }

  @Test
  fun `assertion response has correct format`() {
    val (credential, privateKey) = createTestCredential()
    val requestJson =
      """
      {
        "challenge": "test-challenge",
        "origin": "https://${credential.rpId}",
        "allowCredentials": []
      }
    """
        .trimIndent()

    val assertion =
      cryptoHandler
        .getAssertion(
          credential = credential,
          privateKey = privateKey,
          rpId = credential.rpId,
          challenge = ByteArray(32) { it.toByte() },
          origin = "https://${credential.rpId}",
        )
        .getOrElse { throw AssertionError("Assertion failed") }

    val responseJson =
      PasskeyProviderUtils.buildAssertionResponse(assertion, credential, requestJson)
    val response =
      PasskeyProviderUtils.json.decodeFromString(AssertionResponseJson.serializer(), responseJson)

    assertEquals("public-key", response.type)
    assertEquals(response.id, response.rawId)

    val clientDataJson =
      PasskeyProviderUtils.decodeBase64Url(response.response.clientDataJSON).decodeToString()
    assertTrue(
      clientDataJson.contains("\"type\":\"webauthn.get\""),
      "Should have correct type for assertion",
    )
    assertTrue(clientDataJson.contains("\"crossOrigin\":false"), "Should have crossOrigin field")

    val signatureBytes = PasskeyProviderUtils.decodeBase64Url(response.response.signature)
    assertTrue(
      signatureBytes.size in 70..72,
      "Signature should be DER-encoded (typically 70-72 bytes)",
    )
    assertEquals(
      37,
      PasskeyProviderUtils.decodeBase64Url(response.response.authenticatorData).size,
      "Auth data should be 37 bytes",
    )
  }

  @Test
  fun `COSE key has correct structure for P-256`() {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    assertEquals(65, publicKey.size, "Public key should be 65 bytes uncompressed")
    assertEquals(0x04, publicKey[0].toInt(), "Public key should start with 0x04 (uncompressed)")

    val x = publicKey.sliceArray(1..32)
    val y = publicKey.sliceArray(33..64)

    assertTrue(x.any { it != 0.toByte() }, "X coordinate should not be all zeros")
    assertTrue(y.any { it != 0.toByte() }, "Y coordinate should not be all zeros")
  }

  @Test
  fun `credential ID is 32 bytes from SecureRandom`() {
    val cred1 =
      cryptoHandler
        .createCredential(
          rpId = "example.com",
          userId = "user1".toByteArray(),
          userName = "user1",
          userDisplayName = "User One",
          challenge = ByteArray(32) { it.toByte() },
        )
        .getOrElse { throw AssertionError("Failed") }

    assertEquals(32, cred1.credential.credentialId.size, "Credential ID should be 32 bytes")

    val cred2 =
      cryptoHandler
        .createCredential(
          rpId = "example.com",
          userId = "user2".toByteArray(),
          userName = "user2",
          userDisplayName = "User Two",
          challenge = ByteArray(32) { it.toByte() },
        )
        .getOrElse { throw AssertionError("Failed") }

    assertTrue(
      !cred1.credential.credentialId.contentEquals(cred2.credential.credentialId),
      "Each credential should have unique ID",
    )
  }

  @Test
  fun `RP ID hash is SHA-256`() {
    val rpId = "example.com"
    val expectedHash = java.security.MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())

    val (credential, privateKey) = createTestCredential(rpId = rpId)
    val assertion =
      cryptoHandler
        .getAssertion(
          credential = credential,
          privateKey = privateKey,
          rpId = rpId,
          challenge = ByteArray(32) { it.toByte() },
          origin = "https://$rpId",
        )
        .getOrElse { throw AssertionError("Assertion failed") }

    val actualHash = assertion.authenticatorData.sliceArray(0..31)
    assertTrue(expectedHash.contentEquals(actualHash), "RP ID hash should match SHA-256 of RP ID")
  }

  private fun createTestCredential(
    rpId: String = "example.com",
    userName: String = "testuser",
  ): Pair<PasskeyCredential, ByteArray> {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    val credential =
      PasskeyCredential(
        credentialId = ByteArray(32) { it.toByte() },
        publicKey = publicKey,
        rpId = rpId,
        user = FidoUser(id = "user-id".toByteArray(), name = userName, displayName = "Test User"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
      )
    return Pair(credential, privateKey)
  }

  private fun findAuthDataInCbor(data: ByteArray): Int {
    for (i in 0..(data.size - 37)) {
      val flags = data[i + 32].toInt() and 0xFF
      if (flags and 0x45 == 0x45) {
        return i
      }
    }
    return -1
  }
}
