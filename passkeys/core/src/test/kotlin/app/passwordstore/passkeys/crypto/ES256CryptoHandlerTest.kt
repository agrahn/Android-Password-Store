/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.crypto

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.getOrElse
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Clock

class ES256CryptoHandlerTest {

  private val cryptoHandler = ES256CryptoHandler()

  @Test
  fun `generateKeyPair returns non-empty keys`() {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()

    assertTrue(privateKey.isNotEmpty(), "Private key should not be empty")
    assertTrue(publicKey.isNotEmpty(), "Public key should not be empty")
  }

  @Test
  fun `generateKeyPair generates different keys each time`() {
    val (privateKey1, publicKey1) = cryptoHandler.generateKeyPair()
    val (privateKey2, publicKey2) = cryptoHandler.generateKeyPair()

    assertTrue(
      !privateKey1.contentEquals(privateKey2) || !publicKey1.contentEquals(publicKey2),
      "Key pairs should be different",
    )
  }

  @Test
  fun `sign and verify work correctly`() {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    val authenticatorData = ByteArray(37) { it.toByte() }
    val clientDataHash = ByteArray(32) { (it * 2).toByte() }

    val signResult = cryptoHandler.sign(privateKey, authenticatorData, clientDataHash)

    assertTrue(signResult.isOk, "Sign should succeed")

    val signature = signResult.getOrElse { throw AssertionError("Sign failed") }
    assertTrue(signature.isNotEmpty(), "Signature should not be empty")

    val verifyResult = cryptoHandler.verify(publicKey, signature, authenticatorData, clientDataHash)

    assertTrue(verifyResult.isOk, "Verify should succeed")
    assertTrue(verifyResult.getOrElse { false }, "Signature should be valid")
  }

  @Test
  fun `verify fails with wrong signature`() {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    val authenticatorData = ByteArray(37) { it.toByte() }
    val clientDataHash = ByteArray(32) { (it * 2).toByte() }

    val wrongSignature = ByteArray(70) { 0 }

    val verifyResult =
      cryptoHandler.verify(publicKey, wrongSignature, authenticatorData, clientDataHash)

    val isOkOrFalse = verifyResult.isOk && !verifyResult.getOrElse { true }
    assertTrue(
      isOkOrFalse || verifyResult.isErr,
      "Verify should fail or return false for wrong signature",
    )
  }

  @Test
  fun `createCredential returns valid credential`() {
    val result =
      cryptoHandler.createCredential(
        rpId = "example.com",
        userId = "user123".toByteArray(),
        userName = "testuser",
        userDisplayName = "Test User",
        challenge = ByteArray(32) { it.toByte() },
      )

    assertTrue(result.isOk, "Create credential should succeed")

    val created = result.getOrElse { throw AssertionError("Create credential failed") }
    val credential = created.credential
    assertNotNull(credential.credentialId)
    created.usePrivateKey { privateKey -> assertNotNull(privateKey) }
    assertNotNull(credential.publicKey)
    assertEquals("example.com", credential.rpId)
    assertEquals("testuser", credential.user.name)
    assertEquals("Test User", credential.user.displayName)
    assertEquals(0u, credential.signCount)
  }

  @Test
  fun `getAssertion returns valid assertion`() {
    val created =
      cryptoHandler
        .createCredential(
          rpId = "example.com",
          userId = "user123".toByteArray(),
          userName = "testuser",
          userDisplayName = "Test User",
          challenge = ByteArray(32) { it.toByte() },
        )
        .getOrElse { throw AssertionError("Credential creation failed") }

    val assertionResult = created.usePrivateKey { privateKey ->
      cryptoHandler.getAssertion(
        credential = created.credential,
        privateKey = privateKey,
        rpId = "example.com",
        challenge = ByteArray(32) { it.toByte() },
        origin = "https://example.com",
      )
    }

    assertTrue(assertionResult.isOk, "Get assertion should succeed")

    val assertion = assertionResult.getOrElse { throw AssertionError("Get assertion failed") }
    assertNotNull(assertion.credentialId)
    assertNotNull(assertion.authenticatorData)
    assertNotNull(assertion.signature)
    assertNotNull(assertion.clientDataJSON)
    val clientDataStr = assertion.clientDataJSON.decodeToString()
    assertTrue(
      clientDataStr.contains("\"type\":\"webauthn.get\""),
      "Client data should have correct type",
    )
    assertTrue(
      clientDataStr.contains("\"crossOrigin\":false"),
      "Client data should have crossOrigin",
    )
    assertEquals(37, assertion.authenticatorData.size, "Authenticator data should be 37 bytes")
    assertEquals(
      0x0D,
      assertion.authenticatorData[32].toInt() and 0xFF,
      "Authenticator flags should set UP, UV, and BE for syncable credential",
    )
    assertTrue(
      assertion.signature.size in 68..72,
      "Signature should be DER-encoded (typically 68-72 bytes)",
    )
  }

  @Test
  fun `sign produces DER-encoded signature`() {
    val (privateKey, _) = cryptoHandler.generateKeyPair()
    val authenticatorData = ByteArray(37) { it.toByte() }
    val clientDataHash = ByteArray(32) { (it * 2).toByte() }

    val signResult = cryptoHandler.sign(privateKey, authenticatorData, clientDataHash)

    assertTrue(signResult.isOk, "Sign should succeed")
    val signature = signResult.getOrElse { throw AssertionError("Sign failed") }
    assertTrue(
      signature.size in 68..72,
      "DER signature should typically be 68-72 bytes, got ${signature.size}",
    )
  }

  @Test
  fun `sign and verify round-trip succeeds`() {
    val handler = ES256CryptoHandler()
    val (privateKey, publicKey) = handler.generateKeyPair()
    val authenticatorData = ByteArray(37) { if (it < 32) it.toByte() else (it - 32).toByte() }
    val clientDataHash = ByteArray(32) { (it + 10).toByte() }
    val signResult = handler.sign(privateKey, authenticatorData, clientDataHash)
    assertTrue(signResult.isOk, "Sign should succeed")
    val signature = signResult.getOrElse { throw AssertionError("Sign failed") }
    assertTrue(signature.size in 70..72, "Signature should be 70-72 bytes, got ${signature.size}")
    val verifyResult = handler.verify(publicKey, signature, authenticatorData, clientDataHash)
    assertTrue(verifyResult.isOk, "Verify should succeed")
    assertTrue(verifyResult.getOrElse { false }, "Signature should be valid")
  }

  @Test
  fun `getAssertion produces verifiable assertion`() {
    val handler = ES256CryptoHandler()
    val created =
      handler.createCredential(
        rpId = "example.com",
        userId = byteArrayOf(1),
        userName = "user",
        userDisplayName = "User",
        challenge = ByteArray(32),
      )
    assertTrue(created.isOk, "Create credential should succeed")
    val createdCred = created.getOrElse { throw AssertionError("Create credential failed") }

    val assertionResult = createdCred.usePrivateKey { privateKey ->
      handler.getAssertion(
        credential = createdCred.credential,
        privateKey = privateKey,
        rpId = "example.com",
        challenge = ByteArray(32),
        origin = "https://example.com",
      )
    }
    assertTrue(assertionResult.isOk, "Get assertion should succeed")
    val assertion = assertionResult.getOrElse { throw AssertionError("Get assertion failed") }

    assertEquals(37, assertion.authenticatorData.size, "Authenticator data should be 37 bytes")
    assertTrue(
      assertion.signature.size in 70..72,
      "Signature should be 70-72 bytes, got ${assertion.signature.size}",
    )
    val clientDataHash = MessageDigest.getInstance("SHA-256").digest(assertion.clientDataJSON)
    val verifyResult =
      handler.verify(
        createdCred.credential.publicKey,
        assertion.signature,
        assertion.authenticatorData,
        clientDataHash,
      )
    assertTrue(verifyResult.isOk, "Verify should succeed")
    assertTrue(verifyResult.getOrElse { false }, "Signature should be valid")
  }

  @Test
  fun `assertion with passless-generated key verifies`() {
    val privateKeyPkcs8Hex =
      "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420bbac624fcad5f4c02b19587910107e9f641cacbaa5f377021af660b87e43db05a14403420004ab3d5ec694acf7925f90997f7a5d5cc31530184fa83f1fd15db76f528ee97ddaedbb7141c3ad7caa0e5866bf57acc2377337051fbb664a6d0284235473472df2"
    val publicKeyRawHex =
      "04ab3d5ec694acf7925f90997f7a5d5cc31530184fa83f1fd15db76f528ee97ddaedbb7141c3ad7caa0e5866bf57acc2377337051fbb664a6d0284235473472df2"
    val credentialIdHex = "c347446904ec77359200888afa8b5299a113aa80fa501291a60223f6e55a3228"

    val privateKey = hexStringToByteArray(privateKeyPkcs8Hex)
    val publicKey = hexStringToByteArray(publicKeyRawHex)
    val credentialId = hexStringToByteArray(credentialIdHex)

    val credential =
      PasskeyCredential(
        credentialId = credentialId,
        publicKey = publicKey,
        rpId = "example.com",
        user =
          FidoUser(
            id = "passless-user".toByteArray(),
            name = "passless-user",
            displayName = "Passless User",
          ),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
      )

    val handler = ES256CryptoHandler()
    val assertionResult =
      handler.getAssertion(
        credential = credential,
        privateKey = privateKey,
        rpId = "example.com",
        challenge = ByteArray(32) { it.toByte() },
        origin = "https://example.com",
      )
    assertTrue(assertionResult.isOk, "Get assertion should succeed")
    val assertion = assertionResult.getOrElse { throw AssertionError("Get assertion failed") }

    val clientDataHash = MessageDigest.getInstance("SHA-256").digest(assertion.clientDataJSON)

    val verifyResult =
      handler.verify(
        credential.publicKey,
        assertion.signature,
        assertion.authenticatorData,
        clientDataHash,
      )
    assertTrue(verifyResult.isOk, "Verify should succeed")
    assertTrue(verifyResult.getOrElse { false }, "Signature should be valid")
  }

  @Test
  fun `authenticatorData has correct rpIdHash and flags`() {
    val handler = ES256CryptoHandler()
    val created =
      handler.createCredential(
        rpId = "example.com",
        userId = "user".toByteArray(),
        userName = "user",
        userDisplayName = "User",
        challenge = ByteArray(32),
      )
    assertTrue(created.isOk, "Create credential should succeed")
    val createdCred = created.getOrElse { throw AssertionError("Create credential failed") }

    val assertionResult = createdCred.usePrivateKey { privateKey ->
      handler.getAssertion(
        credential = createdCred.credential,
        privateKey = privateKey,
        rpId = "example.com",
        challenge = ByteArray(32),
        origin = "https://example.com",
      )
    }
    assertTrue(assertionResult.isOk, "Get assertion should succeed")
    val assertion = assertionResult.getOrElse { throw AssertionError("Get assertion failed") }

    val expectedRpIdHash = MessageDigest.getInstance("SHA-256").digest("example.com".toByteArray())

    val actualRpIdHash = assertion.authenticatorData.sliceArray(0..31)
    assertTrue(expectedRpIdHash.contentEquals(actualRpIdHash), "RP ID hash should match")

    val flagsByte = assertion.authenticatorData[32].toInt() and 0xFF
    assertTrue(flagsByte and 0x01 != 0, "UP flag should be set")
    assertTrue(flagsByte and 0x04 != 0, "UV flag should be set")

    val signCountBytes = assertion.authenticatorData.sliceArray(33..36)
    val signCount =
      ((signCountBytes[0].toInt() and 0xFF) shl 24) or
        ((signCountBytes[1].toInt() and 0xFF) shl 16) or
        ((signCountBytes[2].toInt() and 0xFF) shl 8) or
        (signCountBytes[3].toInt() and 0xFF)
    assertEquals(0, signCount, "Sign count should be 0")
  }

  @Test
  fun `clientDataJSON has correct format for GET`() {
    val handler = ES256CryptoHandler()
    val created =
      handler.createCredential(
        rpId = "example.com",
        userId = "user".toByteArray(),
        userName = "user",
        userDisplayName = "User",
        challenge = ByteArray(32),
      )
    assertTrue(created.isOk, "Create credential should succeed")
    val createdCred = created.getOrElse { throw AssertionError("Create credential failed") }

    val assertionResult = createdCred.usePrivateKey { privateKey ->
      handler.getAssertion(
        credential = createdCred.credential,
        privateKey = privateKey,
        rpId = "example.com",
        challenge = ByteArray(32),
        origin = "https://example.com",
      )
    }
    assertTrue(assertionResult.isOk, "Get assertion should succeed")
    val assertion = assertionResult.getOrElse { throw AssertionError("Get assertion failed") }

    val clientDataJSON = assertion.clientDataJSON.decodeToString()

    assertTrue(clientDataJSON.contains("\"type\":\"webauthn.get\""), "Type should be webauthn.get")

    assertTrue(
      clientDataJSON.contains("\"origin\":\"https://example.com\""),
      "Origin should be https://example.com",
    )

    assertTrue(clientDataJSON.contains("\"challenge\":\""), "Challenge should be present")
    assertTrue(!clientDataJSON.contains("\"challenge\":\"\""), "Challenge should not be empty")

    assertTrue(clientDataJSON.contains("\"crossOrigin\":false"), "Cross-origin should be false")
  }

  private fun hexStringToByteArray(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "Hex string must have even length" }
    return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
  }
}
