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

    val credential = result.getOrElse { throw AssertionError("Create credential failed") }
    assertNotNull(credential.credentialId)
    assertNotNull(credential.privateKey)
    assertNotNull(credential.publicKey)
    assertEquals("example.com", credential.rpId)
    assertEquals("testuser", credential.user.name)
    assertEquals("Test User", credential.user.displayName)
    assertEquals(0u, credential.signCount)
  }

  @Test
  fun `getAssertion returns valid assertion`() {
    val credentialResult =
      cryptoHandler.createCredential(
        rpId = "example.com",
        userId = "user123".toByteArray(),
        userName = "testuser",
        userDisplayName = "Test User",
        challenge = ByteArray(32) { it.toByte() },
      )

    val credential = credentialResult.getOrElse {
      throw AssertionError("Credential creation failed")
    }

    val assertionResult =
      cryptoHandler.getAssertion(
        credential = credential,
        rpId = "example.com",
        challenge = ByteArray(32) { it.toByte() },
        origin = "https://example.com",
      )

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
    // Create ES256CryptoHandler instance
    val handler = ES256CryptoHandler()
    // Generate a key pair via `generateKeyPair()`
    val (privateKey, publicKey) = handler.generateKeyPair()
    // Create dummy authenticatorData (37 bytes: 32 rpIdHash + 1 flags + 4 signCount)
    val authenticatorData = ByteArray(37) { if (it < 32) it.toByte() else (it - 32).toByte() }
    // Create dummy clientDataHash (32 bytes)
    val clientDataHash = ByteArray(32) { (it + 10).toByte() }
    // Call `sign(privateKey, authData, clientDataHash)` → get signature
    val signResult = handler.sign(privateKey, authenticatorData, clientDataHash)
    assertTrue(signResult.isOk, "Sign should succeed")
    val signature = signResult.getOrElse { throw AssertionError("Sign failed") }
    // Assert signature size is 70-72 bytes (DER-encoded)
    assertTrue(signature.size in 70..72, "Signature should be 70-72 bytes, got ${signature.size}")
    // Call `verify(publicKey, signature, authData, clientDataHash)` → should return true
    val verifyResult = handler.verify(publicKey, signature, authenticatorData, clientDataHash)
    assertTrue(verifyResult.isOk, "Verify should succeed")
    assertTrue(verifyResult.getOrElse { false }, "Signature should be valid")
  }

  @Test
  fun `getAssertion produces verifiable assertion`() {
    // Create handler, call `createCredential(rpId="example.com", userId=byteArrayOf(1),
    // userName="user", userDisplayName="User", challenge=ByteArray(32))`
    val handler = ES256CryptoHandler()
    val credentialResult =
      handler.createCredential(
        rpId = "example.com",
        userId = byteArrayOf(1),
        userName = "user",
        userDisplayName = "User",
        challenge = ByteArray(32),
      )
    assertTrue(credentialResult.isOk, "Create credential should succeed")
    val credential = credentialResult.getOrElse { throw AssertionError("Create credential failed") }

    // Call `getAssertion(credential, rpId="example.com", challenge=ByteArray(32),
    // origin="https://example.com")`
    val assertionResult =
      handler.getAssertion(
        credential = credential,
        rpId = "example.com",
        challenge = ByteArray(32),
        origin = "https://example.com",
      )
    assertTrue(assertionResult.isOk, "Get assertion should succeed")
    val assertion = assertionResult.getOrElse { throw AssertionError("Get assertion failed") }

    // Assert authenticatorData size is 37
    assertEquals(37, assertion.authenticatorData.size, "Authenticator data should be 37 bytes")
    // Assert signature size is 70-72
    assertTrue(
      assertion.signature.size in 70..72,
      "Signature should be 70-72 bytes, got ${assertion.signature.size}",
    )
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
  fun `assertion with passless-generated key verifies`() {
    // Load the passless fixture data (hex decode the PKCS8 private key and raw public key)
    val privateKeyPkcs8Hex =
      "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420bbac624fcad5f4c02b19587910107e9f641cacbaa5f377021af660b87e43db05a14403420004ab3d5ec694acf7925f90997f7a5d5cc31530184fa83f1fd15db76f528ee97ddaedbb7141c3ad7caa0e5866bf57acc2377337051fbb664a6d0284235473472df2"
    val publicKeyRawHex =
      "04ab3d5ec694acf7925f90997f7a5d5cc31530184fa83f1fd15db76f528ee97ddaedbb7141c3ad7caa0e5866bf57acc2377337051fbb664a6d0284235473472df2"
    val credentialIdHex = "c347446904ec77359200888afa8b5299a113aa80fa501291a60223f6e55a3228"

    // Hex decode the keys
    val privateKey = hexStringToByteArray(privateKeyPkcs8Hex)
    val publicKey = hexStringToByteArray(publicKeyRawHex)
    val credentialId = hexStringToByteArray(credentialIdHex)

    // Build a `PasskeyCredential` with: credentialId from fixture, privateKey from PKCS8 hex,
    // publicKey from raw hex,
    // rpId="example.com", user with id/name/displayName, signCount=0u,
    // transports=listOf("internal"),
    // uvInitialized=true, createdAt=Clock.System.now()
    val credential =
      PasskeyCredential(
        credentialId = credentialId,
        privateKey = privateKey,
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

    // Call `getAssertion(credential, "example.com", ByteArray(32){it.toByte()},
    // "https://example.com")`
    val handler = ES256CryptoHandler()
    val assertionResult =
      handler.getAssertion(
        credential = credential,
        rpId = "example.com",
        challenge = ByteArray(32) { it.toByte() },
        origin = "https://example.com",
      )
    assertTrue(assertionResult.isOk, "Get assertion should succeed")
    val assertion = assertionResult.getOrElse { throw AssertionError("Get assertion failed") }

    val clientDataHash = MessageDigest.getInstance("SHA-256").digest(assertion.clientDataJSON)

    // Verify signature with passless public key
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
    // Create credential and get assertion for rpId="example.com"
    val handler = ES256CryptoHandler()
    val credentialResult =
      handler.createCredential(
        rpId = "example.com",
        userId = "user".toByteArray(),
        userName = "user",
        userDisplayName = "User",
        challenge = ByteArray(32),
      )
    assertTrue(credentialResult.isOk, "Create credential should succeed")
    val credential = credentialResult.getOrElse { throw AssertionError("Create credential failed") }

    val assertionResult =
      handler.getAssertion(
        credential = credential,
        rpId = "example.com",
        challenge = ByteArray(32),
        origin = "https://example.com",
      )
    assertTrue(assertionResult.isOk, "Get assertion should succeed")
    val assertion = assertionResult.getOrElse { throw AssertionError("Get assertion failed") }

    // Compute expected rpIdHash = SHA256("example.com".toByteArray())
    val expectedRpIdHash = MessageDigest.getInstance("SHA-256").digest("example.com".toByteArray())

    // Assert assertion.authenticatorData[:32] == expected rpIdHash
    val actualRpIdHash = assertion.authenticatorData.sliceArray(0..31)
    assertTrue(expectedRpIdHash.contentEquals(actualRpIdHash), "RP ID hash should match")

    // Assert flags byte (authenticatorData[32]) has UP (0x01) and UV (0x04) set
    val flagsByte = assertion.authenticatorData[32].toInt() and 0xFF
    assertTrue(flagsByte and 0x01 != 0, "UP flag should be set")
    assertTrue(flagsByte and 0x04 != 0, "UV flag should be set")

    // Assert signCount (authenticatorData[33:37]) is 0
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
    // Create credential and get assertion
    val handler = ES256CryptoHandler()
    val credentialResult =
      handler.createCredential(
        rpId = "example.com",
        userId = "user".toByteArray(),
        userName = "user",
        userDisplayName = "User",
        challenge = ByteArray(32),
      )
    assertTrue(credentialResult.isOk, "Create credential should succeed")
    val credential = credentialResult.getOrElse { throw AssertionError("Create credential failed") }

    val assertionResult =
      handler.getAssertion(
        credential = credential,
        rpId = "example.com",
        challenge = ByteArray(32),
        origin = "https://example.com",
      )
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
