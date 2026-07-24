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
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock

class FrameworkClientDataHashTest {

  private val cryptoHandler = ES256CryptoHandler()

  @Test
  fun `privileged browser assertion signs exact framework-provided hash`() {
    val credential = createTestCredential()
    val frameworkHash = ByteArray(32) { (it + 42).toByte() }
    val responseJson = """{"type":"webauthn.get","origin":"https://example.com"}""".toByteArray()

    val result =
      cryptoHandler.getAssertionWithFrameworkHash(
        credential = credential,
        rpId = "example.com",
        clientDataHash = frameworkHash,
        responseClientDataJson = responseJson,
      )

    assertTrue(result.isOk, "Should succeed with valid framework hash")
    val assertion = result.getOrElse { throw AssertionError("Failed") }

    val verifyResult =
      cryptoHandler.verify(
        credential.publicKey,
        assertion.signature,
        assertion.authenticatorData,
        frameworkHash,
      )
    assertTrue(verifyResult.isOk, "Verify should complete")
    assertTrue(
      verifyResult.getOrElse { false },
      "Signature must verify against exact framework hash",
    )
  }

  @Test
  fun `one byte change in hash causes verification failure`() {
    val credential = createTestCredential()
    val frameworkHash = ByteArray(32) { (it + 42).toByte() }
    val responseJson = """{"type":"webauthn.get"}""".toByteArray()

    val result =
      cryptoHandler.getAssertionWithFrameworkHash(
        credential = credential,
        rpId = "example.com",
        clientDataHash = frameworkHash,
        responseClientDataJson = responseJson,
      )
    val assertion = result.getOrElse { throw AssertionError("Failed") }

    val tamperedHash = frameworkHash.copyOf()
    tamperedHash[15] = (tamperedHash[15].toInt() xor 0xFF).toByte()

    val verifyResult =
      cryptoHandler.verify(
        credential.publicKey,
        assertion.signature,
        assertion.authenticatorData,
        tamperedHash,
      )
    assertTrue(verifyResult.isOk, "Verify should complete")
    assertFalse(verifyResult.getOrElse { true }, "Signature must NOT verify against tampered hash")
  }

  @Test
  fun `framework hash with 31 bytes is rejected`() {
    val credential = createTestCredential()
    val shortHash = ByteArray(31) { it.toByte() }
    val responseJson = """{"type":"webauthn.get"}""".toByteArray()

    val result =
      cryptoHandler.getAssertionWithFrameworkHash(
        credential = credential,
        rpId = "example.com",
        clientDataHash = shortHash,
        responseClientDataJson = responseJson,
      )

    assertTrue(result.isErr, "Should reject 31-byte hash")
  }

  @Test
  fun `framework hash with 33 bytes is rejected`() {
    val credential = createTestCredential()
    val longHash = ByteArray(33) { it.toByte() }
    val responseJson = """{"type":"webauthn.get"}""".toByteArray()

    val result =
      cryptoHandler.getAssertionWithFrameworkHash(
        credential = credential,
        rpId = "example.com",
        clientDataHash = longHash,
        responseClientDataJson = responseJson,
      )

    assertTrue(result.isErr, "Should reject 33-byte hash")
  }

  @Test
  fun `empty response client data JSON is rejected`() {
    val credential = createTestCredential()
    val frameworkHash = ByteArray(32) { it.toByte() }

    val result =
      cryptoHandler.getAssertionWithFrameworkHash(
        credential = credential,
        rpId = "example.com",
        clientDataHash = frameworkHash,
        responseClientDataJson = ByteArray(0),
      )

    assertTrue(result.isErr, "Should reject empty response client data JSON")
  }

  @Test
  fun `blank rpId is rejected for framework hash assertion`() {
    val credential = createTestCredential()
    val frameworkHash = ByteArray(32) { it.toByte() }
    val responseJson = """{"type":"webauthn.get"}""".toByteArray()

    val result =
      cryptoHandler.getAssertionWithFrameworkHash(
        credential = credential,
        rpId = "",
        clientDataHash = frameworkHash,
        responseClientDataJson = responseJson,
      )

    assertTrue(result.isErr, "Should reject blank RP ID")
  }

  @Test
  fun `assertion response contains framework response client data JSON`() {
    val credential = createTestCredential()
    val frameworkHash = ByteArray(32) { (it + 10).toByte() }
    val responseJson =
      """{"type":"webauthn.get","origin":"https://example.com","crossOrigin":false}""".toByteArray()

    val result =
      cryptoHandler.getAssertionWithFrameworkHash(
        credential = credential,
        rpId = "example.com",
        clientDataHash = frameworkHash,
        responseClientDataJson = responseJson,
      )

    val assertion = result.getOrElse { throw AssertionError("Failed") }
    assertTrue(
      assertion.clientDataJSON.contentEquals(responseJson),
      "Response client data JSON must match framework-provided bytes exactly",
    )
  }

  @Test
  fun `signed byte sequence is authenticatorData concat frameworkHash`() {
    val credential = createTestCredential()
    val frameworkHash = ByteArray(32) { (it + 5).toByte() }
    val responseJson = """{"type":"webauthn.get"}""".toByteArray()

    val result =
      cryptoHandler.getAssertionWithFrameworkHash(
        credential = credential,
        rpId = "example.com",
        clientDataHash = frameworkHash,
        responseClientDataJson = responseJson,
      )

    val assertion = result.getOrElse { throw AssertionError("Failed") }

    val expectedSignedData = assertion.authenticatorData + frameworkHash
    val expectedHash = MessageDigest.getInstance("SHA-256").digest(expectedSignedData)

    val directSign =
      cryptoHandler.sign(credential.privateKey, assertion.authenticatorData, frameworkHash)
    val directSignature = directSign.getOrElse { throw AssertionError("Direct sign failed") }

    val verifyDirect =
      cryptoHandler.verify(
        credential.publicKey,
        assertion.signature,
        assertion.authenticatorData,
        frameworkHash,
      )
    assertTrue(
      verifyDirect.getOrElse { false },
      "Signature must verify over authData || frameworkHash",
    )
  }

  @Test
  fun `native provider-constructed assertion uses reconstructed hash`() {
    val credential = createTestCredential()
    val challenge = ByteArray(32) { it.toByte() }
    val origin = "https://example.com"

    val result =
      cryptoHandler.getAssertion(
        credential = credential,
        rpId = "example.com",
        challenge = challenge,
        origin = origin,
      )

    assertTrue(result.isOk, "Native assertion should succeed")
    val assertion = result.getOrElse { throw AssertionError("Failed") }

    val clientDataHash = MessageDigest.getInstance("SHA-256").digest(assertion.clientDataJSON)

    val verifyResult =
      cryptoHandler.verify(
        credential.publicKey,
        assertion.signature,
        assertion.authenticatorData,
        clientDataHash,
      )
    assertTrue(
      verifyResult.getOrElse { false },
      "Native assertion must verify against reconstructed hash",
    )
  }

  @Test
  fun `signAssertion delegates to sign correctly`() {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    val authData = ByteArray(37) { it.toByte() }
    val clientDataHash = ByteArray(32) { (it + 7).toByte() }

    val signResult = cryptoHandler.signAssertion(privateKey, authData, clientDataHash)
    assertTrue(signResult.isOk, "signAssertion should succeed")
    val signature = signResult.getOrElse { throw AssertionError("Failed") }

    val verifyResult = cryptoHandler.verify(publicKey, signature, authData, clientDataHash)
    assertTrue(verifyResult.getOrElse { false }, "signAssertion result should verify")
  }

  @Test
  fun `ClientDataBinding FrameworkHash equality works`() {
    val hash = ByteArray(32) { it.toByte() }
    val json = """{"type":"webauthn.get"}""".toByteArray()

    val binding1 = ClientDataBinding.FrameworkHash(hash = hash, responseClientDataJson = json)
    val binding2 =
      ClientDataBinding.FrameworkHash(hash = hash.copyOf(), responseClientDataJson = json.copyOf())

    assertEquals(binding1, binding2, "FrameworkHash equality should compare by content")
  }

  @Test
  fun `ClientDataBinding ProviderConstructed is singleton`() {
    val binding1 = ClientDataBinding.ProviderConstructed
    val binding2 = ClientDataBinding.ProviderConstructed

    assertEquals(binding1, binding2, "ProviderConstructed should be a singleton")
  }

  @Test
  fun `credential with no private key is rejected for framework hash`() {
    val credential =
      PasskeyCredential(
        credentialId = ByteArray(32) { it.toByte() },
        privateKey = ByteArray(0),
        publicKey = ByteArray(65) { it.toByte() },
        rpId = "example.com",
        user = FidoUser(id = "user".toByteArray(), name = "test", displayName = "Test"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
      )
    val frameworkHash = ByteArray(32) { it.toByte() }
    val responseJson = """{"type":"webauthn.get"}""".toByteArray()

    val result =
      cryptoHandler.getAssertionWithFrameworkHash(
        credential = credential,
        rpId = "example.com",
        clientDataHash = frameworkHash,
        responseClientDataJson = responseJson,
      )

    assertTrue(result.isErr, "Should reject credential with no private key")
  }

  private fun createTestCredential(): PasskeyCredential {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    return PasskeyCredential(
      credentialId = ByteArray(32) { it.toByte() },
      privateKey = privateKey,
      publicKey = publicKey,
      rpId = "example.com",
      user = FidoUser(id = "user-id".toByteArray(), name = "testuser", displayName = "Test User"),
      signCount = 0u,
      createdAt = Clock.System.now(),
      transports = listOf("internal"),
      uvInitialized = true,
    )
  }
}
