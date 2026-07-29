/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
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
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Cross-implementation invariants shared with pando85/soft-fido2.
 *
 * soft-fido2's CTAP MakeCredential and GetAssertion handlers both treat the 32-byte clientDataHash
 * as an authenticator input and sign authenticatorData || clientDataHash. Its ES256 credential
 * public key encoding is the standard EC2 COSE map {1:2, 3:-7, -1:1, -2:x, -3:y}.
 */
class SoftFido2CompatibilityTest {

  private val cryptoHandler = ES256CryptoHandler()

  @Test
  fun `ES256 attested credential data matches soft-fido2 COSE reference vector`() {
    val x = ByteArray(32) { 0x42.toByte() }
    val y = ByteArray(32) { 0x43.toByte() }
    val credentialId = ByteArray(32) { it.toByte() }
    val publicKey = byteArrayOf(0x04) + x + y
    val credential =
      PasskeyCredential(
        credentialId = credentialId,
        publicKey = publicKey,
        rpId = "example.com",
        user = FidoUser(id = "user-id".toByteArray(), name = "test", displayName = "Test User"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
        backupEligible = false,
        backupState = false,
      )
    val requestJson =
      """
      {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": "dXNlci1pZA", "name": "test", "displayName": "Test User"},
        "challenge": "Y2hhbGxlbmdl",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
      }
      """
        .trimIndent()
    val verifiedContext =
      VerifiedWebAuthnContext(
        callingPackage = "com.example.native",
        origin = "android:apk-key-hash:test",
        callerType = CallerType.NATIVE_APP,
        signingCertificateDigests = setOf("test"),
        clientDataBinding = ClientDataBinding.ProviderConstructed,
      )

    val responseJson =
      PasskeyProviderUtils.buildAttestationResponse(credential, requestJson, verifiedContext)
    val response =
      PasskeyProviderUtils.json.decodeFromString(AttestationResponseJson.serializer(), responseJson)
    val authData = PasskeyProviderUtils.decodeBase64Url(response.response.authenticatorData)

    assertContentEquals(
      MessageDigest.getInstance("SHA-256").digest("example.com".toByteArray()),
      authData.copyOfRange(0, 32),
    )
    assertEquals(0x45, authData[32].toInt() and 0xFF, "UP, UV and AT flags should match CTAP")
    assertContentEquals(byteArrayOf(0, 0, 0, 0), authData.copyOfRange(33, 37))

    val credentialIdLengthOffset = 37 + 16
    assertContentEquals(
      byteArrayOf(0x00, 0x20),
      authData.copyOfRange(credentialIdLengthOffset, credentialIdLengthOffset + 2),
    )
    assertContentEquals(
      credentialId,
      authData.copyOfRange(
        credentialIdLengthOffset + 2,
        credentialIdLengthOffset + 2 + credentialId.size,
      ),
    )

    val coseOffset = credentialIdLengthOffset + 2 + credentialId.size
    val expectedCose =
      byteArrayOf(
        0xA5.toByte(),
        0x01,
        0x02,
        0x03,
        0x26,
        0x20,
        0x01,
        0x21,
        0x58,
        0x20,
      ) + x + byteArrayOf(0x22, 0x58, 0x20) + y

    assertContentEquals(expectedCose, authData.copyOfRange(coseOffset, authData.size))
  }

  @Test
  fun `framework assertion signs authData plus clientDataHash like soft-fido2`() {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    val frameworkHash = ByteArray(32) { (it + 1).toByte() }
    val credential =
      PasskeyCredential(
        credentialId = ByteArray(32) { it.toByte() },
        publicKey = publicKey,
        rpId = "example.com",
        user = FidoUser(id = "user-id".toByteArray(), name = "test", displayName = "Test User"),
        signCount = 42u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
        backupEligible = false,
        backupState = false,
      )

    val assertion =
      cryptoHandler
        .getAssertionWithFrameworkHash(
          credential = credential,
          privateKey = privateKey,
          rpId = credential.rpId,
          clientDataHash = frameworkHash,
          responseClientDataJson = "{}".toByteArray(),
          userVerified = true,
        )
        .getOrElse { throw AssertionError("Assertion failed", it) }

    assertEquals(37, assertion.authenticatorData.size)
    assertContentEquals(
      MessageDigest.getInstance("SHA-256").digest("example.com".toByteArray()),
      assertion.authenticatorData.copyOfRange(0, 32),
    )
    assertEquals(0x05, assertion.authenticatorData[32].toInt() and 0xFF, "UP and UV flags")
    assertContentEquals(
      byteArrayOf(0x00, 0x00, 0x00, 0x2A),
      assertion.authenticatorData.copyOfRange(33, 37),
    )

    val verifiesAgainstFrameworkHash =
      cryptoHandler
        .verify(
          publicKey = publicKey,
          signature = assertion.signature,
          authenticatorData = assertion.authenticatorData,
          clientDataHash = frameworkHash,
        )
        .getOrElse { false }
    assertTrue(verifiesAgainstFrameworkHash)

    val placeholderHash = MessageDigest.getInstance("SHA-256").digest(assertion.clientDataJSON)
    val verifiesAgainstPlaceholder =
      cryptoHandler
        .verify(
          publicKey = publicKey,
          signature = assertion.signature,
          authenticatorData = assertion.authenticatorData,
          clientDataHash = placeholderHash,
        )
        .getOrElse { false }
    assertFalse(
      verifiesAgainstPlaceholder,
      "Credential Manager placeholder must never replace the framework clientDataHash for signing",
    )
  }
}
