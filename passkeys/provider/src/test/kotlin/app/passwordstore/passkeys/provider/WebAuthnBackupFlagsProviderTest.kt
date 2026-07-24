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
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock

class WebAuthnBackupFlagsProviderTest {

  private val cryptoHandler = ES256CryptoHandler()

  @Test
  fun `registration flags match stored credential state for syncable credential`() {
    val (credential, _) = createCredential(backupEligible = true, backupState = false)

    val responseJson = buildAttestation(credential)
    val response =
      PasskeyProviderUtils.json.decodeFromString(AttestationResponseJson.serializer(), responseJson)

    val authData = PasskeyProviderUtils.decodeBase64Url(response.response.authenticatorData)
    val flagsByte = authData[32].toInt() and 0xFF
    assertTrue(flagsByte and 0x08 != 0, "Registration should set BE for syncable credential")
    assertFalse((flagsByte and 0x10) != 0, "Registration should not set BS before backup")
    assertTrue(flagsByte and 0x40 != 0, "Registration should set AT flag")
  }

  @Test
  fun `registration flags include BS for backed up credential`() {
    val (credential, _) = createCredential(backupEligible = true, backupState = true)

    val responseJson = buildAttestation(credential)
    val response =
      PasskeyProviderUtils.json.decodeFromString(AttestationResponseJson.serializer(), responseJson)

    val authData = PasskeyProviderUtils.decodeBase64Url(response.response.authenticatorData)
    val flagsByte = authData[32].toInt() and 0xFF
    assertTrue(flagsByte and 0x08 != 0, "Registration should set BE")
    assertTrue(flagsByte and 0x10 != 0, "Registration should set BS for backed up credential")
  }

  @Test
  fun `registration flags exclude BE for device-bound credential`() {
    val (credential, _) = createCredential(backupEligible = false, backupState = false)

    val responseJson = buildAttestation(credential)
    val response =
      PasskeyProviderUtils.json.decodeFromString(AttestationResponseJson.serializer(), responseJson)

    val authData = PasskeyProviderUtils.decodeBase64Url(response.response.authenticatorData)
    val flagsByte = authData[32].toInt() and 0xFF
    assertFalse((flagsByte and 0x08) != 0, "Registration should not set BE for device-bound")
    assertFalse((flagsByte and 0x10) != 0, "Registration should not set BS for device-bound")
  }

  @Test
  fun `registration and assertion use consistent BE BS flags for same credential`() {
    val (credential, privateKey) = createCredential(backupEligible = true, backupState = true)

    val assertion =
      cryptoHandler
        .getAssertion(
          credential = credential,
          privateKey = privateKey,
          rpId = "example.com",
          challenge = ByteArray(32),
          origin = "https://example.com",
        )
        .getOrElse { throw AssertionError("Assertion failed") }

    val assertionFlags = assertion.authenticatorData[32].toInt() and 0xFF

    val responseJson = buildAttestation(credential)
    val response =
      PasskeyProviderUtils.json.decodeFromString(AttestationResponseJson.serializer(), responseJson)
    val authData = PasskeyProviderUtils.decodeBase64Url(response.response.authenticatorData)
    val registrationFlags = authData[32].toInt() and 0xFF

    val backupBitsMask = 0x18
    assertEquals(
      assertionFlags and backupBitsMask,
      registrationFlags and backupBitsMask,
      "Registration and assertion should encode the same BE/BS bits",
    )
  }

  private fun buildAttestation(credential: PasskeyCredential): String {
    val requestJson =
      """
      {
        "rp": {"id": "example.com", "name": "Test"},
        "user": {"id": "dXNlcg", "name": "test", "displayName": "Test"},
        "challenge": "Y2hhbGxlbmdl"
      }
      """
        .trimIndent()
    val verifiedContext =
      VerifiedWebAuthnContext(
        callingPackage = "com.test",
        origin = "https://example.com",
        callerType = CallerType.NATIVE_APP,
        signingCertificateDigests = setOf("test"),
        clientDataBinding = ClientDataBinding.ProviderConstructed,
      )
    return PasskeyProviderUtils.buildAttestationResponse(credential, requestJson, verifiedContext)
  }

  private fun createCredential(
    backupEligible: Boolean = true,
    backupState: Boolean = false,
  ): Pair<PasskeyCredential, ByteArray> {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    val credential =
      PasskeyCredential(
        credentialId = ByteArray(32) { it.toByte() },
        publicKey = publicKey,
        rpId = "example.com",
        user = FidoUser(id = "user-id".toByteArray(), name = "testuser", displayName = "Test User"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
        backupEligible = backupEligible,
        backupState = backupState,
      )
    return Pair(credential, privateKey)
  }
}
