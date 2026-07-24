/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.crypto

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.RelyingParty
import app.passwordstore.passkeys.model.StoredCredential
import app.passwordstore.passkeys.model.User
import com.github.michaelbull.result.getOrElse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock

class WebAuthnBackupFlagsTest {

  private val cryptoHandler = ES256CryptoHandler()

  @Test
  fun `AuthenticatorFlags build sets UP and UV`() {
    val flags =
      AuthenticatorFlags.build(
        userPresent = true,
        userVerified = true,
        backupEligible = false,
        backupState = false,
      )
    assertEquals(0x05, flags.toInt() and 0xFF)
  }

  @Test
  fun `AuthenticatorFlags build sets BE for syncable credential`() {
    val flags =
      AuthenticatorFlags.build(
        userPresent = true,
        userVerified = true,
        backupEligible = true,
        backupState = false,
      )
    assertEquals(0x0D, flags.toInt() and 0xFF)
    assertTrue(flags.toInt() and AuthenticatorFlags.FLAG_BACKUP_ELIGIBLE.toInt() != 0)
    assertFalse(flags.toInt() and AuthenticatorFlags.FLAG_BACKUP_STATE.toInt() != 0)
  }

  @Test
  fun `AuthenticatorFlags build sets BE and BS for backed up credential`() {
    val flags =
      AuthenticatorFlags.build(
        userPresent = true,
        userVerified = true,
        backupEligible = true,
        backupState = true,
      )
    assertEquals(0x1D, flags.toInt() and 0xFF)
    assertTrue(flags.toInt() and AuthenticatorFlags.FLAG_BACKUP_ELIGIBLE.toInt() != 0)
    assertTrue(flags.toInt() and AuthenticatorFlags.FLAG_BACKUP_STATE.toInt() != 0)
  }

  @Test
  fun `AuthenticatorFlags build rejects BS without BE`() {
    assertFailsWith<IllegalArgumentException> {
      AuthenticatorFlags.build(
        userPresent = true,
        userVerified = true,
        backupEligible = false,
        backupState = true,
      )
    }
  }

  @Test
  fun `AuthenticatorFlags build includes AT flag`() {
    val flags =
      AuthenticatorFlags.build(
        userPresent = true,
        userVerified = true,
        backupEligible = true,
        backupState = false,
        attestedCredentialData = true,
      )
    assertEquals(0x4D, flags.toInt() and 0xFF)
    assertTrue(flags.toInt() and AuthenticatorFlags.FLAG_ATTESTED_CREDENTIAL_DATA.toInt() != 0)
  }

  @Test
  fun `new syncable credential before push has BE=1 BS=0`() {
    val created =
      cryptoHandler
        .createCredential(
          rpId = "example.com",
          userId = "user".toByteArray(),
          userName = "user",
          userDisplayName = "User",
          challenge = ByteArray(32),
        )
        .getOrElse { throw AssertionError("Create failed") }

    assertTrue(created.credential.backupEligible, "New credential should be backup eligible")
    assertFalse(created.credential.backupState, "New credential should not be backed up yet")
  }

  @Test
  fun `assertion flags include BE for syncable credential`() {
    val (credential, privateKey) =
      createSyncableCredentialPair(backupEligible = true, backupState = false)

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

    val flagsByte = assertion.authenticatorData[32].toInt() and 0xFF
    assertTrue(flagsByte and 0x01 != 0, "UP flag should be set")
    assertTrue(flagsByte and 0x04 != 0, "UV flag should be set")
    assertTrue(flagsByte and 0x08 != 0, "BE flag should be set for syncable credential")
    assertFalse((flagsByte and 0x10) != 0, "BS flag should not be set before backup")
  }

  @Test
  fun `assertion flags include BE and BS for backed up credential`() {
    val (credential, privateKey) =
      createSyncableCredentialPair(backupEligible = true, backupState = true)

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

    val flagsByte = assertion.authenticatorData[32].toInt() and 0xFF
    assertTrue(flagsByte and 0x08 != 0, "BE flag should be set")
    assertTrue(flagsByte and 0x10 != 0, "BS flag should be set")
  }

  @Test
  fun `assertion flags exclude BE for device-bound credential`() {
    val (credential, privateKey) =
      createSyncableCredentialPair(backupEligible = false, backupState = false)

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

    val flagsByte = assertion.authenticatorData[32].toInt() and 0xFF
    assertFalse((flagsByte and 0x08) != 0, "BE flag should not be set for device-bound credential")
    assertFalse((flagsByte and 0x10) != 0, "BS flag should not be set for device-bound credential")
  }

  @Test
  fun `PasskeyCredential rejects BS=true when BE=false`() {
    assertFailsWith<IllegalArgumentException> {
      PasskeyCredential(
        credentialId = ByteArray(32),
        publicKey = ByteArray(65),
        rpId = "example.com",
        user = FidoUser(id = ByteArray(1), name = "u", displayName = "u"),
        createdAt = Clock.System.now(),
        backupEligible = false,
        backupState = true,
      )
    }
  }

  @Test
  fun `StoredCredential CBOR roundtrip preserves backup fields`() {
    val original =
      StoredCredential(
        id = byteArrayOf(0x01, 0x02),
        rp = RelyingParty(id = "example.com"),
        user = User(id = byteArrayOf(0x03)),
        signCount = 0u,
        alg = StoredCredential.ALG_ES256,
        privateKey = byteArrayOf(0x10),
        created = 1000L,
        backupEligible = true,
        backupState = true,
      )

    val encoded = original.toCbor()
    val decoded = StoredCredential.fromCbor(encoded)

    assertEquals(original.backupEligible, decoded.backupEligible)
    assertEquals(original.backupState, decoded.backupState)
  }

  @Test
  fun `legacy StoredCredential without backup fields migrates to BE=true BS=false`() {
    val legacy =
      StoredCredential(
        id = byteArrayOf(0x01, 0x02),
        rp = RelyingParty(id = "example.com"),
        user = User(id = byteArrayOf(0x03)),
        signCount = 0u,
        alg = StoredCredential.ALG_ES256,
        privateKey = byteArrayOf(0x10),
        created = 1000L,
      )

    val encoded = legacy.toCbor()
    val decoded = StoredCredential.fromCbor(encoded)

    assertTrue(decoded.backupEligible, "Legacy credential should migrate to backup eligible")
    assertFalse(decoded.backupState, "Legacy credential should not be backed up")
  }

  @Test
  fun `StoredCredential toPasskeyCredential propagates backup fields`() {
    val stored =
      StoredCredential(
        id = byteArrayOf(0x01),
        rp = RelyingParty(id = "example.com"),
        user = User(id = byteArrayOf(0x02)),
        signCount = 0u,
        alg = StoredCredential.ALG_ES256,
        privateKey = cryptoHandler.generateKeyPair().first,
        created = 1000L,
        backupEligible = true,
        backupState = true,
      )

    val credential = stored.toPasskeyCredential()

    assertTrue(credential.backupEligible)
    assertTrue(credential.backupState)
  }

  @Test
  fun `StoredCredential fromPasskeyCredential propagates backup fields`() {
    val (credential, privateKey) =
      createSyncableCredentialPair(backupEligible = true, backupState = true)

    val stored = StoredCredential.fromPasskeyCredential(credential, privateKey)

    assertTrue(stored.backupEligible)
    assertTrue(stored.backupState)
  }

  @Test
  fun `passless fixture credential parses without backup fields`() {
    val bytes =
      javaClass
        .getResourceAsStream(
          "/fixtures/1381816530c267f00fb7d8a844b65f765cbbc059d8d7c695a40b7a1dea48f139.bin"
        )!!
        .readBytes()
    val credential = StoredCredential.fromCbor(bytes)

    assertTrue(
      credential.backupEligible,
      "Passless fixture should migrate to backup eligible (syncable)",
    )
    assertFalse(credential.backupState, "Passless fixture should default to not backed up")
  }

  @Test
  fun `passless fixture credential roundtrips with new backup fields`() {
    val bytes =
      javaClass
        .getResourceAsStream(
          "/fixtures/1381816530c267f00fb7d8a844b65f765cbbc059d8d7c695a40b7a1dea48f139.bin"
        )!!
        .readBytes()
    val original = StoredCredential.fromCbor(bytes)

    val reencoded = original.toCbor()
    val reparsed = StoredCredential.fromCbor(reencoded)

    assertEquals(original.backupEligible, reparsed.backupEligible)
    assertEquals(original.backupState, reparsed.backupState)
    assertEquals(original.rp, reparsed.rp)
    assertEquals(original.alg, reparsed.alg)
  }

  private fun createSyncableCredentialPair(
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
