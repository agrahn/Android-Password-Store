/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.model

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class StoredCredentialTest {

  @Test
  fun `parse fixture credential 1`() {
    val bytes =
      javaClass
        .getResourceAsStream(
          "/fixtures/07b36924d8924098bb427039d7d0f43b86b4cb52a9dec9aab04bf47472e02d7b.bin"
        )!!
        .readBytes()
    val credential = StoredCredential.fromCbor(bytes)

    assertEquals(32, credential.id.size)
    assertEquals(0x07, credential.id[0].toInt() and 0xFF)
    assertEquals(0xb3, credential.id[1].toInt() and 0xFF)

    assertEquals("webauthn.io", credential.rp.id)
    assertNull(credential.rp.name)

    assertEquals("webauthnio-soft-fido2", String(credential.user.id, Charsets.UTF_8))
    assertEquals("soft-fido2", credential.user.name)
    assertNull(credential.user.displayName)

    assertEquals(0u, credential.signCount)
    assertEquals(-8, credential.alg)
    assertEquals(32, credential.privateKey.size)
    assertTrue(credential.discoverable)
    assertEquals(3, credential.extensions.credProtect)
    assertNull(credential.extensions.hmacSecret)
  }

  @Test
  fun `parse fixture credential 2`() {
    val bytes =
      javaClass
        .getResourceAsStream(
          "/fixtures/1381816530c267f00fb7d8a844b65f765cbbc059d8d7c695a40b7a1dea48f139.bin"
        )!!
        .readBytes()
    val credential = StoredCredential.fromCbor(bytes)

    assertEquals("webauthn.io", credential.rp.id)
    assertEquals("passless", credential.user.name)
    assertEquals(-8, credential.alg)
    assertEquals(3, credential.extensions.credProtect)
  }

  @Test
  fun `roundtrip credential`() {
    val privateKey = ByteArray(32) { (it + 0x10).toByte() }
    val original =
      StoredCredential(
        id = byteArrayOf(0x01, 0x02, 0x03, 0x04),
        rp = RelyingParty(id = "example.com", name = "Example Site"),
        user =
          User(id = byteArrayOf(0x05, 0x06, 0x07), name = "testuser", displayName = "Test User"),
        signCount = 42u,
        alg = StoredCredential.ALG_ES256,
        privateKey = privateKey,
        created = 1234567890L,
        discoverable = true,
        extensions = Extensions(credProtect = 2, hmacSecret = true),
      )

    val encoded = original.toCbor()
    val decoded = StoredCredential.fromCbor(encoded)

    assertArrayEquals(original.id, decoded.id)
    assertEquals(original.rp, decoded.rp)
    assertEquals(original.user, decoded.user)
    assertEquals(original.signCount, decoded.signCount)
    assertEquals(original.alg, decoded.alg)
    assertArrayEquals(original.privateKey, decoded.privateKey)
    assertEquals(original.created, decoded.created)
    assertEquals(original.discoverable, decoded.discoverable)
    assertEquals(original.extensions, decoded.extensions)
  }

  @Test
  fun `credential id hex`() {
    val credential =
      StoredCredential(
        id = byteArrayOf(0x01, 0x02, 0x0a, 0x0f, 0xff.toByte()),
        rp = RelyingParty(id = "test.com"),
        user = User(id = byteArrayOf(0x01)),
        signCount = 0u,
        alg = StoredCredential.ALG_ES256,
        privateKey = byteArrayOf(0x00),
        created = 0L,
      )

    assertEquals("01020a0fff", credential.credentialIdHex())
  }

  @Test
  fun `minimal credential`() {
    val privateKey = ByteArray(32) { 0x00 }
    val original =
      StoredCredential(
        id = byteArrayOf(0x01, 0x02),
        rp = RelyingParty(id = "test.com"),
        user = User(id = byteArrayOf(0x03)),
        signCount = 0u,
        alg = StoredCredential.ALG_ES256,
        privateKey = privateKey,
        created = 0L,
      )

    val encoded = original.toCbor()
    val decoded = StoredCredential.fromCbor(encoded)

    assertEquals(original, decoded)
  }

  @Test
  fun `private key shorter than 32 bytes is normalized`() {
    val shortKey = byteArrayOf(0x01, 0x02, 0x03, 0x04)
    val original =
      StoredCredential(
        id = byteArrayOf(0x01),
        rp = RelyingParty(id = "test.com"),
        user = User(id = byteArrayOf(0x02)),
        signCount = 0u,
        alg = StoredCredential.ALG_ES256,
        privateKey = shortKey,
        created = 0L,
      )

    val encoded = original.toCbor()
    val decoded = StoredCredential.fromCbor(encoded)

    assertEquals(32, decoded.privateKey.size)
    val expectedKey = ByteArray(28) + shortKey
    assertArrayEquals(expectedKey, decoded.privateKey)
  }

  @Test
  fun `mismatched public key is nulled out`() {
    val privateKey = ByteArray(32) { (it + 1).toByte() }
    val wrongPublicKey = ByteArray(65) { 0x04 }
    val original =
      StoredCredential(
        id = byteArrayOf(0x01),
        rp = RelyingParty(id = "test.com"),
        user = User(id = byteArrayOf(0x02)),
        signCount = 0u,
        alg = StoredCredential.ALG_ES256,
        privateKey = privateKey,
        publicKey = wrongPublicKey,
        created = 0L,
      )

    val encoded = original.toCbor()
    val decoded = StoredCredential.fromCbor(encoded)

    assertNull(decoded.publicKey)
  }

  @Test
  fun `matching public key is preserved`() {
    val privateKey = ByteArray(32) { (it + 1).toByte() }
    val correctPublicKey = StoredCredential.deriveP256PublicKey(privateKey)
    val original =
      StoredCredential(
        id = byteArrayOf(0x01),
        rp = RelyingParty(id = "test.com"),
        user = User(id = byteArrayOf(0x02)),
        signCount = 0u,
        alg = StoredCredential.ALG_ES256,
        privateKey = privateKey,
        publicKey = correctPublicKey,
        created = 0L,
      )

    val encoded = original.toCbor()
    val decoded = StoredCredential.fromCbor(encoded)

    assertArrayEquals(correctPublicKey, decoded.publicKey)
  }

  @Test
  fun `metadataFromCbor extracts user info without private key`() {
    val privateKey = ByteArray(32) { (it + 0x10).toByte() }
    val original =
      StoredCredential(
        id = byteArrayOf(0x01, 0x02, 0x03, 0x04),
        rp = RelyingParty(id = "example.com", name = "Example Site"),
        user =
          User(id = byteArrayOf(0x05, 0x06, 0x07), name = "testuser", displayName = "Test User"),
        signCount = 42u,
        alg = StoredCredential.ALG_ES256,
        privateKey = privateKey,
        created = 1234567890L,
        discoverable = true,
        extensions = Extensions(credProtect = 2, hmacSecret = true),
        backupEligible = true,
        backupState = false,
      )

    val encoded = original.toCbor()
    val metadata = StoredCredential.metadataFromCbor(encoded)

    assertArrayEquals(byteArrayOf(0x01, 0x02, 0x03, 0x04), metadata.credentialId)
    assertEquals("example.com", metadata.rpId)
    assertEquals("testuser", metadata.userName)
    assertEquals("Test User", metadata.userDisplayName)
    assertEquals(42uL, metadata.signCount)
    assertEquals(true, metadata.backupEligible)
    assertEquals(false, metadata.backupState)
  }

  @Test
  fun `metadataFromCbor handles null user fields`() {
    val privateKey = ByteArray(32) { (it + 0x10).toByte() }
    val original =
      StoredCredential(
        id = byteArrayOf(0x0A, 0x0B),
        rp = RelyingParty(id = "rp.test", name = null),
        user = User(id = byteArrayOf(0x01), name = null, displayName = null),
        signCount = 0u,
        alg = StoredCredential.ALG_ES256,
        privateKey = privateKey,
        created = 0L,
      )

    val encoded = original.toCbor()
    val metadata = StoredCredential.metadataFromCbor(encoded)

    assertEquals("rp.test", metadata.rpId)
    assertEquals("", metadata.userName)
    assertEquals("", metadata.userDisplayName)
  }

  @Test
  fun `metadataFromCbor works with passless fixture`() {
    val bytes =
      javaClass
        .getResourceAsStream(
          "/fixtures/07b36924d8924098bb427039d7d0f43b86b4cb52a9dec9aab04bf47472e02d7b.bin"
        )!!
        .readBytes()
    val metadata = StoredCredential.metadataFromCbor(bytes)

    assertEquals("webauthn.io", metadata.rpId)
    assertEquals("soft-fido2", metadata.userName)
    assertEquals("", metadata.userDisplayName)
    assertEquals(32, metadata.credentialId.size)
  }
}
