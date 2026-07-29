/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.model

import app.passwordstore.passkeys.crypto.CallerType
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class StoredCredentialBindingMetadataTest {

  private fun baseCredential(): StoredCredential =
    StoredCredential(
      id = ByteArray(32) { it.toByte() },
      rp = RelyingParty(id = "example.com", name = "Example"),
      user = User(id = "user1".toByteArray(), name = "testuser", displayName = "Test User"),
      signCount = 0u,
      alg = StoredCredential.ALG_ES256,
      privateKey = ByteArray(32) { (it + 1).toByte() },
      publicKey = ByteArray(65).also { it[0] = 0x04 },
      created = 1700000000L,
    )

  @Test
  fun `binding metadata round-trips through CBOR`() {
    val original =
      baseCredential()
        .copy(
          createdByCallerType = CallerType.NATIVE_APP,
          createdByPackage = "com.example.app",
          createdByCertificateDigest = "abc123digest",
          verifiedOrigin = "android:apk-key-hash:xyz",
        )

    val cbor = original.toCbor()
    val restored = StoredCredential.fromCbor(cbor)

    assertEquals(CallerType.NATIVE_APP, restored.createdByCallerType)
    assertEquals("com.example.app", restored.createdByPackage)
    assertEquals("abc123digest", restored.createdByCertificateDigest)
    assertEquals("android:apk-key-hash:xyz", restored.verifiedOrigin)
  }

  @Test
  fun `null binding metadata round-trips through CBOR`() {
    val original = baseCredential()
    val cbor = original.toCbor()
    val restored = StoredCredential.fromCbor(cbor)

    assertNull(restored.createdByCallerType)
    assertNull(restored.createdByPackage)
    assertNull(restored.createdByCertificateDigest)
    assertNull(restored.verifiedOrigin)
  }

  @Test
  fun `browser caller type round-trips`() {
    val original =
      baseCredential()
        .copy(
          createdByCallerType = CallerType.PRIVILEGED_BROWSER,
          createdByPackage = "com.android.chrome",
          createdByCertificateDigest = "browserdigest",
          verifiedOrigin = "https://example.com",
        )

    val cbor = original.toCbor()
    val restored = StoredCredential.fromCbor(cbor)

    assertEquals(CallerType.PRIVILEGED_BROWSER, restored.createdByCallerType)
    assertEquals("com.android.chrome", restored.createdByPackage)
    assertEquals("https://example.com", restored.verifiedOrigin)
  }

  @Test
  fun `toPasskeyCredential preserves binding metadata`() {
    val stored =
      baseCredential()
        .copy(
          createdByCallerType = CallerType.NATIVE_APP,
          createdByPackage = "com.example",
          createdByCertificateDigest = "digest",
          verifiedOrigin = "android:apk-key-hash:abc",
        )

    val passkey = stored.toPasskeyCredential()

    assertEquals(CallerType.NATIVE_APP, passkey.createdByCallerType)
    assertEquals("com.example", passkey.createdByPackage)
    assertEquals("digest", passkey.createdByCertificateDigest)
    assertEquals("android:apk-key-hash:abc", passkey.verifiedOrigin)
  }

  @Test
  fun `fromPasskeyCredential preserves binding metadata`() {
    val privateKey = ByteArray(32)
    val passkey =
      app.passwordstore.passkeys.model.PasskeyCredential(
        credentialId = ByteArray(32),
        publicKey = ByteArray(65).also { it[0] = 0x04 },
        rpId = "example.com",
        user = FidoUser(id = ByteArray(4), name = "user", displayName = "User"),
        createdAt = kotlin.time.Instant.fromEpochSeconds(1700000000L),
        createdByCallerType = CallerType.PRIVILEGED_BROWSER,
        createdByPackage = "com.brave.browser",
        createdByCertificateDigest = "bravedigest",
        verifiedOrigin = "https://example.com",
      )

    val stored = StoredCredential.fromPasskeyCredential(passkey, privateKey)

    assertEquals(CallerType.PRIVILEGED_BROWSER, stored.createdByCallerType)
    assertEquals("com.brave.browser", stored.createdByPackage)
    assertEquals("bravedigest", stored.createdByCertificateDigest)
    assertEquals("https://example.com", stored.verifiedOrigin)
  }

  @Test
  fun `fromPasskeyCredential owns arrays it wipes`() {
    val credentialId = ByteArray(32) { (it + 1).toByte() }
    val publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() }
    val userId = ByteArray(16) { (it + 2).toByte() }
    val privateKey = ByteArray(32) { (it + 3).toByte() }
    val passkey =
      PasskeyCredential(
        credentialId = credentialId,
        publicKey = publicKey,
        rpId = "example.com",
        user = FidoUser(id = userId, name = "user", displayName = "User"),
        createdAt = kotlin.time.Instant.fromEpochSeconds(1700000000L),
      )
    val expectedCredentialId = credentialId.copyOf()
    val expectedPublicKey = publicKey.copyOf()
    val expectedUserId = userId.copyOf()
    val expectedPrivateKey = privateKey.copyOf()

    StoredCredential.fromPasskeyCredential(passkey, privateKey).close()

    assertArrayEquals(expectedCredentialId, credentialId)
    assertArrayEquals(expectedPublicKey, publicKey)
    assertArrayEquals(expectedUserId, userId)
    assertArrayEquals(expectedPrivateKey, privateKey)
  }

  @Test
  fun `old credential without binding fields can be parsed`() {
    val original = baseCredential()
    val cbor = original.toCbor()
    val restored = StoredCredential.fromCbor(cbor)

    assertNull(restored.createdByCallerType)
    assertNull(restored.createdByPackage)
    assertNull(restored.createdByCertificateDigest)
    assertNull(restored.verifiedOrigin)
    assertEquals("example.com", restored.rp.id)
    assertArrayEquals(original.id, restored.id)
  }
}
