/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.security

import app.passwordstore.passkeys.model.Extensions
import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.RelyingParty
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import app.passwordstore.passkeys.model.StoredCredential
import app.passwordstore.passkeys.model.User
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock

class SensitiveZeroizationTest {

  private fun isZeroed(bytes: ByteArray): Boolean = bytes.all { it == 0.toByte() }

  @Test
  fun `SensitiveBytes borrow provides access without transfer`() {
    val backing = byteArrayOf(1, 2, 3, 4)
    val sensitive = SensitiveBytes(backing)

    val result = sensitive.borrow { it[0] }
    assertEquals(1.toByte(), result)
    assertFalse(sensitive.isReleased())

    sensitive.close()
    assertTrue(sensitive.isReleased())
    assertTrue(isZeroed(backing))
  }

  @Test
  fun `SensitiveBytes move transfers ownership and invalidates previous`() {
    val data = byteArrayOf(10, 20, 30)
    val original = SensitiveBytes(data.copyOf())

    val moved = original.move()
    assertTrue(original.isReleased())

    val borrowed = moved.borrow { it.copyOf() }
    assertContentEquals(data, borrowed)

    moved.close()
    assertTrue(moved.isReleased())
  }

  @Test
  fun `SensitiveBytes close wipes backing array`() {
    val backing = byteArrayOf(1, 2, 3, 4, 5)
    val sensitive = SensitiveBytes(backing)

    sensitive.close()
    assertTrue(isZeroed(backing))
    assertTrue(sensitive.isReleased())
  }

  @Test
  fun `SensitiveBytes access after close throws`() {
    val sensitive = SensitiveBytes(byteArrayOf(1, 2, 3))
    sensitive.close()

    assertFailsWith<IllegalStateException> { sensitive.bytes() }
    assertFailsWith<IllegalStateException> { sensitive.borrow {} }
    assertFailsWith<IllegalStateException> { sensitive.move() }
  }

  @Test
  fun `SensitiveBytes toString does not reveal content`() {
    val sensitive = SensitiveBytes(byteArrayOf(1, 2, 3))
    val str = sensitive.toString()
    assertFalse(str.contains("1"))
    assertFalse(str.contains("2"))
    assertFalse(str.contains("3"))
    assertTrue(str.contains("REDACTED"))
    sensitive.close()
  }

  @Test
  fun `SensitiveChars borrow and close wipe chars`() {
    val chars = charArrayOf('s', 'e', 'c', 'r', 'e', 't')
    val sensitive = SensitiveChars.wrap(chars)

    val result = sensitive.borrow { it[0] }
    assertEquals('s', result)

    sensitive.close()
    assertTrue(sensitive.isReleased())
    assertTrue(chars.all { it == '\u0000' })
  }

  @Test
  fun `SensitiveChars toString does not reveal content`() {
    val sensitive = SensitiveChars.wrap(charArrayOf('p', 'a', 's', 's'))
    val str = sensitive.toString()
    assertTrue(str.contains("REDACTED"))
    assertFalse(str.contains("pass"))
    sensitive.close()
  }

  @Test
  fun `useSensitiveChars wipes on normal exit`() {
    val chars = charArrayOf('t', 'e', 's', 't')
    val result = chars.useSensitiveChars { it[0] }
    assertEquals('t', result)
    assertTrue(chars.all { it == '\u0000' })
  }

  @Test
  fun `useSensitiveChars wipes on exception`() {
    val chars = charArrayOf('t', 'e', 's', 't')
    assertFailsWith<RuntimeException> {
      chars.useSensitiveChars { throw RuntimeException("fail") }
    }
    assertTrue(chars.all { it == '\u0000' })
  }

  @Test
  fun `useSensitiveCharsOrNull handles null`() {
    val nullChars: CharArray? = null
    val result = nullChars.useSensitiveCharsOrNull { it[0] }
    assertEquals(null, result)
  }

  @Test
  fun `useSensitiveCharsOrNull wipes on normal exit`() {
    val chars = charArrayOf('a', 'b')
    val result = chars.useSensitiveCharsOrNull { it[0] }
    assertEquals('a', result)
    assertTrue(chars.all { it == '\u0000' })
  }

  @Test
  fun `SensitivePasskeyCredential close wipes private key`() {
    val keyData = ByteArray(32) { it.toByte() }
    val credential =
      SensitivePasskeyCredential(
        credentialId = ByteArray(32),
        publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
        rpId = "example.com",
        user = FidoUser(ByteArray(16), "user", "User"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
        backupEligible = true,
        backupState = false,
        fileLastModified = 0L,
        privateKey = SensitiveBytes(keyData),
      )

    credential.close()
    assertTrue(isZeroed(keyData))
  }

  @Test
  fun `SensitivePasskeyCredential usePrivateKey after close throws`() {
    val credential =
      SensitivePasskeyCredential(
        credentialId = ByteArray(32),
        publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
        rpId = "example.com",
        user = FidoUser(ByteArray(16), "user", "User"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
        backupEligible = true,
        backupState = false,
        fileLastModified = 0L,
        privateKey = SensitiveBytes(ByteArray(32)),
      )

    credential.close()
    assertFailsWith<IllegalStateException> {
      credential.usePrivateKey {}
    }
  }

  @Test
  fun `SensitivePasskeyCredential toPublicCredential does not expose private key`() {
    val keyData = ByteArray(32) { it.toByte() }
    val credential =
      SensitivePasskeyCredential(
        credentialId = ByteArray(32),
        publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
        rpId = "example.com",
        user = FidoUser(ByteArray(16), "user", "User"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
        backupEligible = true,
        backupState = false,
        fileLastModified = 0L,
        privateKey = SensitiveBytes(keyData),
      )

    val publicCred = credential.toPublicCredential()
    assertTrue(publicCred.toString().contains("redacted", ignoreCase = true))
    credential.close()
    assertTrue(isZeroed(keyData))
  }

  @Test
  fun `SensitivePasskeyCredential toString does not reveal private key`() {
    val credential =
      SensitivePasskeyCredential(
        credentialId = ByteArray(32),
        publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
        rpId = "example.com",
        user = FidoUser(ByteArray(16), "user", "User"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
        backupEligible = true,
        backupState = false,
        fileLastModified = 0L,
        privateKey = SensitiveBytes(ByteArray(32) { 0xFF.toByte() }),
      )

    val str = credential.toString()
    assertTrue(str.contains("REDACTED"))
    credential.close()
  }

  @Test
  fun `StoredCredential toString does not reveal private key`() {
    val stored =
      StoredCredential(
        id = ByteArray(32),
        rp = RelyingParty("example.com"),
        user = User(ByteArray(16), "user", "User"),
        signCount = 0u,
        alg = -7,
        privateKey = ByteArray(32) { 0xFF.toByte() },
        created = 0L,
      )

    val str = stored.toString()
    assertTrue(str.contains("REDACTED"))
  }

  @Test
  fun `BoundedSensitiveOutputStream transferOwnership avoids copy`() {
    val stream = BoundedSensitiveOutputStream(1024)
    val data = byteArrayOf(1, 2, 3, 4, 5)
    stream.write(data)

    val owned = stream.transferOwnership()
    assertFalse(owned.isReleased())

    owned.borrow { buf ->
      for (i in data.indices) {
        assertEquals(data[i], buf[i])
      }
    }

    owned.close()
    assertTrue(owned.isReleased())
  }

  @Test
  fun `BoundedSensitiveOutputStream close wipes buffer`() {
    val stream = BoundedSensitiveOutputStream(1024)
    stream.write(byteArrayOf(1, 2, 3))
    stream.close()

    assertFailsWith<IllegalStateException> { stream.takeBytes() }
    assertFailsWith<IllegalStateException> { stream.transferOwnership() }
  }

  @Test
  fun `StoredCredential fromCbor roundtrip preserves data`() {
    val original =
      StoredCredential(
        id = ByteArray(32) { it.toByte() },
        rp = RelyingParty("example.com", "Example"),
        user = User(ByteArray(16) { it.toByte() }, "user", "User"),
        signCount = 42u,
        alg = -7,
        privateKey = ByteArray(32) { (it + 1).toByte() },
        publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
        created = 1700000000L,
        discoverable = true,
        backupEligible = true,
        backupState = false,
      )

    val cbor = original.toCbor()
    val decoded = StoredCredential.fromCbor(cbor)

    assertContentEquals(original.id, decoded.id)
    assertContentEquals(original.privateKey, decoded.privateKey)
    assertEquals(original.rp.id, decoded.rp.id)
    assertEquals(original.signCount, decoded.signCount)
    assertEquals(original.created, decoded.created)

    cbor.fill(0)
  }

  @Test
  fun `StoredCredential wipe zeros private key and other sensitive fields`() {
    val id = ByteArray(32) { (it + 1).toByte() }
    val privateKey = ByteArray(32) { (it + 10).toByte() }
    val publicKey = ByteArray(65) { (it + 20).toByte() }
    val userId = ByteArray(16) { (it + 30).toByte() }
    val credRandom = ByteArray(8) { (it + 40).toByte() }
    val stored =
      StoredCredential(
        id = id,
        rp = RelyingParty("example.com"),
        user = User(userId, "user", "User"),
        signCount = 0u,
        alg = -7,
        privateKey = privateKey,
        publicKey = publicKey,
        created = 0L,
        extensions = Extensions(credRandom = credRandom),
      )

    stored.wipe()

    assertTrue(isZeroed(privateKey))
    assertTrue(isZeroed(publicKey!!))
    assertTrue(isZeroed(id))
    assertTrue(isZeroed(userId))
    assertTrue(isZeroed(credRandom))
  }

  @Test
  fun `StoredCredential close wipes sensitive fields`() {
    val privateKey = ByteArray(32) { 0xAA.toByte() }
    val stored =
      StoredCredential(
        id = ByteArray(32),
        rp = RelyingParty("example.com"),
        user = User(ByteArray(16), "user", "User"),
        signCount = 0u,
        alg = -7,
        privateKey = privateKey,
        created = 0L,
      )

    stored.close()
    assertTrue(isZeroed(privateKey))
  }

  @Test
  fun `fromStoredCredential wipes source StoredCredential`() {
    val privateKey = ByteArray(32) { (it + 1).toByte() }
    val stored =
      StoredCredential(
        id = ByteArray(32) { (it + 10).toByte() },
        rp = RelyingParty("example.com"),
        user = User(ByteArray(16) { (it + 20).toByte() }, "user", "User"),
        signCount = 0u,
        alg = -7,
        privateKey = privateKey,
        publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
        created = 0L,
      )

    val sensitive = SensitivePasskeyCredential.fromStoredCredential(stored)
    assertTrue(isZeroed(privateKey))

    val borrowedKey = sensitive.usePrivateKey { it.copyOf() }
    assertContentEquals(ByteArray(32) { (it + 1).toByte() }, borrowedKey)

    sensitive.close()
  }
}
