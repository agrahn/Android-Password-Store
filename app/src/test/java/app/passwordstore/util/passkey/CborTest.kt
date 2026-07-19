/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.passkey

import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CborTest {
  @Test
  fun testNonAsciiTextRoundTrip() {
    val c = Cbor()
    val s = "Salut, René 😊 !"
    val enc = c.encode(s)
    val dec = c.decode(enc) as String?
    assertEquals(s, dec)
  }

  @Test
  fun testMapOrdering() {
    val c = Cbor()
    // Two maps with the same entries but different insertion order
    val m1: Map<String, Long> = linkedMapOf("b" to 1L, "aa" to 2L)
    val m2: Map<String, Long> = linkedMapOf("aa" to 2L, "b" to 1L)

    val e1 = c.encode(m1)
    val e2 = c.encode(m2)

    // Encoded bytes must be identical if map encoding is lexicographical
    assertTrue(e1.contentEquals(e2))

    // Decoding should return the expected key/value pairs
    val d = c.decode(e1) as Map<*, *>
    assertEquals(2, d.size)
    assertEquals(1L, d["b"])
    assertEquals(2L, d["aa"])
  }

  @Test
  fun testNullRoundTrip() {
    val c = Cbor()
    val e = c.encode(null)
    val d = c.decode(e)
    assertNull(d)
  }

  @Test
  fun test64BitInteger() {
    val c = Cbor()
    val big: Long = 4_294_967_296L // 2^32
    val e = c.encode(big)
    val d = c.decode(e)
    assertTrue(d is Long)
    assertEquals(big, d as Long)
  }

  @Test
  fun testByteArray() {
    val c = Cbor()
    val credential = ByteArray(32)
    SecureRandom().nextBytes(credential)
    val e = c.encode(credential)
    val d = c.decode(e)
    assertTrue(d is ByteArray)
    assertTrue(credential.contentEquals(d as ByteArray))
  }
}
