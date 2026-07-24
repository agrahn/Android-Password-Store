/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.security

import java.io.ByteArrayInputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BoundedInputStreamTest {

  @Test
  fun `reads exactly maxBytes from stream`() {
    val data = ByteArray(100) { it.toByte() }
    val bounded = BoundedInputStream(ByteArrayInputStream(data), 50)
    val result = ByteArray(50)
    var offset = 0
    while (offset < 50) {
      val n = bounded.read(result, offset, 50 - offset)
      if (n == -1) break
      offset += n
    }
    assertEquals(50, offset)
    assertArrayEquals(data.copyOfRange(0, 50), result)
  }

  @Test
  fun `reads at limit boundary exactly`() {
    val data = ByteArray(256 * 1024) { (it % 256).toByte() }
    val bounded = BoundedInputStream(ByteArrayInputStream(data), data.size.toLong())
    val result = bounded.readBytes()
    assertEquals(data.size, result.size)
    assertArrayEquals(data, result)
  }

  @Test
  fun `single byte read at limit returns negative one`() {
    val data = ByteArray(10) { it.toByte() }
    val bounded = BoundedInputStream(ByteArrayInputStream(data), 10)
    for (i in 0 until 10) {
      val b = bounded.read()
      assertEquals(i.toByte(), b.toByte())
    }
    assertEquals(-1, bounded.read())
  }

  @Test
  fun `bulk read does not exceed limit`() {
    val data = ByteArray(100) { it.toByte() }
    val bounded = BoundedInputStream(ByteArrayInputStream(data), 10)
    val buf = ByteArray(50)
    val n = bounded.read(buf, 0, 50)
    assertEquals(10, n)
  }

  @Test
  fun `totalBytesRead tracks correctly`() {
    val data = ByteArray(100) { it.toByte() }
    val bounded = BoundedInputStream(ByteArrayInputStream(data), 50)
    bounded.read()
    assertEquals(1L, bounded.totalBytesRead)
    bounded.read(ByteArray(10), 0, 10)
    assertEquals(11L, bounded.totalBytesRead)
  }

  @Test
  fun `available is clamped to remaining`() {
    val data = ByteArray(100)
    val bounded = BoundedInputStream(ByteArrayInputStream(data), 10)
    assertTrue(bounded.available() <= 10)
  }

  @Test
  fun `empty stream reads nothing`() {
    val bounded = BoundedInputStream(ByteArrayInputStream(ByteArray(0)), 100)
    assertEquals(-1, bounded.read())
    assertEquals(0L, bounded.totalBytesRead)
  }
}
