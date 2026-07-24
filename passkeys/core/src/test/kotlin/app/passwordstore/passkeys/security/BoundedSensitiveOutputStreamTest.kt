/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class BoundedSensitiveOutputStreamTest {

  @Test
  fun `writes within limit succeed`() {
    val out = BoundedSensitiveOutputStream(100)
    out.write(ByteArray(50) { it.toByte() })
    assertEquals(50, out.size())
    val sensitive = out.takeBytes()
    assertEquals(50, sensitive.size())
    sensitive.release()
    out.close()
  }

  @Test
  fun `writes at exact limit succeed`() {
    val limit = 64
    val out = BoundedSensitiveOutputStream(limit)
    val data = ByteArray(limit) { (it % 256).toByte() }
    out.write(data)
    assertEquals(limit, out.size())
    val sensitive = out.takeBytes()
    assertArrayEquals(data, sensitive.bytes())
    sensitive.release()
    out.close()
  }

  @Test(expected = BoundedOutputLimitExceededException::class)
  fun `writes exceeding limit throw`() {
    val out = BoundedSensitiveOutputStream(10)
    out.write(ByteArray(11))
  }

  @Test(expected = BoundedOutputLimitExceededException::class)
  fun `incremental writes exceeding limit throw`() {
    val out = BoundedSensitiveOutputStream(10)
    out.write(ByteArray(5))
    out.write(ByteArray(6))
  }

  @Test(expected = BoundedOutputLimitExceededException::class)
  fun `single byte write at limit plus one throws`() {
    val out = BoundedSensitiveOutputStream(1)
    out.write(0x42)
    out.write(0x43)
  }

  @Test
  fun `takeBytes returns correct data`() {
    val out = BoundedSensitiveOutputStream(100)
    val data = byteArrayOf(1, 2, 3, 4, 5)
    out.write(data)
    val sensitive = out.takeBytes()
    assertArrayEquals(data, sensitive.bytes())
    sensitive.release()
    out.close()
  }

  @Test
  fun `close wipes internal buffer`() {
    val out = BoundedSensitiveOutputStream(100)
    out.write(byteArrayOf(1, 2, 3))
    out.close()
    try {
      out.takeBytes()
      throw AssertionError("Expected IllegalStateException after close")
    } catch (_: IllegalStateException) {}
  }

  @Test
  fun `SensitiveBytes release zeros data`() {
    val data = byteArrayOf(1, 2, 3, 4, 5)
    val sensitive = SensitiveBytes(data.copyOf())
    val ref = sensitive.bytes()
    sensitive.release()
    for (b in ref) {
      assertEquals(0.toByte(), b)
    }
  }
}
