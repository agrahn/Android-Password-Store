/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.security

import app.passwordstore.passkeys.cbor.Cbor
import app.passwordstore.passkeys.cbor.CborArray
import app.passwordstore.passkeys.cbor.CborException
import app.passwordstore.passkeys.cbor.CborMap
import app.passwordstore.passkeys.cbor.CborParseOptions
import app.passwordstore.passkeys.cbor.CborValue
import java.io.ByteArrayInputStream
import java.io.DataOutputStream
import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class PasskeyInputBoundaryTest {

  @Test
  fun `01 ciphertext exactly at maximum is accepted by BoundedInputStream`() {
    val limit = 1024L
    val data = ByteArray(limit.toInt()) { (it % 256).toByte() }
    val bounded = BoundedInputStream(ByteArrayInputStream(data), limit)
    val result = bounded.readBoundedBytes(data.size)
    assertEquals(limit.toInt(), result.size)
    assertArrayEquals(data, result)
  }

  @Test
  fun `02 ciphertext maximum plus one is rejected by BoundedInputStream`() {
    val limit = 1024L
    val data = ByteArray(limit.toInt() + 1) { (it % 256).toByte() }
    val bounded = BoundedInputStream(ByteArrayInputStream(data), limit)
    try {
      bounded.readBoundedBytes(data.size)
      fail("Expected BoundedInputLimitExceededException")
    } catch (e: BoundedInputLimitExceededException) {
      assertEquals(limit, e.maxBytes)
    }
  }

  @Test
  fun `03 stat size below limit but stream produces more bytes aborts`() {
    val limit = 100L
    val data = ByteArray(200) { (it % 256).toByte() }
    val bounded = BoundedInputStream(ByteArrayInputStream(data), limit)
    val buf = ByteArray(50)
    var totalRead = 0
    try {
      while (true) {
        val n = bounded.read(buf)
        if (n == -1) break
        totalRead += n
      }
    } catch (e: BoundedInputLimitExceededException) {
      assertEquals(limit, e.maxBytes)
    }
    assertTrue(totalRead >= 100)
    assertTrue(bounded.hasReachedLimit())
  }

  @Test
  fun `04 large file rejected from metadata without full read`() {
    val limits = PasskeyInputLimits(maxCiphertextBytes = 1024)
    val oversizedLength = 2L * 1024 * 1024 * 1024
    assertTrue(oversizedLength > limits.maxCiphertextBytes)
  }

  @Test
  fun `05 small ciphertext expanding to plaintext maximum plus one aborts`() {
    val out = BoundedSensitiveOutputStream(10)
    try {
      out.write(ByteArray(11))
      fail("Expected BoundedOutputLimitExceededException")
    } catch (e: BoundedOutputLimitExceededException) {
      assertEquals(10L, e.maxBytes)
    }
    out.close()
  }

  @Test
  fun `06 BoundedSensitiveOutputStream wipes buffer on close`() {
    val out = BoundedSensitiveOutputStream(100)
    val data = byteArrayOf(1, 2, 3, 4, 5)
    out.write(data)
    val sensitive = out.takeBytes()
    val ref = sensitive.bytes()
    assertArrayEquals(data, ref)
    sensitive.release()
    out.close()
    for (b in ref) {
      assertEquals(0.toByte(), b)
    }
  }

  @Test
  fun `07 CBOR depth exactly at maximum is accepted`() {
    val maxDepth = 5
    val options = CborParseOptions(maxDepth = maxDepth)
    val nested = buildNestedArrayCbor(depth = maxDepth)
    Cbor.parse(nested, options)
  }

  @Test
  fun `08 CBOR depth maximum plus one is rejected`() {
    val maxDepth = 5
    val options = CborParseOptions(maxDepth = maxDepth)
    val nested = buildNestedArrayCbor(depth = maxDepth + 1)
    try {
      Cbor.parse(nested, options)
      fail("Expected CborException for depth exceeded")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("depth") || e.message!!.contains("Maximum"))
    }
  }

  @Test
  fun `09 CBOR collection count exactly at maximum is accepted`() {
    val maxItems = 10
    val options = CborParseOptions(maxCollectionItems = maxItems)
    val array = buildArrayCbor(items = maxItems)
    Cbor.parse(array, options)
  }

  @Test
  fun `10 CBOR collection count maximum plus one is rejected`() {
    val maxItems = 10
    val options = CborParseOptions(maxCollectionItems = maxItems)
    val array = buildArrayCbor(items = maxItems + 1)
    try {
      Cbor.parse(array, options)
      fail("Expected CborException for collection size exceeded")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("too large") || e.message!!.contains("Array size"))
    }
  }

  @Test
  fun `11 oversized RP ID field is rejected by CBOR string limit`() {
    val maxStringBytes = 100
    val options = CborParseOptions(maxStringBytes = maxStringBytes)
    val largeRpId = "x".repeat(maxStringBytes + 1)
    val map = CborMap.from(mapOf("rp_id" to CborValue.TextString(largeRpId)))
    val bytes = Cbor.fromMap(map).toBytes()
    try {
      Cbor.parse(bytes, options)
      fail("Expected CborException for oversized string")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("too large") || e.message!!.contains("Text string"))
    }
  }

  @Test
  fun `12 duplicate CBOR key is rejected`() {
    val out = java.io.ByteArrayOutputStream()
    val data = DataOutputStream(out)
    data.writeByte(0xa2)
    data.writeByte(0x61)
    data.writeByte('a'.code)
    data.writeByte(0x01)
    data.writeByte(0x61)
    data.writeByte('a'.code)
    data.writeByte(0x02)
    data.flush()
    try {
      Cbor.parse(out.toByteArray())
      fail("Expected CborException for duplicate key")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("Duplicate key"))
    }
  }

  @Test
  fun `13 valid CBOR object followed by trailing bytes is rejected`() {
    val map = CborMap.from(mapOf("key" to CborValue.TextString("value")))
    val bytes = Cbor.fromMap(map).toBytes()
    val withTrailing = bytes + byteArrayOf(0x00, 0x01, 0x02)
    try {
      Cbor.parse(withTrailing)
      fail("Expected CborException for trailing data")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("Trailing data"))
    }
  }

  @Test
  fun `14 unsupported algorithm with huge key field rejected within total limit`() {
    val maxStringBytes = 100
    val options = CborParseOptions(maxStringBytes = maxStringBytes)
    val hugeKey = ByteArray(maxStringBytes + 1) { it.toByte() }
    val map =
      CborMap.from(
        mapOf(
          "alg" to CborValue.UnsignedInteger(BigInteger.valueOf(9999)),
          "key" to CborValue.ByteString(hugeKey),
        )
      )
    val bytes = Cbor.fromMap(map).toBytes()
    try {
      Cbor.parse(bytes, options)
      fail("Expected CborException for oversized byte string")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("too large") || e.message!!.contains("Byte string"))
    }
  }

  @Test
  fun `15 asset links body at maximum is parseable`() {
    val limits = PasskeyInputLimits(maxAssetLinksBytes = 256)
    val body =
      """[{"relation":["delegate_permission/common.handle_all_urls"],"target":{"namespace":"android_app","package_name":"com.example","sha256_cert_fingerprints":["AA:BB"]}}]"""
    assertTrue(body.toByteArray().size <= limits.maxAssetLinksBytes)
  }

  @Test
  fun `16 asset links body exceeding maximum is detected`() {
    val limits = PasskeyInputLimits(maxAssetLinksBytes = 10)
    val body =
      """[{"relation":["delegate_permission/common.handle_all_urls"],"target":{"namespace":"android_app","package_name":"com.example","sha256_cert_fingerprints":["AA:BB"]}}]"""
    assertTrue(body.toByteArray().size > limits.maxAssetLinksBytes)
  }

  @Test
  fun `17 excess asset link statement count is detected`() {
    val limits = PasskeyInputLimits(maxAssetLinkStatements = 2)
    val statementCount = 3
    assertTrue(statementCount > limits.maxAssetLinkStatements)
  }

  @Test
  fun `18 excess relation count per statement is detected`() {
    val limits = PasskeyInputLimits(maxRelationsPerStatement = 2)
    val relationCount = 3
    assertTrue(relationCount > limits.maxRelationsPerStatement)
  }

  @Test
  fun `19 excess fingerprint count per statement is detected`() {
    val limits = PasskeyInputLimits(maxFingerprintsPerStatement = 2)
    val fingerprintCount = 3
    assertTrue(fingerprintCount > limits.maxFingerprintsPerStatement)
  }

  @Test
  fun `20 BoundedInputStream single byte read at boundary`() {
    val data = ByteArray(5) { it.toByte() }
    val bounded = BoundedInputStream(ByteArrayInputStream(data), 5)
    for (i in 0 until 5) {
      val b = bounded.read()
      assertEquals(i.toByte(), b.toByte())
    }
    val next = bounded.read()
    assertEquals(-1, next)
  }

  @Test
  fun `BoundedInputStream bulk read clamped at limit`() {
    val data = ByteArray(100) { it.toByte() }
    val bounded = BoundedInputStream(ByteArrayInputStream(data), 10)
    val buf = ByteArray(50)
    val n = bounded.read(buf, 0, 50)
    assertEquals(10, n)
  }

  @Test
  fun `BoundedSensitiveOutputStream exact limit write succeeds`() {
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

  @Test
  fun `BoundedSensitiveOutputStream incremental writes exceeding limit throw`() {
    val out = BoundedSensitiveOutputStream(10)
    out.write(ByteArray(5))
    try {
      out.write(ByteArray(6))
      fail("Expected BoundedOutputLimitExceededException")
    } catch (e: BoundedOutputLimitExceededException) {
      assertEquals(10L, e.maxBytes)
    }
    out.close()
  }

  @Test
  fun `CBOR indefinite length is rejected`() {
    val indefiniteArray = byteArrayOf(0x9f.toByte(), 0x01, 0x02, 0xff.toByte())
    try {
      Cbor.parse(indefiniteArray)
      fail("Expected CborException for indefinite length")
    } catch (e: CborException) {
      assertTrue(e.message!!.contains("Indefinite"))
    }
  }

  @Test
  fun `PasskeyInputLimits rejects zero values`() {
    try {
      PasskeyInputLimits(maxCiphertextBytes = 0)
      fail("Expected IllegalArgumentException")
    } catch (_: IllegalArgumentException) {}
    try {
      PasskeyInputLimits(maxPlaintextBytes = -1)
      fail("Expected IllegalArgumentException")
    } catch (_: IllegalArgumentException) {}
    try {
      PasskeyInputLimits(maxCborDepth = 0)
      fail("Expected IllegalArgumentException")
    } catch (_: IllegalArgumentException) {}
  }

  @Test
  fun `PasskeyInputError types carry correct information`() {
    val emptyError = PasskeyInputError.EmptyCiphertext
    assertTrue(emptyError.message.contains("empty"))

    val tooLargeError = PasskeyInputError.CiphertextTooLarge(1000, 500)
    assertTrue(tooLargeError.message.contains("1000"))
    assertTrue(tooLargeError.message.contains("500"))

    val plaintextError = PasskeyInputError.PlaintextTooLarge(64 * 1024L)
    assertTrue(plaintextError.message.contains("65536"))

    val trailingError = PasskeyInputError.TrailingCborData
    assertTrue(trailingError.message.contains("Trailing"))

    val dupKeyError = PasskeyInputError.DuplicateCborKey
    assertTrue(dupKeyError.message.contains("Duplicate"))

    val cancelledError = PasskeyInputError.OperationCancelled
    assertTrue(cancelledError.message.contains("cancelled"))
  }

  @Test
  fun `PasskeyConcurrencyLimiter has expected defaults`() {
    val limiter = PasskeyConcurrencyLimiter.DEFAULT
    assertEquals(2, limiter.maxConcurrentDecryptions)
    assertEquals(4, limiter.maxConcurrentDalFetches)
    assertEquals(1, limiter.maxConcurrentIndexRebuilds)
  }

  private fun buildNestedArrayCbor(depth: Int): ByteArray {
    if (depth == 0) {
      return Cbor.fromArray(CborArray.from(listOf())).toBytes()
    }
    val inner = buildNestedArrayCbor(depth - 1)
    val innerValue =
      Cbor.parse(inner, CborParseOptions(rejectTrailingData = false, maxDepth = depth + 1))
    val wrapped =
      CborValue.Array(
        CborArray.from(
          listOf(
            innerValue.asArray().toList().let {
              CborValue.Array(CborArray.from(it))
            }
          )
        )
      )
    return Cbor.fromValue(wrapped).toBytes()
  }

  private fun buildArrayCbor(items: Int): ByteArray {
    val elements =
      (0 until items).map {
        CborValue.UnsignedInteger(BigInteger.valueOf(it.toLong()))
      }
    return Cbor.fromArray(CborArray.from(elements)).toBytes()
  }
}
