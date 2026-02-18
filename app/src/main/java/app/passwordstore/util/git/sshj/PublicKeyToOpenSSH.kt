/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * with the help of GPT-5 mini
 */
package app.passwordstore.util.git.sshj

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64

/**
 * Convert a java.security.PublicKey to an OpenSSH authorized_keys line. Supports RSA, ECDSA
 * (nistp256/384/521) and Ed25519 (attempts to extract raw key from X.509).
 */
fun publicKeyToOpenSsh(pub: PublicKey): String {
  val (keyType, keyBlob) =
    when {
      pub is RSAPublicKey -> rsaBlob(pub)
      pub is ECPublicKey -> ecdsaBlob(pub)
      pub.algorithm.equals("Ed25519", ignoreCase = true) ||
        pub.algorithm.equals("EdEC", ignoreCase = true) -> ed25519Blob(pub)
      else -> throw IllegalArgumentException("Unsupported key type: ${pub.algorithm}")
    }

  val b64 = Base64.getEncoder().encodeToString(keyBlob)
  return "$keyType $b64"
}

/* -------------------- helpers -------------------- */

private fun rsaBlob(pub: RSAPublicKey): Pair<String, ByteArray> {
  val keyType = "ssh-rsa"
  val out = ByteArrayOutputStream()
  writeString(out, keyType)
  writeMpint(out, pub.publicExponent)
  writeMpint(out, pub.modulus)
  return keyType to out.toByteArray()
}

private fun ecdsaBlob(pub: ECPublicKey): Pair<String, ByteArray> {
  // map key size to curve name
  val fieldSizeBits = pub.params.curve.field.fieldSize
  val curveName =
    when (fieldSizeBits) {
      256 -> "nistp256"
      384 -> "nistp384"
      521 -> "nistp521"
      else -> throw IllegalArgumentException("Unsupported EC curve size: $fieldSizeBits")
    }
  val keyType = "ecdsa-sha2-$curveName"

  // uncompressed point: 0x04 || X || Y padded to coordinate length
  val coordSize = (fieldSizeBits + 7) / 8
  val x = unsignedCoordinate(pub.w.affineX, coordSize)
  val y = unsignedCoordinate(pub.w.affineY, coordSize)
  val q = ByteArray(1 + x.size + y.size)
  q[0] = 0x04
  System.arraycopy(x, 0, q, 1, x.size)
  System.arraycopy(y, 0, q, 1 + x.size, y.size)

  val out = ByteArrayOutputStream()
  writeString(out, keyType)
  writeString(out, curveName)
  writeString(out, q)
  return keyType to out.toByteArray()
}

private fun ed25519Blob(pub: PublicKey): Pair<String, ByteArray> {
  val keyType = "ssh-ed25519"
  // try to extract raw 32-byte key from X.509 encoding (SubjectPublicKeyInfo BIT STRING)
  val raw =
    extractRawKeyFromX509(pub.encoded)
      ?: throw IllegalArgumentException("Cannot extract Ed25519 public key bytes from encoded key")
  val out = ByteArrayOutputStream()
  writeString(out, keyType)
  writeString(out, raw)
  return keyType to out.toByteArray()
}

/* -------------------- small binary writers (SSH style) -------------------- */

private fun writeUint32(out: ByteArrayOutputStream, v: Int) {
  out.write(
    byteArrayOf(
      ((v shr 24) and 0xff).toByte(),
      ((v shr 16) and 0xff).toByte(),
      ((v shr 8) and 0xff).toByte(),
      (v and 0xff).toByte(),
    )
  )
}

private fun writeString(out: ByteArrayOutputStream, s: String) {
  val bytes = s.toByteArray(Charsets.US_ASCII)
  writeUint32(out, bytes.size)
  out.write(bytes)
}

private fun writeString(out: ByteArrayOutputStream, bytes: ByteArray) {
  writeUint32(out, bytes.size)
  out.write(bytes)
}

private fun writeMpint(out: ByteArrayOutputStream, b: BigInteger) {
  if (b.signum() < 0) throw IllegalArgumentException("mpint must be non-negative")
  var mag = b.toByteArray()
  // BigInteger.toByteArray() may include a leading zero to indicate positive sign;
  // strip that so we produce the minimal unsigned representation
  if (mag.size > 1 && mag[0] == 0.toByte()) {
    mag = mag.copyOfRange(1, mag.size)
  }
  writeString(out, mag)
}

/* -------------------- utilities -------------------- */

private fun unsignedCoordinate(bi: BigInteger, size: Int): ByteArray {
  val raw = bi.toByteArray()
  // strip leading zero if present from sign, then left-pad to `size`
  val mag = if (raw.size > 1 && raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
  if (mag.size == size) return mag
  if (mag.size > size) {
    // unexpected, but trim leading bytes
    return mag.copyOfRange(mag.size - size, mag.size)
  }
  // pad with leading zeros
  val out = ByteArray(size)
  System.arraycopy(mag, 0, out, size - mag.size, mag.size)
  return out
}

/**
 * Minimal attempt to extract the public key BIT STRING payload from a DER-encoded X.509
 * SubjectPublicKeyInfo. We look for the first BIT STRING (tag 0x03) in the top-level sequence and
 * return its contents minus the initial "unused bits" octet.
 *
 * Not a full ASN.1 parser but sufficient for typical X.509 encodings produced by the JCA.
 */
private fun extractRawKeyFromX509(der: ByteArray): ByteArray? {
  var i = 0
  fun readByte(): Int {
    if (i >= der.size) throw IndexOutOfBoundsException()
    return der[i++].toInt() and 0xff
  }
  fun readLength(): Int {
    val b = readByte()
    return if (b and 0x80 == 0) {
      b
    } else {
      val n = b and 0x7f
      var v = 0
      repeat(n) { v = (v shl 8) or readByte() }
      v
    }
  }

  try {
    // Expect SEQUENCE (0x30)
    val tag = readByte()
    if (tag != 0x30) return null
    val seqLen = readLength()
    val seqEnd = i + seqLen

    while (i < seqEnd) {
      val t = der[i].toInt() and 0xff
      if (t == 0x03) {
        // BIT STRING
        i++
        val len = run {
          val saved = i
          val l = readLength()
          l
        }
        val unusedBits = readByte() // usually 0
        val keyBytes = der.copyOfRange(i, i + len - 1)
        return keyBytes
      } else {
        // skip this element (tag + length + value)
        i++
        val len = readLength()
        i += len
      }
    }
  } catch (_: Exception) {
    return null
  }
  return null
}
