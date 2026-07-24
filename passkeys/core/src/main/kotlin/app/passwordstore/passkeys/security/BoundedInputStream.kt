/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.security

import java.io.FilterInputStream
import java.io.InputStream

public class BoundedInputStream(
  delegate: InputStream,
  private val maxBytes: Long,
) : FilterInputStream(delegate) {

  private var bytesRead: Long = 0L

  public val totalBytesRead: Long
    get() = bytesRead

  override fun read(): Int {
    if (bytesRead >= maxBytes) {
      val probe = `in`.read()
      if (probe == -1) return -1
      throw BoundedInputLimitExceededException(maxBytes)
    }
    val result = `in`.read()
    if (result != -1) {
      bytesRead++
    }
    return result
  }

  override fun read(b: ByteArray, off: Int, len: Int): Int {
    if (bytesRead >= maxBytes) {
      val probe = `in`.read()
      if (probe == -1) return -1
      throw BoundedInputLimitExceededException(maxBytes)
    }
    val remaining = maxBytes - bytesRead
    val clampedLen = minOf(len.toLong(), remaining).toInt()
    val result = `in`.read(b, off, clampedLen)
    if (result > 0) {
      bytesRead += result
    }
    return result
  }

  override fun skip(n: Long): Long {
    val remaining = maxBytes - bytesRead
    val clampedSkip = minOf(n, remaining)
    val skipped = `in`.skip(clampedSkip)
    bytesRead += skipped
    return skipped
  }

  override fun available(): Int {
    val remaining = (maxBytes - bytesRead).toInt()
    return minOf(`in`.available(), remaining)
  }

  override fun markSupported(): Boolean = false

  public fun hasReachedLimit(): Boolean = bytesRead >= maxBytes

  public fun readBoundedBytes(size: Int): ByteArray {
    val result = ByteArray(size)
    var offset = 0
    val buf = ByteArray(minOf(8192, size))
    while (offset < size) {
      val n = read(buf, 0, minOf(buf.size, size - offset))
      if (n == -1) break
      System.arraycopy(buf, 0, result, offset, n)
      offset += n
    }
    return if (offset == size) result else result.copyOf(offset)
  }
}

public class BoundedInputLimitExceededException(public val maxBytes: Long) :
  Exception("Read exceeded maximum of $maxBytes bytes")
