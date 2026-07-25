/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.security

import java.io.OutputStream

public class BoundedSensitiveOutputStream(private val maxBytes: Int) :
  OutputStream(), AutoCloseable {

  private var buffer: ByteArray? = ByteArray(maxBytes)
  private var position: Int = 0
  @Volatile private var closed = false

  override fun write(b: Int) {
    check(!closed) { "Stream is closed" }
    val buf = buffer ?: throw IllegalStateException("Buffer has been released")
    if (position >= maxBytes) {
      throw BoundedOutputLimitExceededException(maxBytes.toLong())
    }
    buf[position++] = b.toByte()
  }

  override fun write(b: ByteArray, off: Int, len: Int) {
    check(!closed) { "Stream is closed" }
    val buf = buffer ?: throw IllegalStateException("Buffer has been released")
    if (position + len > maxBytes) {
      throw BoundedOutputLimitExceededException(maxBytes.toLong())
    }
    System.arraycopy(b, off, buf, position, len)
    position += len
  }

  public fun size(): Int = position

  public fun takeBytes(): SensitiveBytes {
    check(!closed) { "Stream is closed" }
    val buf = buffer ?: throw IllegalStateException("Buffer has been released")
    val result = ByteArray(position)
    System.arraycopy(buf, 0, result, 0, position)
    return SensitiveBytes(result)
  }

  public fun transferOwnership(): SensitiveBytes {
    check(!closed) { "Stream is closed" }
    val buf = buffer ?: throw IllegalStateException("Buffer has been released")
    val result = ByteArray(position)
    System.arraycopy(buf, 0, result, 0, position)
    buf.fill(0)
    buffer = null
    closed = true
    return SensitiveBytes(result)
  }

  override fun close() {
    if (!closed) {
      closed = true
      wipeInternalBuffer()
    }
  }

  private fun wipeInternalBuffer() {
    buffer?.fill(0)
    buffer = null
  }
}

public class SensitiveBytes(
  @PublishedApi internal var data: ByteArray?,
  @PublishedApi internal val dataSize: Int = data?.size ?: 0,
) : AutoCloseable {

  @Volatile private var released = false

  public fun bytes(): ByteArray {
    val buf = data ?: throw IllegalStateException("Bytes have been released")
    return if (buf.size == dataSize) buf else buf.copyOfRange(0, dataSize)
  }

  public fun size(): Int = if (data != null) dataSize else 0

  public fun isReleased(): Boolean = released

  public inline fun <T> borrow(block: (ByteArray) -> T): T {
    val buf = data ?: throw IllegalStateException("Bytes have been released")
    val view = if (buf.size == dataSize) buf else buf.copyOfRange(0, dataSize)
    return block(view)
  }

  public fun move(): SensitiveBytes {
    val buf = data ?: throw IllegalStateException("Bytes have been released")
    val size = dataSize
    data = null
    released = true
    return if (buf.size == size) {
      SensitiveBytes(buf, size)
    } else {
      val result = ByteArray(size)
      System.arraycopy(buf, 0, result, 0, size)
      buf.fill(0)
      SensitiveBytes(result, size)
    }
  }

  public fun release() {
    data?.fill(0)
    data = null
    released = true
  }

  override fun close() {
    release()
  }

  override fun toString(): String = "SensitiveBytes(<REDACTED>)"
}

public class BoundedOutputLimitExceededException(public val maxBytes: Long) :
  Exception("Output exceeded maximum of $maxBytes bytes")
