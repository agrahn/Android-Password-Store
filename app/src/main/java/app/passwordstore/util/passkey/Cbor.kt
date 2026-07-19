/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.passkey

import app.passwordstore.util.extensions.wipe
import java.nio.ByteBuffer

/*
 * Class for CBOR serialisation and de-serialisation;
 * zeroises temporary arrays and writer backing buffers where possible.
 * Floating point data is not covered as it is not used in passkeys.
 * Code suggested by Gemini and revised by Copilot
 */
class Cbor {
  data class Item(val item: Any?, val len: Int)

  data class Arg(val arg: Long, val len: Int)

  private val TYPE_UNSIGNED_INT = 0x00
  private val TYPE_NEGATIVE_INT = 0x01
  private val TYPE_BYTE_STRING = 0x02
  private val TYPE_TEXT_STRING = 0x03
  private val TYPE_ARRAY = 0x04
  private val TYPE_MAP = 0x05
  private val TYPE_TAG = 0x06
  private val TYPE_FLOAT = 0x07

  // Small dynamic ByteBuffer-backed writer used for encoding
  private class BufferWriter(initialCapacity: Int = 256) {
    private var buf: ByteBuffer = ByteBuffer.allocate(initialCapacity)

    private fun ensureCapacity(additional: Int) {
      if (buf.remaining() >= additional) return
      val needed = buf.position() + additional
      var newCap = buf.capacity() * 2
      if (newCap < needed) newCap = needed
      val newBuf = ByteBuffer.allocate(newCap)
      buf.flip() // limit = position, position = 0
      newBuf.put(buf)
      // wipe old buffer backing before letting it be GC'd
      try {
        val oldBacking = buf.array()
        oldBacking.wipe()
      } catch (_: UnsupportedOperationException) {
        // ignore if no array backing
      }
      buf = newBuf
    }

    private fun writeByte(b: Int) {
      ensureCapacity(1)
      buf.put((b and 0xFF).toByte())
    }

    fun write(bytes: ByteArray) {
      ensureCapacity(bytes.size)
      buf.put(bytes)
    }

    fun writeArg(type: Int, arg: Long) {
      val t = (type shl 5) and 0xFF
      when {
        arg < 24L -> {
          writeByte(t or arg.toInt())
        }
        arg <= 0xFFL -> {
          writeByte(t or 24)
          writeByte((arg and 0xFFL).toInt())
        }
        arg <= 0xFFFFL -> {
          writeByte(t or 25)
          writeByte(((arg shr 8) and 0xFF).toInt())
          writeByte((arg and 0xFF).toInt())
        }
        arg <= 0xFFFFFFFFL -> {
          writeByte(t or 26)
          writeByte(((arg shr 24) and 0xFF).toInt())
          writeByte(((arg shr 16) and 0xFF).toInt())
          writeByte(((arg shr 8) and 0xFF).toInt())
          writeByte((arg and 0xFF).toInt())
        }
        else -> {
          writeByte(t or 27)
          writeByte(((arg shr 56) and 0xFF).toInt())
          writeByte(((arg shr 48) and 0xFF).toInt())
          writeByte(((arg shr 40) and 0xFF).toInt())
          writeByte(((arg shr 32) and 0xFF).toInt())
          writeByte(((arg shr 24) and 0xFF).toInt())
          writeByte(((arg shr 16) and 0xFF).toInt())
          writeByte(((arg shr 8) and 0xFF).toInt())
          writeByte((arg and 0xFF).toInt())
        }
      }
    }

    fun toByteArray(): ByteArray {
      val size = buf.position()
      val out = ByteArray(size)
      buf.flip()
      buf.get(out)
      // Wipe the internal backing array up to 'size' if available
      try {
        val backing = buf.array()
        backing.wipe(0, size)
      } catch (_: UnsupportedOperationException) {
        // ignore if no array backing
      }
      return out
    }
  }

  // Public API
  fun decode(data: ByteArray): Any? {
    val ret = parseItem(data, 0)
    return ret.item
  }

  // Accept nullable values so callers can encode Kotlin null -> CBOR null
  fun encode(data: Any?): ByteArray {
    if (data == null) {
      val w = BufferWriter()
      w.writeArg(TYPE_FLOAT, 22L) // CBOR null
      return w.toByteArray()
    }

    if (data is UInt) {
      val w = BufferWriter()
      w.writeArg(TYPE_UNSIGNED_INT, data.toLong())
      return w.toByteArray()
    }

    if (data is Boolean) {
      val simpleValue = if (data) 21L else 20L
      val w = BufferWriter()
      w.writeArg(TYPE_FLOAT, simpleValue)
      return w.toByteArray()
    }

    if (data is Number) {
      if (data is Double) {
        throw IllegalArgumentException("Don't support doubles yet")
      } else {
        val value = data.toLong()
        val w = BufferWriter()
        if (value >= 0) {
          w.writeArg(TYPE_UNSIGNED_INT, value)
        } else {
          w.writeArg(TYPE_NEGATIVE_INT, -1 - value)
        }
        return w.toByteArray()
      }
    }

    if (data is ByteArray) {
      val w = BufferWriter()
      w.writeArg(TYPE_BYTE_STRING, data.size.toLong())
      w.write(data)
      return w.toByteArray()
    }

    if (data is String) {
      val bytes = data.encodeToByteArray()
      try {
        val w = BufferWriter()
        w.writeArg(TYPE_TEXT_STRING, bytes.size.toLong())
        w.write(bytes)
        return w.toByteArray()
      } finally {
        bytes.wipe()
      }
    }

    if (data is List<*>) {
      val w = BufferWriter()
      w.writeArg(TYPE_ARRAY, data.size.toLong())
      for (i in data) {
        val enc = encode(i)
        try {
          w.write(enc)
        } finally {
          enc.wipe()
        }
      }
      return w.toByteArray()
    }

    if (data is Map<*, *>) {
      val w = BufferWriter()
      w.writeArg(TYPE_MAP, data.size.toLong())

      // Build list of (encodedKeyBytes, encodedValueBytes) pairs to sort canonically
      val entries = ArrayList<Pair<ByteArray, ByteArray>>(data.size)
      for (entry in data) {
        val k = encode(entry.key)
        val v = encode(entry.value)
        entries.add(Pair(k, v))
      }

      // Sort: lexicographical unsigned bytewise ordering of the encoded key bytes.
      // If one is a prefix of the other, the shorter one is considered smaller.
      entries.sortWith(
        Comparator { a, b ->
          val ka = a.first
          val kb = b.first
          val min = kotlin.math.min(ka.size, kb.size)
          for (i in 0 until min) {
            val diff = (ka[i].toInt() and 0xFF) - (kb[i].toInt() and 0xFF)
            if (diff != 0) return@Comparator diff
          }
          ka.size - kb.size
        }
      )

      try {
        for ((k, v) in entries) {
          w.write(k)
          w.write(v)
        }
      } finally {
        for ((k, v) in entries) {
          k.wipe()
          v.wipe()
        }
      }

      return w.toByteArray()
    }

    throw IllegalArgumentException("Bad type: ${data::class.java.simpleName}")
  }

  // Decoding helpers (with bounds checks)
  private fun getType(data: ByteArray, offset: Int): Int {
    if (offset >= data.size)
      throw IllegalArgumentException(
        "Truncated CBOR data (missing initial type byte at offset $offset)"
      )
    val d = data[offset].toInt()
    return (d and 0xFF) shr 5
  }

  private fun getArg(data: ByteArray, offset: Int): Arg {
    if (offset >= data.size)
      throw IllegalArgumentException("Truncated CBOR data (missing arg at offset $offset)")
    val ai = data[offset].toInt() and 0x1F
    if (ai < 24) {
      return Arg(ai.toLong(), 1)
    }
    if (ai == 24) {
      if (offset + 2 > data.size)
        throw IllegalArgumentException(
          "Truncated CBOR data (expected 1 extra byte for arg=24 at offset $offset)"
        )
      return Arg(data[offset + 1].toLong() and 0xFFL, 2)
    }
    if (ai == 25) {
      if (offset + 3 > data.size)
        throw IllegalArgumentException(
          "Truncated CBOR data (expected 2 extra bytes for arg=25 at offset $offset)"
        )
      var ret = (data[offset + 1].toLong() and 0xFFL) shl 8
      ret = ret or (data[offset + 2].toLong() and 0xFFL)
      return Arg(ret, 3)
    }
    if (ai == 26) {
      if (offset + 5 > data.size)
        throw IllegalArgumentException(
          "Truncated CBOR data (expected 4 extra bytes for arg=26 at offset $offset)"
        )
      var ret = (data[offset + 1].toLong() and 0xFFL) shl 24
      ret = ret or ((data[offset + 2].toLong() and 0xFFL) shl 16)
      ret = ret or ((data[offset + 3].toLong() and 0xFFL) shl 8)
      ret = ret or (data[offset + 4].toLong() and 0xFFL)
      return Arg(ret, 5)
    }
    if (ai == 27) {
      if (offset + 9 > data.size)
        throw IllegalArgumentException(
          "Truncated CBOR data (expected 8 extra bytes for arg=27 at offset $offset)"
        )
      var ret = 0L
      for (i in 1..8) {
        ret = (ret shl 8) or (data[offset + i].toLong() and 0xFFL)
      }
      return Arg(ret, 9)
    }
    if (ai == 31) {
      throw IllegalArgumentException("Indefinite length items are not supported")
    }
    throw IllegalArgumentException("Bad arg")
  }

  private fun parseItem(data: ByteArray, offset: Int): Item {
    val itemType = getType(data, offset)
    val arg = getArg(data, offset)

    when (itemType) {
      TYPE_UNSIGNED_INT -> {
        return Item(arg.arg, arg.len)
      }
      TYPE_NEGATIVE_INT -> {
        return Item(-1 - arg.arg, arg.len)
      }
      TYPE_BYTE_STRING -> {
        val start = offset + arg.len
        val length = arg.arg.toInt()
        if (length < 0) throw IllegalArgumentException("Negative length")
        if (start + length > data.size)
          throw IllegalArgumentException(
            "Truncated CBOR byte string (start=$start length=$length, data.size=${data.size})"
          )
        val ret = data.sliceArray(start until start + length)
        return Item(
          ret,
          arg.len + length,
        )
      }
      TYPE_TEXT_STRING -> {
        val start = offset + arg.len
        val length = arg.arg.toInt()
        if (length < 0) throw IllegalArgumentException("Negative length")
        if (start + length > data.size)
          throw IllegalArgumentException(
            "Truncated CBOR text string (start=$start length=$length, data.size=${data.size})"
          )
        val tmp = data.sliceArray(start until start + length)
        val s = tmp.toString(Charsets.UTF_8)
        tmp.wipe()
        return Item(s, arg.len + length)
      }
      TYPE_ARRAY -> {
        val ret = mutableListOf<Any?>()
        var consumed = arg.len
        val cnt = arg.arg.toInt()
        for (i in 0 until cnt) {
          val item = parseItem(data, offset + consumed)
          ret.add(item.item)
          consumed += item.len
        }
        return Item(ret.toList(), consumed)
      }
      TYPE_MAP -> {
        val ret = mutableMapOf<Any?, Any?>()
        var consumed = arg.len
        val cnt = arg.arg.toInt()
        for (i in 0 until cnt) {
          val key = parseItem(data, offset + consumed)
          consumed += key.len
          val value = parseItem(data, offset + consumed)
          consumed += value.len
          ret[key.item] = value.item
        }
        return Item(ret.toMap(), consumed)
      }
      TYPE_FLOAT -> {
        return when (arg.arg) {
          20L -> Item(false, arg.len)
          21L -> Item(true, arg.len)
          22L -> Item(null, arg.len) // map CBOR null to Kotlin null
          else ->
            throw IllegalArgumentException(
              "Unsupported Major Type 7 simple value or float: ${arg.arg}"
            )
        }
      }
      else -> {
        throw IllegalArgumentException("Bad type")
      }
    }
  }
}
