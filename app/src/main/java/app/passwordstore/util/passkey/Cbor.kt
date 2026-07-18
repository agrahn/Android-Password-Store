/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.passkey

/*
 * class for CBOR serialisation and de-serialisation;
 * code suggested by Gemini
 */
class Cbor {
  data class Item(val item: Any, val len: Int)

  data class Arg(val arg: Long, val len: Int)

  val TYPE_UNSIGNED_INT = 0x00
  val TYPE_NEGATIVE_INT = 0x01
  val TYPE_BYTE_STRING = 0x02
  val TYPE_TEXT_STRING = 0x03
  val TYPE_ARRAY = 0x04
  val TYPE_MAP = 0x05
  val TYPE_TAG = 0x06
  val TYPE_FLOAT = 0x07

  fun decode(data: ByteArray): Any {
    val ret = parseItem(data, 0)
    return ret.item
  }

  fun encode(data: Any): ByteArray {
    if (data is UInt) {
      val value = data.toLong()
      return createArg(TYPE_UNSIGNED_INT, value)
    }
    if (data is Boolean) {
      val simpleValue = if (data) 21L else 20L
      return createArg(TYPE_FLOAT, simpleValue)
    }
    if (data is Number) {
      if (data is Double) {
        throw IllegalArgumentException("Don't support doubles yet")
      } else {
        val value = data.toLong()
        if (value >= 0) {
          return createArg(TYPE_UNSIGNED_INT, value)
        } else {
          return createArg(TYPE_NEGATIVE_INT, -1 - value)
        }
      }
    }
    if (data is ByteArray) {
      return createArg(TYPE_BYTE_STRING, data.size.toLong()) + data
    }
    if (data is String) {
      return createArg(TYPE_TEXT_STRING, data.length.toLong()) + data.encodeToByteArray()
    }
    if (data is List<*>) {
      var ret = createArg(TYPE_ARRAY, data.size.toLong())
      for (i in data) {
        ret += encode(i ?: throw NullPointerException())
      }
      return ret
    }
    if (data is Map<*, *>) {
      var ret = createArg(TYPE_MAP, data.size.toLong())
      var byteMap: MutableMap<ByteArray, ByteArray> = mutableMapOf()
      for (i in data) {
        byteMap.put(
          encode(i.key ?: throw NullPointerException()),
          encode(i.value ?: throw NullPointerException()),
        )
      }

      var keysList = ArrayList<ByteArray>(byteMap.keys)
      keysList.sortedWith(
        Comparator<ByteArray> { a, b ->
          var aBytes = byteMap.get(a) ?: throw NullPointerException()
          var bBytes = byteMap.get(b) ?: throw NullPointerException()
          when {
            a.size > b.size -> 1
            a.size < b.size -> -1
            aBytes.size > bBytes.size -> 1
            aBytes.size < bBytes.size -> -1
            else -> 0
          }
        }
      )

      for (key in keysList) {
        ret += key
        ret += byteMap.get(key) ?: throw NullPointerException()
      }
      return ret
    }
    throw IllegalArgumentException("Bad type: ${data::class.java.simpleName}")
  }

  private fun getType(data: ByteArray, offset: Int): Int {
    val d = data[offset].toInt()
    return (d and 0xFF) shr 5
  }

  private fun getArg(data: ByteArray, offset: Int): Arg {
    val arg = data[offset].toLong() and 0x1F
    if (arg < 24) {
      return Arg(arg, 1)
    }
    if (arg == 24L) {
      return Arg(data[offset + 1].toLong() and 0xFF, 2)
    }
    if (arg == 25L) {
      var ret = (data[offset + 1].toLong() and 0xFF) shl 8
      ret = ret or (data[offset + 2].toLong() and 0xFF)
      return Arg(ret, 3)
    }
    if (arg == 26L) {
      var ret = (data[offset + 1].toLong() and 0xFF) shl 24
      ret = ret or ((data[offset + 2].toLong() and 0xFF) shl 16)
      ret = ret or ((data[offset + 3].toLong() and 0xFF) shl 8)
      ret = ret or (data[offset + 4].toLong() and 0xFF)
      return Arg(ret, 5)
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
        val ret = data.sliceArray(offset + arg.len until offset + arg.len + arg.arg.toInt())
        return Item(ret, arg.len + arg.arg.toInt())
      }
      TYPE_TEXT_STRING -> {
        val ret = data.sliceArray(offset + arg.len until offset + arg.len + arg.arg.toInt())
        return Item(ret.toString(Charsets.UTF_8), arg.len + arg.arg.toInt())
      }
      TYPE_ARRAY -> {
        val ret = mutableListOf<Any>()
        var consumed = arg.len
        for (i in 0 until arg.arg.toInt()) {
          val item = parseItem(data, offset + consumed)
          ret.add(item.item)
          consumed += item.len
        }
        return Item(ret.toList(), consumed)
      }
      TYPE_MAP -> {
        val ret = mutableMapOf<Any, Any>()
        var consumed = arg.len
        for (i in 0 until arg.arg.toInt()) {
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
          22L -> Item(Unit, arg.len) // map CBOR null to Unit, avoids passing pure raw null
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

  private fun createArg(type: Int, arg: Long): ByteArray {
    val t = type shl 5
    val a = arg.toInt()
    if (arg < 24) {
      return byteArrayOf(((t or a) and 0xFF).toByte())
    }
    if (arg <= 0xFF) {
      return byteArrayOf(((t or 24) and 0xFF).toByte(), (a and 0xFF).toByte())
    }
    if (arg <= 0xFFFF) {
      return byteArrayOf(
        ((t or 25) and 0xFF).toByte(),
        ((a shr 8) and 0xFF).toByte(),
        (a and 0xFF).toByte(),
      )
    }
    if (arg <= 0xFFFFFFFF) {
      return byteArrayOf(
        ((t or 26) and 0xFF).toByte(),
        ((a shr 24) and 0xFF).toByte(),
        ((a shr 16) and 0xFF).toByte(),
        ((a shr 8) and 0xFF).toByte(),
        (a and 0xFF).toByte(),
      )
    }
    throw IllegalArgumentException("bad Arg")
  }
}
