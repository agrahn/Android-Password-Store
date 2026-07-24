/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.cbor

import app.passwordstore.passkeys.security.PasskeyInputLimits
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.math.BigInteger

public data class CborParseOptions(
  val maxDepth: Int = PasskeyInputLimits.DEFAULT.maxCborDepth,
  val maxCollectionItems: Int = PasskeyInputLimits.DEFAULT.maxCborCollectionItems,
  val maxStringBytes: Int = PasskeyInputLimits.DEFAULT.maxBinaryFieldBytes,
  val rejectTrailingData: Boolean = true,
  val rejectDuplicateKeys: Boolean = true,
) {
  public companion object {
    public val DEFAULT: CborParseOptions = CborParseOptions()
  }
}

public class Cbor private constructor(private val data: CborValue) {

  public fun asMap(): CborMap =
    (data as? CborValue.Map)?.value
      ?: throw CborException("Expected map, got ${data::class.simpleName}")

  public fun asArray(): CborArray =
    (data as? CborValue.Array)?.value
      ?: throw CborException("Expected array, got ${data::class.simpleName}")

  public fun asString(): String =
    (data as? CborValue.TextString)?.value
      ?: throw CborException("Expected text string, got ${data::class.simpleName}")

  public fun asBytes(): ByteArray =
    when (data) {
      is CborValue.ByteString -> data.value
      is CborValue.Array -> data.value.toByteArray()
      else -> throw CborException("Expected byte string or array, got ${data::class.simpleName}")
    }

  public fun asInt(): Int =
    when (data) {
      is CborValue.UnsignedInteger -> {
        val value = data.value
        if (value > BigInteger.valueOf(Int.MAX_VALUE.toLong())) {
          throw CborException("Integer value too large for Int: $value")
        }
        value.toInt()
      }
      is CborValue.NegativeInteger -> {
        val value = data.value
        if (value < BigInteger.valueOf(Int.MIN_VALUE.toLong())) {
          throw CborException("Integer value too small for Int: $value")
        }
        value.toInt()
      }
      else -> throw CborException("Expected integer, got ${data::class.simpleName}")
    }

  public fun asLong(): Long =
    when (data) {
      is CborValue.UnsignedInteger -> {
        val value = data.value
        if (value > BigInteger.valueOf(Long.MAX_VALUE)) {
          throw CborException("Integer value too large for Long: $value")
        }
        value.toLong()
      }
      is CborValue.NegativeInteger -> {
        val value = data.value
        if (value < BigInteger.valueOf(Long.MIN_VALUE)) {
          throw CborException("Integer value too small for Long: $value")
        }
        value.toLong()
      }
      else -> throw CborException("Expected integer, got ${data::class.simpleName}")
    }

  public fun asBoolean(): Boolean =
    when (data) {
      is CborValue.True -> true
      is CborValue.False -> false
      else -> throw CborException("Expected boolean, got ${data::class.simpleName}")
    }

  public fun isNull(): Boolean = data is CborValue.Null

  public fun toBytes(): ByteArray = CborWriter.write(data)

  public companion object {
    public fun parse(bytes: ByteArray, options: CborParseOptions = CborParseOptions.DEFAULT): Cbor {
      val result = CborReader.read(bytes, options)
      return Cbor(result.value)
    }

    public fun fromMap(map: CborMap): Cbor = Cbor(CborValue.Map(map))

    public fun fromArray(array: CborArray): Cbor = Cbor(CborValue.Array(array))

    internal fun fromValue(value: CborValue): Cbor = Cbor(value)
  }
}

public sealed class CborValue {
  public data class UnsignedInteger(val value: BigInteger) : CborValue()

  public data class NegativeInteger(val value: BigInteger) : CborValue()

  public data class ByteString(val value: ByteArray) : CborValue() {
    override fun equals(other: Any?): Boolean =
      other is ByteString && value.contentEquals(other.value)

    override fun hashCode(): Int = value.contentHashCode()
  }

  public data class TextString(val value: String) : CborValue()

  public data class Array(val value: CborArray) : CborValue()

  public data class Map(val value: CborMap) : CborValue()

  public data object True : CborValue()

  public data object False : CborValue()

  public data object Null : CborValue()
}

public class CborMap private constructor(private val entries: MutableMap<String, CborValue>) {

  public val keys: Set<String>
    get() = entries.keys

  public operator fun get(key: String): Cbor? = entries[key]?.let { Cbor.fromValue(it) }

  public fun getString(key: String): String? = (entries[key] as? CborValue.TextString)?.value

  public fun getBytes(key: String): ByteArray? =
    when (val value = entries[key]) {
      is CborValue.ByteString -> value.value
      is CborValue.Array -> value.value.toByteArray()
      else -> null
    }

  public fun getInt(key: String): Int? =
    when (val value = entries[key]) {
      is CborValue.UnsignedInteger -> {
        if (value.value > BigInteger.valueOf(Int.MAX_VALUE.toLong())) {
          throw CborException("Integer value too large for Int at key '$key': ${value.value}")
        }
        value.value.toInt()
      }
      is CborValue.NegativeInteger -> {
        if (value.value < BigInteger.valueOf(Int.MIN_VALUE.toLong())) {
          throw CborException("Integer value too small for Int at key '$key': ${value.value}")
        }
        value.value.toInt()
      }
      else -> null
    }

  public fun getLong(key: String): Long? =
    when (val value = entries[key]) {
      is CborValue.UnsignedInteger -> {
        if (value.value > BigInteger.valueOf(Long.MAX_VALUE)) {
          throw CborException("Integer value too large for Long at key '$key': ${value.value}")
        }
        value.value.toLong()
      }
      is CborValue.NegativeInteger -> {
        if (value.value < BigInteger.valueOf(Long.MIN_VALUE)) {
          throw CborException("Integer value too small for Long at key '$key': ${value.value}")
        }
        value.value.toLong()
      }
      else -> null
    }

  public fun getBoolean(key: String): Boolean? =
    when (entries[key]) {
      is CborValue.True -> true
      is CborValue.False -> false
      else -> null
    }

  public fun getMap(key: String): CborMap? = (entries[key] as? CborValue.Map)?.value

  public fun isArray(key: String): Boolean = entries[key] is CborValue.Array

  public fun isNull(key: String): Boolean = entries[key] is CborValue.Null

  public fun contains(key: String): Boolean = entries.containsKey(key)

  public fun toMutableMap(): MutableMap<String, CborValue> = entries

  public companion object {
    public fun create(): CborMap = CborMap(mutableMapOf())

    public fun from(entries: Map<String, CborValue>): CborMap = CborMap(entries.toMutableMap())
  }
}

public class CborArray private constructor(private val elements: MutableList<CborValue>) {

  public val size: Int
    get() = elements.size

  public operator fun get(index: Int): Cbor? = elements.getOrNull(index)?.let { Cbor.fromValue(it) }

  public fun toList(): List<CborValue> = elements.toList()

  public fun toByteArray(): ByteArray {
    return elements
      .filterIsInstance<CborValue.UnsignedInteger>()
      .map {
        val intValue = it.value.toInt()
        if (intValue < 0 || intValue > 255) {
          throw CborException("Byte value out of range: $intValue")
        }
        intValue.toByte()
      }
      .toByteArray()
  }

  public companion object {
    public fun create(): CborArray = CborArray(mutableListOf())

    public fun from(elements: List<CborValue>): CborArray = CborArray(elements.toMutableList())
  }
}

public class CborException(message: String) : Exception(message)

private data class CborReadResult(val value: CborValue, val bytesRead: Int)

private object CborReader {
  private const val MAJOR_UNSIGNED = 0
  private const val MAJOR_NEGATIVE = 1
  private const val MAJOR_BYTES = 2
  private const val MAJOR_TEXT = 3
  private const val MAJOR_ARRAY = 4
  private const val MAJOR_MAP = 5
  private const val MAJOR_TAG = 6
  private const val MAJOR_SIMPLE = 7

  private const val SIMPLE_FALSE = 20
  private const val SIMPLE_TRUE = 21
  private const val SIMPLE_NULL = 22

  fun read(bytes: ByteArray, options: CborParseOptions = CborParseOptions.DEFAULT): CborReadResult {
    val input = DataInputStream(ByteArrayInputStream(bytes))
    val countingInput = CountingDataInputStream(input)
    val value = readValue(countingInput, 0, options)
    if (options.rejectTrailingData) {
      val remaining = bytes.size - countingInput.bytesRead
      if (remaining > 0) {
        throw CborException("Trailing data after CBOR root object ($remaining bytes)")
      }
    }
    return CborReadResult(value, countingInput.bytesRead)
  }

  private fun readValue(
    input: CountingDataInputStream,
    depth: Int,
    options: CborParseOptions,
  ): CborValue {
    if (depth > options.maxDepth) {
      throw CborException("Maximum nesting depth (${options.maxDepth}) exceeded")
    }
    val firstByte = input.readUnsignedByte()
    val majorType = firstByte shr 5
    val additionalInfo = firstByte and 0x1F

    return when (majorType) {
      MAJOR_UNSIGNED -> CborValue.UnsignedInteger(readUnsignedInteger(input, additionalInfo))
      MAJOR_NEGATIVE ->
        CborValue.NegativeInteger(
          BigInteger.valueOf(-1) - readUnsignedInteger(input, additionalInfo)
        )
      MAJOR_BYTES -> CborValue.ByteString(readByteString(input, additionalInfo, options))
      MAJOR_TEXT -> CborValue.TextString(readTextString(input, additionalInfo, options))
      MAJOR_ARRAY -> CborValue.Array(readArray(input, additionalInfo, depth, options))
      MAJOR_MAP -> CborValue.Map(readMap(input, additionalInfo, depth, options))
      MAJOR_TAG -> {
        readUnsignedInteger(input, additionalInfo)
        readValue(input, depth + 1, options)
      }
      MAJOR_SIMPLE -> readSimple(additionalInfo)
      else -> throw CborException("Unknown major type: $majorType")
    }
  }

  private fun readUnsignedInteger(input: CountingDataInputStream, additionalInfo: Int): BigInteger {
    return when (additionalInfo) {
      in 0..23 -> BigInteger.valueOf(additionalInfo.toLong())
      24 -> BigInteger.valueOf(input.readUnsignedByte().toLong())
      25 -> BigInteger.valueOf(input.readUnsignedShort().toLong())
      26 -> BigInteger.valueOf(input.readInt().toLong() and 0xFFFFFFFF)
      27 -> BigInteger(1, input.readNBytes(8))
      else -> throw CborException("Invalid additional info for unsigned integer: $additionalInfo")
    }
  }

  private fun readByteString(
    input: CountingDataInputStream,
    additionalInfo: Int,
    options: CborParseOptions,
  ): ByteArray {
    val length = readLength(input, additionalInfo)
    if (length > Int.MAX_VALUE) {
      throw CborException("Byte string length too large: $length")
    }
    if (length > options.maxStringBytes) {
      throw CborException("Byte string too large: $length (max ${options.maxStringBytes})")
    }
    return input.readNBytes(length.toInt())
  }

  private fun readTextString(
    input: CountingDataInputStream,
    additionalInfo: Int,
    options: CborParseOptions,
  ): String {
    val length = readLength(input, additionalInfo)
    if (length > Int.MAX_VALUE) {
      throw CborException("Text string length too large: $length")
    }
    if (length > options.maxStringBytes) {
      throw CborException("Text string too large: $length (max ${options.maxStringBytes})")
    }
    return String(input.readNBytes(length.toInt()), Charsets.UTF_8)
  }

  private fun readArray(
    input: CountingDataInputStream,
    additionalInfo: Int,
    depth: Int,
    options: CborParseOptions,
  ): CborArray {
    val length = readLength(input, additionalInfo)
    if (length > options.maxCollectionItems) {
      throw CborException("Array size too large: $length (max ${options.maxCollectionItems})")
    }
    val elements = mutableListOf<CborValue>()
    repeat(length.toInt()) { elements.add(readValue(input, depth + 1, options)) }
    return CborArray.from(elements)
  }

  private fun readMap(
    input: CountingDataInputStream,
    additionalInfo: Int,
    depth: Int,
    options: CborParseOptions,
  ): CborMap {
    val length = readLength(input, additionalInfo)
    if (length > options.maxCollectionItems) {
      throw CborException("Map size too large: $length (max ${options.maxCollectionItems})")
    }
    val map = mutableMapOf<String, CborValue>()
    repeat(length.toInt()) {
      val key =
        when (val keyValue = readValue(input, depth + 1, options)) {
          is CborValue.TextString -> keyValue.value
          is CborValue.UnsignedInteger -> keyValue.value.toString()
          is CborValue.NegativeInteger -> keyValue.value.toString()
          else ->
            throw CborException(
              "Map key must be text or integer, got ${keyValue::class.simpleName}"
            )
        }
      if (options.rejectDuplicateKeys && map.containsKey(key)) {
        throw CborException("Duplicate key in CBOR map: $key")
      }
      val value = readValue(input, depth + 1, options)
      map[key] = value
    }
    return CborMap.from(map)
  }

  private fun readSimple(additionalInfo: Int): CborValue {
    return when (additionalInfo) {
      SIMPLE_FALSE -> CborValue.False
      SIMPLE_TRUE -> CborValue.True
      SIMPLE_NULL -> CborValue.Null
      else -> throw CborException("Unknown simple value: $additionalInfo")
    }
  }

  private fun readLength(input: CountingDataInputStream, additionalInfo: Int): Long {
    return when (additionalInfo) {
      in 0..23 -> additionalInfo.toLong()
      24 -> input.readUnsignedByte().toLong()
      25 -> input.readUnsignedShort().toLong()
      26 -> input.readInt().toLong() and 0xFFFFFFFF
      27 -> input.readLong()
      31 -> throw CborException("Indefinite length not supported")
      else -> throw CborException("Invalid additional info for length: $additionalInfo")
    }
  }
}

private class CountingDataInputStream(private val delegate: DataInputStream) {
  var bytesRead: Int = 0
    private set

  fun readUnsignedByte(): Int {
    val v = delegate.readUnsignedByte()
    bytesRead++
    return v
  }

  fun readUnsignedShort(): Int {
    val v = delegate.readUnsignedShort()
    bytesRead += 2
    return v
  }

  fun readInt(): Int {
    val v = delegate.readInt()
    bytesRead += 4
    return v
  }

  fun readLong(): Long {
    val v = delegate.readLong()
    bytesRead += 8
    return v
  }

  fun readNBytes(n: Int): ByteArray {
    val v = delegate.readNBytes(n)
    bytesRead += v.size
    return v
  }
}

private object CborWriter {
  private const val MAJOR_UNSIGNED = 0
  private const val MAJOR_NEGATIVE = 1
  private const val MAJOR_BYTES = 2
  private const val MAJOR_TEXT = 3
  private const val MAJOR_ARRAY = 4
  private const val MAJOR_MAP = 5
  private const val MAJOR_SIMPLE = 7

  private const val SIMPLE_FALSE = 20
  private const val SIMPLE_TRUE = 21
  private const val SIMPLE_NULL = 22

  fun write(value: CborValue): ByteArray {
    val output = ByteArrayOutputStream()
    val dataOutput = DataOutputStream(output)
    writeValue(dataOutput, value)
    return output.toByteArray()
  }

  private fun writeValue(output: DataOutputStream, value: CborValue) {
    when (value) {
      is CborValue.UnsignedInteger -> writeUnsignedInteger(output, value.value)
      is CborValue.NegativeInteger -> writeNegativeInteger(output, value.value)
      is CborValue.ByteString -> writeByteString(output, value.value)
      is CborValue.TextString -> writeTextString(output, value.value)
      is CborValue.Array -> writeArray(output, value.value)
      is CborValue.Map -> writeMap(output, value.value)
      is CborValue.True -> output.writeByte((MAJOR_SIMPLE shl 5) or SIMPLE_TRUE)
      is CborValue.False -> output.writeByte((MAJOR_SIMPLE shl 5) or SIMPLE_FALSE)
      is CborValue.Null -> output.writeByte((MAJOR_SIMPLE shl 5) or SIMPLE_NULL)
    }
  }

  private fun writeUnsignedInteger(output: DataOutputStream, value: BigInteger) {
    if (value > BigInteger.valueOf(Long.MAX_VALUE)) {
      throw CborException("Unsigned integer too large for CBOR encoding: $value")
    }
    val longValue = value.toLong()
    when {
      longValue in 0..23 -> output.writeByte((MAJOR_UNSIGNED shl 5) or longValue.toInt())
      longValue in 0..255 -> {
        output.writeByte((MAJOR_UNSIGNED shl 5) or 24)
        output.writeByte(longValue.toInt())
      }
      longValue in 0..65535 -> {
        output.writeByte((MAJOR_UNSIGNED shl 5) or 25)
        output.writeShort(longValue.toInt())
      }
      longValue in 0..4294967295L -> {
        output.writeByte((MAJOR_UNSIGNED shl 5) or 26)
        output.writeInt(longValue.toInt())
      }
      else -> {
        output.writeByte((MAJOR_UNSIGNED shl 5) or 27)
        output.writeLong(longValue)
      }
    }
  }

  private fun writeNegativeInteger(output: DataOutputStream, value: BigInteger) {
    if (value < BigInteger.valueOf(Long.MIN_VALUE)) {
      throw CborException("Negative integer too small for CBOR encoding: $value")
    }
    val cborValue = (-value.toLong()) - 1
    when {
      cborValue in 0..23 -> output.writeByte((MAJOR_NEGATIVE shl 5) or cborValue.toInt())
      cborValue in 0..255 -> {
        output.writeByte((MAJOR_NEGATIVE shl 5) or 24)
        output.writeByte(cborValue.toInt())
      }
      cborValue in 0..65535 -> {
        output.writeByte((MAJOR_NEGATIVE shl 5) or 25)
        output.writeShort(cborValue.toInt())
      }
      cborValue in 0..4294967295L -> {
        output.writeByte((MAJOR_NEGATIVE shl 5) or 26)
        output.writeInt(cborValue.toInt())
      }
      else -> {
        output.writeByte((MAJOR_NEGATIVE shl 5) or 27)
        output.writeLong(cborValue)
      }
    }
  }

  private fun writeByteString(output: DataOutputStream, value: ByteArray) {
    writeLength(output, MAJOR_BYTES, value.size.toLong())
    output.write(value)
  }

  private fun writeTextString(output: DataOutputStream, value: String) {
    val bytes = value.toByteArray(Charsets.UTF_8)
    writeLength(output, MAJOR_TEXT, bytes.size.toLong())
    output.write(bytes)
  }

  private fun writeArray(output: DataOutputStream, array: CborArray) {
    writeLength(output, MAJOR_ARRAY, array.size.toLong())
    array.toList().forEach { writeValue(output, it) }
  }

  private fun writeMap(output: DataOutputStream, map: CborMap) {
    writeLength(output, MAJOR_MAP, map.keys.size.toLong())
    map.toMutableMap().forEach { (key, value) ->
      writeTextString(output, key)
      writeValue(output, value)
    }
  }

  private fun writeLength(output: DataOutputStream, majorType: Int, length: Long) {
    when {
      length in 0..23 -> output.writeByte((majorType shl 5) or length.toInt())
      length in 0..255 -> {
        output.writeByte((majorType shl 5) or 24)
        output.writeByte(length.toInt())
      }
      length in 0..65535 -> {
        output.writeByte((majorType shl 5) or 25)
        output.writeShort(length.toInt())
      }
      length in 0..4294967295L -> {
        output.writeByte((majorType shl 5) or 26)
        output.writeInt(length.toInt())
      }
      else -> {
        output.writeByte((majorType shl 5) or 27)
        output.writeLong(length)
      }
    }
  }
}

public fun ByteArray.toCborIntegerArray(): CborValue.Array {
  val elements =
    this.map { byte ->
      CborValue.UnsignedInteger(BigInteger.valueOf((byte.toInt() and 0xFF).toLong()))
    }
  return CborValue.Array(CborArray.from(elements))
}
