/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.passkey

import app.passwordstore.util.extensions.wipe
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.runCatching
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.ECPrivateKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale
import kotlinx.serialization.*
import kotlinx.serialization.cbor.*
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter

@OptIn(
  kotlin.ExperimentalUnsignedTypes::class,
  kotlinx.serialization.ExperimentalSerializationApi::class,
)
@Serializable
data class PasskeyCredential(
  @SerialName("id") val id: UShortArray,
  @SerialName("rp") val rp: RelyingPartyInfo,
  @SerialName("user") val user: UserInfo,
  @SerialName("sign_count") val signCount: UInt = 0u,
  @SerialName("alg") val alg: Int,
  @SerialName("private_key") val privateKey: UShortArray,
  @SerialName("created") val created: Long,
  @SerialName("zone") val zone: String = "UTC",
) {

  fun getAlgorithmName(): String? = Algorithm.fromId(alg)?.algorithmName

  fun getAlgorithmString(): String? = Algorithm.fromId(alg)?.toString()

  fun incrementSignCount(): PasskeyCredential = copy(signCount = signCount + 1u)

  fun idHex(): String = id.joinToString("") { String.format("%02x", it.toInt()) }

  fun idByteArray(): ByteArray = ByteArray(id.size) { id[it].toByte() }

  /**
   * Serialize this PasskeyCredential instance to CBOR format. throws Exception if serialization
   * fails
   */
  fun toCbor(): ByteArray = cborEngine.encodeToByteArray(PasskeyCredential.serializer(), this)

  /**
   * Serialize this PasskeyCredential instance to CBOR format. Returns a Result type for error
   * handling.
   */
  fun toCborResult(): Result<ByteArray, Throwable> = runCatching { toCbor() }

  fun clearPrivateKey() = privateKey.fill(0u)

  fun signData(dataToSign: ByteArray): Result<ByteArray, Throwable> = runCatching {
    val jcaPrivateKey = loadPrivateKey()

    val engine =
      Signature.getInstance(
        when (Algorithm.fromId(alg)) {
          Algorithm.EDDSA -> "Ed25519"
          Algorithm.ES256 -> "SHA256withECDSA"
          Algorithm.RS256 -> "SHA256withRSA"
          else -> {
            throw IllegalStateException(
              "Creating Signature instance from unsupported passkey algorithm, COSE alg=${alg}"
            )
          }
        },
        BouncyCastleProvider(),
      )

    engine.initSign(jcaPrivateKey)
    engine.update(dataToSign)
    engine.sign()
  }

  fun creationDateTimeString(formatStyle: FormatStyle = FormatStyle.LONG): String {
    val instant = Instant.ofEpochSecond(created)
    val zoneId = ZoneId.of(zone)
    val zonedDateTime = instant.atZone(zoneId)
    val currentLocale = Locale.getDefault()
    val formatter = DateTimeFormatter.ofLocalizedDateTime(formatStyle).withLocale(currentLocale)
    return zonedDateTime.format(formatter)
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is PasskeyCredential) return false
    if (!id.contentEquals(other.id)) return false
    if (rp != other.rp) return false
    if (user != other.user) return false
    if (signCount != other.signCount) return false
    if (alg != other.alg) return false
    if (!privateKey.contentEquals(other.privateKey)) return false
    if (created != other.created) return false
    if (zone != other.zone) return false
    return true
  }

  override fun hashCode(): Int {
    var result = id.contentHashCode()
    result = 31 * result + rp.hashCode()
    result = 31 * result + user.hashCode()
    result = 31 * result + signCount.hashCode()
    result = 31 * result + alg
    result = 31 * result + privateKey.contentHashCode()
    result = 31 * result + created.hashCode()
    result = 31 * result + zone.hashCode()
    return result
  }

  companion object {

    private val cborEngine: Cbor = Cbor {
      ignoreUnknownKeys = true
      useDefiniteLengthEncoding = true
      encodeDefaults = true
    }

    private fun ByteArray.toUShortArray(): UShortArray =
      UShortArray(size) { this[it].toUByte().toUShort() }

    fun createNew(
      credentialId: ByteArray,
      rpId: String,
      rpName: String? = null,
      userId: ByteArray,
      userName: String,
      userDisplayName: String? = null,
      algorithm: Algorithm,
      keyPair: KeyPair,
      createdAt: Instant = Instant.now(),
      zoneId: ZoneId = ZoneId.systemDefault(),
    ): PasskeyCredential =
      PasskeyCredential(
        id = credentialId.toUShortArray(),
        rp =
          RelyingPartyInfo(
            id = rpId,
            name = rpName,
          ),
        user =
          UserInfo(
            id = userId.toUShortArray(),
            name = userName,
            displayName = userDisplayName,
          ),
        alg = algorithm.id,
        privateKey =
          getPrivateKeyRawBytesAsUShortArray(
            keyPair = keyPair,
            algorithm = algorithm,
          ),
        created = createdAt.getEpochSecond(),
        zone = zoneId.toString(),
      )

    // Parse [cborBytes] into a PasskeyCredential instance.
    @Suppress("UNCHECKED_CAST")
    fun fromCbor(cborBytes: ByteArray): Result<PasskeyCredential, Throwable> = runCatching {
      cborEngine.decodeFromByteArray(PasskeyCredential.serializer(), cborBytes)
    }

    private fun getPrivateKeyRawBytesAsUShortArray(
      keyPair: KeyPair,
      algorithm: Algorithm,
    ): UShortArray {
      val bytes =
        when (algorithm) {
          Algorithm.EDDSA -> getEd25519PrivateKeyRawBytes(keyPair.private)
          Algorithm.ES256 -> getES256PrivateKeyRawBytes(keyPair.private)
          Algorithm.RS256 -> getRS256PrivateKeyRawBytes(keyPair.private)
        }
      return bytes.toUShortArray().also { bytes.wipe() }
    }

    // PrivateKey conversions to raw bytes

    /* ECDSA P-256 private key as raw BigInteger scalar, converted to zero-padded, size 32 ByteArray
     * with leading sign byte stripped */
    private fun getES256PrivateKeyRawBytes(privateKey: PrivateKey): ByteArray {
      val s = (privateKey as ECPrivateKey).s.toByteArray()
      val sPadded = ByteArray(32) + s
      s.wipe()
      return sPadded.copyOfRange(sPadded.size - 32, sPadded.size).also { sPadded.wipe() }
    }

    /* Ed25519 private key, converted to raw size 32 ByteArray using BouncyCastle */
    private fun getEd25519PrivateKeyRawBytes(privateKey: PrivateKey): ByteArray {
      val encoded = privateKey.encoded
      return (PrivateKeyFactory.createKey(encoded) as Ed25519PrivateKeyParameters).encoded.also {
        encoded.wipe()
      }
    }

    // RSA-2048 private key, with modulus and exponent concatenated to size 512 ByteArray
    private fun getRS256PrivateKeyRawBytes(privateKey: PrivateKey): ByteArray {
      val rsaKey = privateKey as RSAPrivateKey

      val mod = rsaKey.modulus.toByteArray()
      val modPadded = ByteArray(256) + mod
      mod.wipe()
      val nBytes = modPadded.copyOfRange(modPadded.size - 256, modPadded.size)
      modPadded.wipe()

      val exp = rsaKey.privateExponent.toByteArray()
      val expPadded = ByteArray(256) + exp
      exp.wipe()
      val dBytes = expPadded.copyOfRange(expPadded.size - 256, expPadded.size)
      expPadded.wipe()

      return (nBytes + dBytes).also {
        nBytes.wipe()
        dBytes.wipe()
      }
    }
  }

  private fun loadPrivateKey(): PrivateKey =
    when (Algorithm.fromId(alg)) {
      Algorithm.EDDSA -> rebuildEd25519FromPrivateKeyRawUShortArray()
      Algorithm.ES256 -> rebuildES256FromPrivateKeyRawUShortArray()
      Algorithm.RS256 -> rebuildRS256FromPrivateKeyRawUShortArray()
      else -> throw IllegalStateException("Unsupported passkey algorithm, COSE alg=${alg}")
    }

  // PrivateKey conversions from raw bytes

  private fun rebuildES256FromPrivateKeyRawUShortArray(): PrivateKey {
    require(privateKey.size == 32) { "ECDSA P-256 raw private key must be 32 bytes" }
    val bytes = ByteArray(32) { privateKey[it].toByte() }

    /* Force the byte array to be interpreted as a POSITIVE number (signum = 1).
     * This safely strips or corrects any missing leading zero bytes from BigInteger
     * conversion. */
    val s = BigInteger(1, bytes)
    bytes.wipe()

    // private key scalar validation
    val n = org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("secp256r1").n
    require(s >= BigInteger.ONE && s < n) { "Private key scalar out of valid range" }

    // Fetch the standard secp256r1 (NIST P-256) curve parameters
    val params =
      AlgorithmParameters.getInstance("EC", BouncyCastleProvider()).apply {
        init(java.security.spec.ECGenParameterSpec("secp256r1"))
      }
    val ecParameters = params.getParameterSpec(java.security.spec.ECParameterSpec::class.java)

    // Generate the KeySpec and build the private key
    val keySpec = ECPrivateKeySpec(s, ecParameters)
    val keyFactory = KeyFactory.getInstance("EC", BouncyCastleProvider())

    return keyFactory.generatePrivate(keySpec)
  }

  private fun rebuildEd25519FromPrivateKeyRawUShortArray(): PrivateKey {
    require(privateKey.size == 32) { "Ed25519 raw private key must be 32 bytes" }
    val bytes = ByteArray(32) { privateKey[it].toByte() }

    val privateKeyParams = Ed25519PrivateKeyParameters(bytes)
    bytes.wipe()
    val privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams)
    return JcaPEMKeyConverter().setProvider(BouncyCastleProvider()).getPrivateKey(privateKeyInfo)
  }

  private fun rebuildRS256FromPrivateKeyRawUShortArray(): PrivateKey {
    require(privateKey.size == 512) { "Buffer must be exactly 512 bytes" }
    val bytes = ByteArray(512) { privateKey[it].toByte() }

    val nBytes = bytes.copyOfRange(0, 256)
    val n = BigInteger(1, nBytes)
    nBytes.wipe()
    val dBytes = bytes.copyOfRange(256, 512)
    val d = BigInteger(1, dBytes)
    dBytes.wipe()
    bytes.wipe()
    val keySpec = RSAPrivateKeySpec(n, d)
    return KeyFactory.getInstance("RSA", BouncyCastleProvider()).generatePrivate(keySpec)
  }

  @Serializable
  data class UserInfo(
    @SerialName("id") val id: UShortArray,
    @SerialName("name") val name: String,
    @SerialName("display_name") val displayName: String? = null,
    @SerialName("reveal_name") var revealName: Boolean = false,
  ) {
    /* override auto-generated equals() and hashCode() methods which do not work correctly
     * since they compare by ref not by content */
    override fun equals(other: Any?): Boolean {
      if (this === other) return true
      if (other !is UserInfo) return false
      if (!id.contentEquals(other.id)) return false
      if (name != other.name) return false
      if (displayName != other.displayName) return false
      if (revealName != other.revealName) return false
      return true
    }

    override fun hashCode(): Int {
      var result = id.contentHashCode()
      result = 31 * result + name.hashCode()
      result = 31 * result + (displayName?.hashCode() ?: 0)
      result = 31 * result + revealName.hashCode()
      return result
    }

    fun idHex(): String = id.joinToString("") { String.format("%02x", it.toInt()) }

    fun idByteArray(): ByteArray = ByteArray(id.size) { id[it].toByte() }
  }

  @Serializable
  data class RelyingPartyInfo(
    @SerialName("id") val id: String,
    @SerialName("name") val name: String? = null,
  ) {
    override fun equals(other: Any?): Boolean {
      if (this === other) return true
      if (other !is RelyingPartyInfo) return false
      if (id != other.id) return false
      if (name != other.name) return false
      return true
    }

    override fun hashCode(): Int {
      var result = id.hashCode()
      result = 31 * result + name.hashCode()
      return result
    }
  }
}
