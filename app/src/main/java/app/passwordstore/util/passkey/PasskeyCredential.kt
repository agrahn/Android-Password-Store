/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.passkey

import android.os.Build
import androidx.annotation.RequiresApi
import app.passwordstore.util.extensions.b64Encode
import app.passwordstore.util.extensions.unsafeLazy
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
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
data class PasskeyCredential(
  val id: ByteArray,
  val rp: RelyingPartyInfo,
  val user: UserInfo,
  val signCount: UInt = 0u,
  val alg: Int,
  val privateKey: ByteArray,
  val created: Long,
  val zone: String,
) {

  fun getAlgorithmName(): String? = Algorithm.fromId(alg)?.algorithmName

  fun getAlgorithmString(): String? = Algorithm.fromId(alg)?.toString()

  fun incrementSignCount(): PasskeyCredential = copy(signCount = signCount + 1u)

  fun idBase64(): String = id.b64Encode().concatToString()

  fun idHex(): String = id.toHexString()

  /**
   * Serialize this PasskeyCredential instance to CBOR format. throws Exception if serialization
   * fails
   */
  fun toCbor(): ByteArray {
    val rpInfoMap = mutableMapOf<String, Any>()
    rpInfoMap["id"] = rp.id
    rp.name?.let { rpInfoMap["name"] = it }

    val userInfoMap = mutableMapOf<String, Any>()
    userInfoMap["id"] = user.id
    userInfoMap["name"] = user.name
    user.displayName?.let { userInfoMap["display_name"] = it }
    userInfoMap["reveal_name"] = user.revealName

    val passkeyMap = mutableMapOf<String, Any>()
    passkeyMap["id"] = id
    passkeyMap["rp"] = rpInfoMap
    passkeyMap["user"] = userInfoMap
    passkeyMap["sign_count"] = signCount
    passkeyMap["alg"] = alg
    passkeyMap["private_key"] = privateKey
    passkeyMap["created"] = created
    passkeyMap["zone"] = zone

    return cborEngine.encode(passkeyMap)
  }

  /**
   * Serialize this PasskeyCredential instance to CBOR format. Returns a Result type for error
   * handling.
   */
  fun toCborResult(): Result<ByteArray, Throwable> = runCatching { toCbor() }

  fun clearPrivateKey() = privateKey.wipe()

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

    private val cborEngine: Cbor by unsafeLazy { Cbor() }

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
        id = credentialId,
        rp =
          RelyingPartyInfo(
            id = rpId,
            name = rpName,
          ),
        user =
          UserInfo(
            id = userId,
            name = userName,
            displayName = userDisplayName,
          ),
        alg = algorithm.id,
        privateKey =
          getPrivateKeyRawBytes(
            keyPair = keyPair,
            algorithm = algorithm,
          ),
        created = createdAt.getEpochSecond(),
        zone = zoneId.toString(),
      )

    // Parse [cborBytes] into a PasskeyCredential instance.
    @Suppress("UNCHECKED_CAST")
    fun fromCbor(cborBytes: ByteArray): Result<PasskeyCredential, Throwable> = runCatching {
      val rootMap = cborEngine.decode(cborBytes) as Map<String, Any>

      // Helper to check if a value is absent, or explicitly encoded as CBOR null (Unit)
      fun Any?.unwrapNull(): Any? = if (this == Unit || this == null) null else this

      // 1. Decode RelyingPartyInfo tolerating explicit nulls
      val rpRaw = rootMap["rp"] as? Map<String, Any>
      val rpInfo =
        RelyingPartyInfo(
          id = rpRaw?.get("id")?.unwrapNull() as? String ?: "",
          name = rpRaw?.get("name")?.unwrapNull() as? String,
        )

      // 2. Decode UserInfo tolerating explicit nulls
      val userRaw = rootMap["user"] as? Map<String, Any>
      val userInfo =
        UserInfo(
          id = userRaw?.get("id")?.unwrapNull() as? ByteArray ?: byteArrayOf(),
          name = userRaw?.get("name")?.unwrapNull() as? String ?: "",
          displayName = userRaw?.get("display_name")?.unwrapNull() as? String,
          revealName = userRaw?.get("reveal_name")?.unwrapNull() as? Boolean ?: false,
        )

      // 3. Decode Root PasskeyCredential tolerating explicit nulls
      PasskeyCredential(
        id = rootMap["id"]?.unwrapNull() as? ByteArray ?: byteArrayOf(),
        rp = rpInfo,
        user = userInfo,
        signCount = (rootMap["sign_count"]?.unwrapNull() as? Long)?.toUInt() ?: 0u,
        alg = (rootMap["alg"]?.unwrapNull() as? Long)?.toInt() ?: 0,
        privateKey = rootMap["private_key"]?.unwrapNull() as? ByteArray ?: byteArrayOf(),
        created = rootMap["created"]?.unwrapNull() as? Long ?: 0L,
        zone = rootMap["zone"]?.unwrapNull() as? String ?: "UTC",
      )
    }

    fun getPrivateKeyRawBytes(keyPair: KeyPair, algorithm: Algorithm): ByteArray =
      when (algorithm) {
        Algorithm.EDDSA -> getEd25519PrivateKeyRawBytes(keyPair.private)
        Algorithm.ES256 -> getES256PrivateKeyRawBytes(keyPair.private)
        Algorithm.RS256 -> getRS256PrivateKeyRawBytes(keyPair.private)
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
      Algorithm.EDDSA -> rebuildEd25519FromPrivateKeyRawBytes()
      Algorithm.ES256 -> rebuildES256FromPrivateKeyRawBytes()
      Algorithm.RS256 -> rebuildRS256FromPrivateKeyRawBytes()
      else -> throw IllegalStateException("Unsupported passkey algorithm, COSE alg=${alg}")
    }

  // PrivateKey conversions from raw bytes
  private fun rebuildES256FromPrivateKeyRawBytes(): PrivateKey {
    require(privateKey.size == 32) { "ECDSA P-256 raw private key must be 32 bytes" }
    /* Force the byte array to be interpreted as a POSITIVE number (signum = 1).
     * This safely strips or corrects any missing leading zero bytes from BigInteger
     * conversion. */
    val s = BigInteger(1, privateKey)

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

  private fun rebuildEd25519FromPrivateKeyRawBytes(): PrivateKey {
    require(privateKey.size == 32) { "Ed25519 raw private key must be 32 bytes" }
    val privateKeyParams = Ed25519PrivateKeyParameters(privateKey, 0)
    val privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParams)
    return JcaPEMKeyConverter().setProvider(BouncyCastleProvider()).getPrivateKey(privateKeyInfo)
  }

  private fun rebuildRS256FromPrivateKeyRawBytes(): PrivateKey {
    require(privateKey.size == 512) { "Buffer must be exactly 512 bytes" }
    val nBytes = privateKey.copyOfRange(0, 256)
    val n = BigInteger(1, nBytes)
    nBytes.wipe()
    val dBytes = privateKey.copyOfRange(256, 512)
    val d = BigInteger(1, dBytes)
    dBytes.wipe()
    val keySpec = RSAPrivateKeySpec(n, d)
    return KeyFactory.getInstance("RSA", BouncyCastleProvider()).generatePrivate(keySpec)
  }

  data class UserInfo(
    val id: ByteArray,
    val name: String,
    val displayName: String? = null,
    var revealName: Boolean = false,
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

    fun idBase64(): String = id.b64Encode().concatToString()

    fun idHex(): String = id.toHexString()
  }

  data class RelyingPartyInfo(
    val id: String,
    val name: String? = null,
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
