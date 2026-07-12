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
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.databind.CBORMapper
import com.fasterxml.jackson.module.kotlin.kotlinModule
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

  /* maps between signCount (class property, camelCase) to sign_count (CBOR fieldname,
   * snake_case) */
  @JsonProperty("sign_count") val signCount: UInt = 0u,
  val alg: Int,
  @JsonProperty("private_key") val privateKey: ByteArray,
  val created: Long,
  val zone: String,
  val discoverable: Boolean = true,
  val extensions: CredentialExtensions = CredentialExtensions(),
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
  fun toCbor(): ByteArray = cborMapper.writeValueAsBytes(this)

  /**
   * Serialize this PasskeyCredential instance to CBOR format. Returns a Result type for error
   * handling.
   */
  fun toCborResult(): Result<ByteArray, Throwable> = runCatching {
    cborMapper.writeValueAsBytes(this)
  }

  fun clearPrivateKey() {
    privateKey.wipe()
  }

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
    if (discoverable != other.discoverable) return false
    if (extensions != other.extensions) return false
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
    result = 31 * result + discoverable.hashCode()
    result = 31 * result + (extensions?.hashCode() ?: 0)
    return result
  }

  companion object {
    private val cborMapper: ObjectMapper by unsafeLazy { // initialised once, on first use
      CBORMapper().apply {
        registerModule(kotlinModule())
        configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
      }
    }

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
    fun fromCbor(cborBytes: ByteArray): Result<PasskeyCredential, Throwable> = runCatching {
      cborMapper.readValue(cborBytes, PasskeyCredential::class.java)
    }

    fun getPrivateKeyRawBytes(keyPair: KeyPair, algorithm: Algorithm): ByteArray =
      when (algorithm) {
        Algorithm.EDDSA -> getEd25519PrivateKeyRawBytes(keyPair.private)
        Algorithm.ES256 -> getEC256PrivateKeyRawBytes(keyPair.private)
        Algorithm.RS256 -> getRsaCustom512PrivateKeyRawBytes(keyPair.private)
      }

    // PrivateKey conversions to raw bytes, implementations by Gemini
    private fun getEC256PrivateKeyRawBytes(privateKey: PrivateKey): ByteArray {
      val ecKey = privateKey as ECPrivateKey

      // Extract the raw BigInteger scalar d
      val d: java.math.BigInteger = ecKey.s

      // Convert BigInteger to a byte array
      val rawBytes = d.toByteArray()

      return when {
        // Case 1: Exactly 32 bytes (Perfect fit)
        rawBytes.size == 32 -> rawBytes

        // Case 2: 33 bytes due to an extra zero sign-bit padding from BigInteger
        rawBytes.size == 33 && rawBytes[0] == 0.toByte() -> rawBytes.copyOfRange(1, 33)

        // Case 3: Smaller than 32 bytes (Needs leading zero padding)
        else -> {
          val padded = ByteArray(32)
          System.arraycopy(rawBytes, 0, padded, 32 - rawBytes.size, rawBytes.size)
          padded
        }
      }
    }

    private fun getEd25519PrivateKeyRawBytes(privateKey: PrivateKey): ByteArray =
      (PrivateKeyFactory.createKey(privateKey.encoded) as Ed25519PrivateKeyParameters).encoded

    private fun getRsaCustom512PrivateKeyRawBytes(privateKey: PrivateKey): ByteArray {
      val rsaKey = privateKey as RSAPrivateKey
      val nBytes = rsaKey.modulus.to256Bytes()
      val dBytes = rsaKey.privateExponent.to256Bytes()
      return nBytes + dBytes
    }

    // Helper to pad BigInteger out to exactly 256 bytes
    private fun BigInteger.to256Bytes(): ByteArray {
      val raw = this.toByteArray()
      return when {
        raw.size == 256 -> raw
        raw.size == 257 && raw[0] == 0.toByte() -> raw.copyOfRange(1, 257)
        else -> ByteArray(256).apply { System.arraycopy(raw, 0, this, 256 - raw.size, raw.size) }
      }
    }
  }

  private fun loadPrivateKey(): PrivateKey =
    when (Algorithm.fromId(alg)) {
      Algorithm.EDDSA -> rebuildEd25519FromPrivateKeyRawBytes()
      Algorithm.ES256 -> rebuildEC256FromPrivateKeyRawBytes()
      Algorithm.RS256 -> rebuildRsaFromCustom512PivateKeyRawBytes()
      else -> throw IllegalStateException("Unsupported passkey algorithm, COSE alg=${alg}")
    }

  // PrivateKey conversions from raw bytes, implementations by Gemini
  private fun rebuildEC256FromPrivateKeyRawBytes(): PrivateKey {
    require(privateKey.size == 32) { "ECDSA P-256 raw private key must be 32 bytes" }
    /* Force the byte array to be interpreted as a POSITIVE number (signum = 1).
     * This safely strips or corrects any missing leading zero bytes from BigInteger
     * conversion. */
    val s = BigInteger(1, privateKey)

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

    val privKeyParams = Ed25519PrivateKeyParameters(privateKey, 0)
    val privKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privKeyParams)

    return JcaPEMKeyConverter().setProvider(BouncyCastleProvider()).getPrivateKey(privKeyInfo)
  }

  private fun rebuildRsaFromCustom512PivateKeyRawBytes(): PrivateKey {
    require(privateKey.size == 512) { "Buffer must be exactly 512 bytes" }
    val n = BigInteger(1, privateKey.copyOfRange(0, 256))
    val d = BigInteger(1, privateKey.copyOfRange(256, 512))

    val keySpec = RSAPrivateKeySpec(n, d)
    return KeyFactory.getInstance("RSA", BouncyCastleProvider()).generatePrivate(keySpec)
  }

  data class CredentialExtensions(
    @JsonProperty("cred_protect") val credProtect: UByte? = null,
    @JsonProperty("hmac_secret") val hmacSecret: Boolean? = null,
    @JsonProperty("cred_random") val credRandom: ByteArray? = null,
  ) {
    override fun equals(other: Any?): Boolean {
      if (this === other) return true
      if (other !is CredentialExtensions) return false
      if (credProtect != other.credProtect) return false
      if (hmacSecret != other.hmacSecret) return false
      if (!credRandom.contentEquals(other.credRandom)) return false
      return true
    }

    override fun hashCode(): Int {
      var result = credProtect.hashCode()
      result = 31 * result + hmacSecret.hashCode()
      result = 31 * result + credRandom.contentHashCode()
      return result
    }
  }

  data class UserInfo(
    val id: ByteArray,
    val name: String,
    @JsonProperty("display_name") val displayName: String? = null,
    @JsonProperty("reveal_name") var revealName: Boolean = false,
  ) {
    /* override auto-generated equals() and hashCode() methods which do not work correctly
     * since they compare by ref not by content */
    override fun equals(other: Any?): Boolean {
      if (this === other) return true
      if (other !is UserInfo) return false
      if (!id.contentEquals(other.id)) return false
      if (name != other.name) return false
      if (revealName != other.revealName) return false
      if (displayName != other.displayName) return false
      return true
    }

    override fun hashCode(): Int {
      var result = id.contentHashCode()
      result = 31 * result + name.hashCode()
      result = 31 * result + revealName.hashCode()
      result = 31 * result + (displayName?.hashCode() ?: 0)
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
