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
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.jce.provider.BouncyCastleProvider

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
data class StoredCredential(
  val id: ByteArray,
  val rp: RelyingPartyInfo,
  val user: UserInfo,

  // maps between signCount (class property, camelCase) to sign_count (CBOR fieldname, snake_case)
  @JsonProperty("sign_count") val signCount: UInt,
  val alg: Int,
  @JsonProperty("private_key") val privateKey: ByteArray,
  val created: Long,
  val zone: String,
  val discoverable: Boolean = true,
  val extensions: CredentialExtensions = CredentialExtensions(),
) {

  fun getAlgorithmName(): String? = PasskeyCredential.Algorithm.fromId(alg)?.algorithmName

  fun getAlgorithmString(): String? = PasskeyCredential.Algorithm.fromId(alg)?.toString()

  fun incrementSignCount(): StoredCredential = copy(signCount = signCount + 1u)

  fun idBase64(): String = id.b64Encode().concatToString()

  fun idHex(): String = id.toHexString()

  /**
   * Serialize this StoredCredential instance to CBOR format. throws Exception if serialization
   * fails
   */
  fun toCbor(): ByteArray = cborMapper.writeValueAsBytes(this)

  /**
   * Serialize this StoredCredential instance to CBOR format. Returns a Result type for error
   * handling.
   */
  fun toCborResult(): Result<ByteArray, Throwable> = runCatching {
    cborMapper.writeValueAsBytes(this)
  }

  fun clearPrivateKey() {
    privateKey.wipe()
  }

  fun signData(dataToSign: ByteArray): Result<ByteArray, Throwable> = runCatching {
    val keySpec = PKCS8EncodedKeySpec(privateKey)
    val keyFactory =
      KeyFactory.getInstance(
        when (PasskeyCredential.Algorithm.fromId(alg)) {
          PasskeyCredential.Algorithm.EDDSA -> "Ed25519"
          PasskeyCredential.Algorithm.ES256 -> "EC"
          PasskeyCredential.Algorithm.RS256 -> "RSA"
          else -> {
            throw IllegalStateException("Unsupported passkey algorithm, COSE alg=${alg}")
          }
        },
        BouncyCastleProvider(),
      )
    val jcaPrivateKey = keyFactory.generatePrivate(keySpec)

    val algorithm = PasskeyCredential.Algorithm.fromId(alg)

    val engine =
      Signature.getInstance(
        when (algorithm) {
          PasskeyCredential.Algorithm.EDDSA -> "Ed25519"
          PasskeyCredential.Algorithm.ES256 -> "SHA256withECDSA"
          PasskeyCredential.Algorithm.RS256 -> "SHA256withRSA"
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
    if (other !is StoredCredential) return false
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

    /** Parse [cborBytes] into a StoredCredential instance. */
    fun fromCbor(cborBytes: ByteArray): Result<StoredCredential, Throwable> = runCatching {
      cborMapper.readValue(cborBytes, StoredCredential::class.java)
    }

    /** Parse PasskeyCredential instance [credential] into a StoredCredential instance. */
    fun fromPasskeyCredential(credential: PasskeyCredential): Result<StoredCredential, Throwable> =
      runCatching {
        StoredCredential(
          id = credential.credentialId,
          rp = RelyingPartyInfo(credential.rpId),
          user =
            UserInfo(
              credential.user.id,
              credential.user.name,
              credential.user.displayName,
            ),
          signCount = credential.signCount,
          alg = credential.algorithm.id,
          privateKey = credential.keyPair.private.encoded,
          created = credential.createdAt.getEpochSecond(),
          zone = credential.zoneId.toString(),
          discoverable = true,
          extensions = CredentialExtensions(),
        )
      }
  }
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
  // override auto-generated equals() and hashCode() methods which do not work correctly since they
  // compare by ref not by content
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
