/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.model

import app.passwordstore.passkeys.cbor.Cbor
import app.passwordstore.passkeys.cbor.CborMap
import app.passwordstore.passkeys.cbor.CborValue
import app.passwordstore.passkeys.cbor.toCborIntegerArray
import java.math.BigInteger
import kotlin.time.Instant
import logcat.LogPriority
import logcat.logcat
import org.bouncycastle.crypto.ec.CustomNamedCurves

public data class StoredCredential(
  val id: ByteArray,
  val rp: RelyingParty,
  val user: User,
  val signCount: UInt,
  val alg: Int,
  val privateKey: ByteArray,
  val publicKey: ByteArray? = null,
  val created: Long,
  val discoverable: Boolean = true,
  val extensions: Extensions = Extensions(),
  val backupEligible: Boolean = true,
  val backupState: Boolean = false,
) : AutoCloseable {

  @Volatile private var wiped = false

  public fun wipe() {
    privateKey.fill(0)
    publicKey?.fill(0)
    id.fill(0)
    user.id.fill(0)
    extensions.credRandom?.fill(0)
    wiped = true
  }

  override fun close() {
    wipe()
  }

  override fun toString(): String =
    "StoredCredential(id=<redacted>, rp=$'$'{rp}, signCount=$'$'{signCount}, alg=$'$'{alg}, privateKey=<REDACTED>, publicKey=${'$'}{publicKey?.let { \"<present>\" } ?: \"<null>\"}, created=$'$'{created})"

  public fun toCbor(): ByteArray {
    val map = mutableMapOf<String, CborValue>()
    map["id"] = id.toCborIntegerArray()
    map["rp"] = CborValue.Map(rp.toCborMap())
    map["user"] = CborValue.Map(user.toCborMap())
    map["sign_count"] = CborValue.UnsignedInteger(BigInteger.valueOf(signCount.toLong()))
    map["alg"] = CborValue.NegativeInteger(BigInteger.valueOf(alg.toLong()))
    map["private_key"] = privateKey.toCborIntegerArray()
    publicKey?.let { map["public_key"] = it.toCborIntegerArray() }
      ?: run { map["public_key"] = CborValue.Null }
    map["created"] = CborValue.UnsignedInteger(BigInteger.valueOf(created))
    map["discoverable"] = if (discoverable) CborValue.True else CborValue.False
    map["extensions"] = CborValue.Map(extensions.toCborMap())
    map["backup_eligible"] = if (backupEligible) CborValue.True else CborValue.False
    map["backup_state"] = if (backupState) CborValue.True else CborValue.False
    return Cbor.fromMap(CborMap.from(map)).toBytes()
  }

  public fun toPasskeyCredential(): PasskeyCredential {
    return PasskeyCredential(
      credentialId = id,
      publicKey = publicKey ?: deriveP256PublicKey(privateKey),
      rpId = rp.id,
      user = FidoUser(id = user.id, name = user.name ?: "", displayName = user.displayName ?: ""),
      signCount = signCount.toULong(),
      createdAt = Instant.fromEpochSeconds(created),
      transports = listOf("internal"),
      uvInitialized = true,
      backupEligible = backupEligible,
      backupState = backupState,
    )
  }

  public fun credentialIdHex(): String {
    return id.joinToString("") { byte -> "%02x".format(byte) }
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
    if (publicKey != null) {
      if (other.publicKey == null) return false
      if (!publicKey.contentEquals(other.publicKey)) return false
    } else if (other.publicKey != null) return false
    if (created != other.created) return false
    if (discoverable != other.discoverable) return false
    if (extensions != other.extensions) return false
    if (backupEligible != other.backupEligible) return false
    if (backupState != other.backupState) return false
    return true
  }

  override fun hashCode(): Int {
    var result = id.contentHashCode()
    result = 31 * result + rp.hashCode()
    result = 31 * result + user.hashCode()
    result = 31 * result + signCount.hashCode()
    result = 31 * result + alg
    result = 31 * result + privateKey.contentHashCode()
    result = 31 * result + (publicKey?.contentHashCode() ?: 0)
    result = 31 * result + created.hashCode()
    result = 31 * result + discoverable.hashCode()
    result = 31 * result + extensions.hashCode()
    result = 31 * result + backupEligible.hashCode()
    result = 31 * result + backupState.hashCode()
    return result
  }

  public companion object {
    public const val ALG_ES256: Int = -7

    private val p256Curve by lazy { CustomNamedCurves.getByName("secp256r1") }

    public fun deriveP256PublicKey(privateKeyScalar: ByteArray): ByteArray {
      val n = p256Curve.n
      val d = BigInteger(1, privateKeyScalar)
      require(d >= BigInteger.ONE && d < n) { "Private key scalar out of valid range" }
      return p256Curve.g.multiply(d).normalize().getEncoded(false)
    }

    public fun fromCbor(bytes: ByteArray): StoredCredential {
      val map = Cbor.parse(bytes).asMap()

      val id = map.getBytes("id") ?: throw IllegalArgumentException("Missing 'id' field")
      val rpMap = map.getMap("rp") ?: throw IllegalArgumentException("Missing 'rp' field")
      val userMap = map.getMap("user") ?: throw IllegalArgumentException("Missing 'user' field")
      val signCount =
        map.getLong("sign_count")?.toUInt()
          ?: throw IllegalArgumentException("Missing 'sign_count' field")
      val alg = map.getInt("alg") ?: throw IllegalArgumentException("Missing 'alg' field")
      val rawPrivateKey =
        map.getBytes("private_key") ?: throw IllegalArgumentException("Missing 'private_key' field")
      val privateKey =
        if (rawPrivateKey.size < 32) {
          ByteArray(32 - rawPrivateKey.size) + rawPrivateKey
        } else {
          rawPrivateKey
        }
      val rawPublicKey = if (map.isNull("public_key")) null else map.getBytes("public_key")
      val publicKey =
        if (rawPublicKey != null) {
          try {
            val derived = deriveP256PublicKey(privateKey)
            if (!derived.contentEquals(rawPublicKey)) {
              logcat(LogPriority.WARN) {
                "Stored public key does not match derived key, re-deriving from private scalar"
              }
              null
            } else {
              rawPublicKey
            }
          } catch (_: Exception) {
            logcat(LogPriority.WARN) {
              "Failed to derive public key for validation, will re-derive"
            }
            null
          }
        } else {
          null
        }
      val created =
        map.getLong("created") ?: throw IllegalArgumentException("Missing 'created' field")
      val discoverable = map.getBoolean("discoverable") ?: true
      val extensionsMap = map.getMap("extensions")
      val backupEligible = map.getBoolean("backup_eligible") ?: true
      val backupState = map.getBoolean("backup_state") ?: false

      return StoredCredential(
        id = id,
        rp = RelyingParty.fromCborMap(rpMap),
        user = User.fromCborMap(userMap),
        signCount = signCount,
        alg = alg,
        privateKey = privateKey,
        publicKey = publicKey,
        created = created,
        discoverable = discoverable,
        extensions = extensionsMap?.let { Extensions.fromCborMap(it) } ?: Extensions(),
        backupEligible = backupEligible,
        backupState = backupState,
      )
    }

    public fun metadataFromCbor(bytes: ByteArray): PasskeyMetadata {
      val map = Cbor.parse(bytes).asMap()

      val id = map.getBytes("id") ?: throw IllegalArgumentException("Missing 'id' field")
      val rpMap = map.getMap("rp") ?: throw IllegalArgumentException("Missing 'rp' field")
      val userMap = map.getMap("user")
      val signCount = map.getLong("sign_count")?.toULong() ?: 0uL
      val created = map.getLong("created") ?: 0L
      val backupEligible = map.getBoolean("backup_eligible") ?: true
      val backupState = map.getBoolean("backup_state") ?: false

      val rpId = rpMap.getString("id") ?: throw IllegalArgumentException("Missing 'rp.id' field")
      val userName =
        if (userMap != null && !userMap.isNull("name")) userMap.getString("name") ?: "" else ""
      val userDisplayName =
        if (userMap != null && !userMap.isNull("display_name"))
          userMap.getString("display_name") ?: ""
        else ""

      return PasskeyMetadata(
        credentialId = id,
        rpId = rpId,
        userName = userName,
        userDisplayName = userDisplayName,
        createdAt = kotlin.time.Instant.fromEpochSeconds(created),
        signCount = signCount,
        backupEligible = backupEligible,
        backupState = backupState,
      )
    }

    public fun fromPasskeyCredential(
      credential: PasskeyCredential,
      privateKey: ByteArray,
    ): StoredCredential {
      return StoredCredential(
        id = credential.credentialId.copyOf(),
        rp = RelyingParty(id = credential.rpId, name = null),
        user =
          User(
            id = credential.user.id.copyOf(),
            name = credential.user.name,
            displayName = credential.user.displayName,
          ),
        signCount = credential.signCount.toUInt(),
        alg = ALG_ES256,
        privateKey = privateKey.copyOf(),
        publicKey = credential.publicKey.copyOf(),
        created = credential.createdAt.epochSeconds,
        discoverable = true,
        extensions = Extensions(),
        backupEligible = credential.backupEligible,
        backupState = credential.backupState,
      )
    }
  }
}

public data class RelyingParty(val id: String, val name: String? = null) {
  public fun toCborMap(): CborMap {
    val map = mutableMapOf<String, CborValue>()
    map["id"] = CborValue.TextString(id)
    name?.let { map["name"] = CborValue.TextString(it) } ?: run { map["name"] = CborValue.Null }
    return CborMap.from(map)
  }

  public companion object {
    public fun fromCborMap(map: CborMap): RelyingParty {
      return RelyingParty(
        id = map.getString("id") ?: throw IllegalArgumentException("Missing 'rp.id' field"),
        name = if (map.isNull("name")) null else map.getString("name"),
      )
    }
  }
}

public data class User(
  val id: ByteArray,
  val name: String? = null,
  val displayName: String? = null,
) {
  public fun toCborMap(): CborMap {
    val map = mutableMapOf<String, CborValue>()
    map["id"] = id.toCborIntegerArray()
    name?.let { map["name"] = CborValue.TextString(it) } ?: run { map["name"] = CborValue.Null }
    displayName?.let { map["display_name"] = CborValue.TextString(it) }
      ?: run { map["display_name"] = CborValue.Null }
    return CborMap.from(map)
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is User) return false
    if (!id.contentEquals(other.id)) return false
    if (name != other.name) return false
    if (displayName != other.displayName) return false
    return true
  }

  override fun hashCode(): Int {
    var result = id.contentHashCode()
    result = 31 * result + (name?.hashCode() ?: 0)
    result = 31 * result + (displayName?.hashCode() ?: 0)
    return result
  }

  public companion object {
    public fun fromCborMap(map: CborMap): User {
      return User(
        id = map.getBytes("id") ?: throw IllegalArgumentException("Missing 'user.id' field"),
        name = if (map.isNull("name")) null else map.getString("name"),
        displayName = if (map.isNull("display_name")) null else map.getString("display_name"),
      )
    }
  }
}

public data class Extensions(
  val credProtect: Int? = null,
  val hmacSecret: Boolean? = null,
  val credRandom: ByteArray? = null,
) {
  public fun toCborMap(): CborMap {
    val map = mutableMapOf<String, CborValue>()
    credProtect?.let {
      map["cred_protect"] = CborValue.UnsignedInteger(BigInteger.valueOf(it.toLong()))
    } ?: run { map["cred_protect"] = CborValue.Null }
    hmacSecret?.let { map["hmac_secret"] = if (it) CborValue.True else CborValue.False }
      ?: run { map["hmac_secret"] = CborValue.Null }
    credRandom?.let { map["cred_random"] = it.toCborIntegerArray() }
    return CborMap.from(map)
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is Extensions) return false
    if (credProtect != other.credProtect) return false
    if (hmacSecret != other.hmacSecret) return false
    if (credRandom != null) {
      if (other.credRandom == null) return false
      if (!credRandom.contentEquals(other.credRandom)) return false
    } else if (other.credRandom != null) return false
    return true
  }

  override fun hashCode(): Int {
    var result = credProtect ?: 0
    result = 31 * result + (hmacSecret?.hashCode() ?: 0)
    result = 31 * result + (credRandom?.contentHashCode() ?: 0)
    return result
  }

  public companion object {
    public fun fromCborMap(map: CborMap): Extensions {
      return Extensions(
        credProtect = if (map.isNull("cred_protect")) null else map.getInt("cred_protect"),
        hmacSecret = if (map.isNull("hmac_secret")) null else map.getBoolean("hmac_secret"),
        credRandom = map.getBytes("cred_random"),
      )
    }
  }
}
