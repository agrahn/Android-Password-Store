/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.crypto

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.security.SensitiveBytes
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.time.Clock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.ec.CustomNamedCurves

public class ES256CryptoHandler : PasskeyCryptoHandler {

  private val secureRandom = SecureRandom()

  private val p256Spec: ECParameterSpec by lazy {
    val gen = KeyPairGenerator.getInstance("EC")
    gen.initialize(ECGenParameterSpec("secp256r1"))
    (gen.generateKeyPair().public as ECPublicKey).params
  }

  private val p256BcCurve by lazy { CustomNamedCurves.getByName("secp256r1") }

  private fun loadPrivateKey(keyBytes: ByteArray): java.security.PrivateKey {
    val keyFactory = KeyFactory.getInstance("EC")
    return if (keyBytes.size == 32) {
      val d = BigInteger(1, keyBytes)
      val n = p256BcCurve.n
      require(d >= BigInteger.ONE && d < n) { "Private key scalar out of valid range" }
      val keySpec = ECPrivateKeySpec(d, p256Spec)
      keyFactory.generatePrivate(keySpec)
    } else {
      keyFactory.generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }
  }

  private fun bigIntegerTo32Bytes(value: BigInteger): ByteArray {
    val bytes = value.toByteArray()
    return when {
      bytes.size == 32 -> bytes
      bytes.size == 33 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, 33)
      bytes.size < 32 -> ByteArray(32 - bytes.size) + bytes
      else -> bytes.copyOfRange(bytes.size - 32, bytes.size)
    }
  }

  override fun generateKeyPair(): Pair<ByteArray, ByteArray> {
    val keyPairGenerator = KeyPairGenerator.getInstance("EC")
    keyPairGenerator.initialize(ECGenParameterSpec("secp256r1"), secureRandom)
    val keyPair = keyPairGenerator.generateKeyPair()

    val publicKeyBytes =
      SubjectPublicKeyInfo.getInstance(keyPair.public.encoded).publicKeyData.bytes
    val privateKeyBytes = bigIntegerTo32Bytes((keyPair.private as ECPrivateKey).s)

    return Pair(privateKeyBytes, publicKeyBytes)
  }

  override fun sign(
    privateKey: ByteArray,
    authenticatorData: ByteArray,
    clientDataHash: ByteArray,
  ): Result<ByteArray, Throwable> {
    if (privateKey.isEmpty()) return Err(IllegalArgumentException("Private key cannot be empty"))
    if (authenticatorData.isEmpty())
      return Err(IllegalArgumentException("Authenticator data cannot be empty"))
    if (clientDataHash.isEmpty())
      return Err(IllegalArgumentException("Client data hash cannot be empty"))

    return try {
      val privateKeyObj = loadPrivateKey(privateKey)

      val dataToSign = authenticatorData + clientDataHash

      val signature = Signature.getInstance("SHA256withECDSA")
      signature.initSign(privateKeyObj)
      signature.update(dataToSign)
      val derSignature = signature.sign()

      Ok(derSignature)
    } catch (e: Exception) {
      Err(e)
    }
  }

  override fun verify(
    publicKey: ByteArray,
    signature: ByteArray,
    authenticatorData: ByteArray,
    clientDataHash: ByteArray,
  ): Result<Boolean, Throwable> {
    if (publicKey.isEmpty()) return Err(IllegalArgumentException("Public key cannot be empty"))
    if (signature.isEmpty()) return Err(IllegalArgumentException("Signature cannot be empty"))
    if (authenticatorData.isEmpty())
      return Err(IllegalArgumentException("Authenticator data cannot be empty"))
    if (clientDataHash.isEmpty())
      return Err(IllegalArgumentException("Client data hash cannot be empty"))

    return try {
      val keyFactory = KeyFactory.getInstance("EC")
      val keySpec = X509EncodedKeySpec(unwrapRawPublicKey(publicKey))
      val publicKeyObj = keyFactory.generatePublic(keySpec)

      val dataToVerify = authenticatorData + clientDataHash

      val sig = Signature.getInstance("SHA256withECDSA")
      sig.initVerify(publicKeyObj)
      sig.update(dataToVerify)
      Ok(sig.verify(signature))
    } catch (e: Exception) {
      Err(e)
    }
  }

  override fun createCredential(
    rpId: String,
    userId: ByteArray,
    userName: String,
    userDisplayName: String,
    challenge: ByteArray,
  ): Result<CreatedPasskeyCredential, Throwable> {
    if (rpId.isBlank()) return Err(IllegalArgumentException("RP ID cannot be blank"))
    if (userId.isEmpty()) return Err(IllegalArgumentException("User ID cannot be empty"))

    return try {
      val (privateKey, publicKey) = generateKeyPair()
      val sensitivePrivateKey = SensitiveBytes(privateKey)
      try {
        val credentialId = generateCredentialId()

        val publicCredential =
          PasskeyCredential(
            credentialId = credentialId,
            publicKey = publicKey,
            rpId = rpId,
            user = FidoUser(id = userId, name = userName, displayName = userDisplayName),
            signCount = 0u,
            createdAt = Clock.System.now(),
            transports = listOf("internal"),
            uvInitialized = true,
          )

        Ok(CreatedPasskeyCredential(publicCredential, sensitivePrivateKey))
      } catch (e: Throwable) {
        sensitivePrivateKey.close()
        throw e
      }
    } catch (e: Exception) {
      Err(e)
    }
  }

  override fun getAssertion(
    credential: PasskeyCredential,
    privateKey: ByteArray,
    rpId: String,
    challenge: ByteArray,
    origin: String,
    userVerified: Boolean,
  ): Result<AssertionResult, Throwable> {
    if (rpId.isBlank()) return Err(IllegalArgumentException("RP ID cannot be blank"))
    if (challenge.isEmpty()) return Err(IllegalArgumentException("Challenge cannot be empty"))
    if (origin.isBlank()) return Err(IllegalArgumentException("Origin cannot be blank"))
    if (privateKey.isEmpty()) return Err(IllegalArgumentException("Credential has no private key"))

    return try {
      val authenticatorData =
        buildAuthenticatorData(
          rpId,
          credential.signCount,
          credential.backupEligible,
          credential.backupState,
          userVerified,
        )
      val (clientDataJson, clientDataHash) = buildClientData(challenge, origin, "webauthn.get")

      sign(privateKey, authenticatorData, clientDataHash)
        .fold(
          success = { signature ->
            Ok(
              AssertionResult(
                credentialId = credential.credentialId,
                authenticatorData = authenticatorData,
                signature = signature,
                userHandle = credential.user.id,
                clientDataJSON = clientDataJson.toByteArray(),
              )
            )
          },
          failure = { Err(it) },
        )
    } catch (e: Exception) {
      Err(e)
    }
  }

  override fun getAssertionWithFrameworkHash(
    credential: PasskeyCredential,
    privateKey: ByteArray,
    rpId: String,
    clientDataHash: ByteArray,
    responseClientDataJson: ByteArray,
    userVerified: Boolean,
  ): Result<AssertionResult, Throwable> {
    if (rpId.isBlank()) return Err(IllegalArgumentException("RP ID cannot be blank"))
    if (clientDataHash.size != 32)
      return Err(
        IllegalArgumentException(
          "Framework clientDataHash must be exactly 32 bytes, got ${clientDataHash.size}"
        )
      )
    if (responseClientDataJson.isEmpty())
      return Err(IllegalArgumentException("Response client data JSON cannot be empty"))
    if (privateKey.isEmpty()) return Err(IllegalArgumentException("Credential has no private key"))

    return try {
      val authenticatorData =
        buildAuthenticatorData(
          rpId,
          credential.signCount,
          credential.backupEligible,
          credential.backupState,
          userVerified,
        )

      sign(privateKey, authenticatorData, clientDataHash)
        .fold(
          success = { signature ->
            Ok(
              AssertionResult(
                credentialId = credential.credentialId,
                authenticatorData = authenticatorData,
                signature = signature,
                userHandle = credential.user.id,
                clientDataJSON = responseClientDataJson,
              )
            )
          },
          failure = { Err(it) },
        )
    } catch (e: Exception) {
      Err(e)
    }
  }

  override fun signAssertion(
    privateKey: ByteArray,
    authenticatorData: ByteArray,
    clientDataHash: ByteArray,
  ): Result<ByteArray, Throwable> {
    return sign(privateKey, authenticatorData, clientDataHash)
  }

  override fun derivePublicKey(privateKey: ByteArray): Result<ByteArray, Throwable> {
    return try {
      val d = BigInteger(1, privateKey)
      val n = p256BcCurve.n
      require(d >= BigInteger.ONE && d < n) { "Private key scalar out of valid range" }
      val q = p256BcCurve.g.multiply(d).normalize()
      Ok(q.getEncoded(false))
    } catch (e: Exception) {
      Err(e)
    }
  }

  private fun generateCredentialId(): ByteArray {
    val idBytes = ByteArray(32)
    secureRandom.nextBytes(idBytes)
    return idBytes
  }

  private fun buildAuthenticatorData(
    rpId: String,
    signCount: ULong,
    backupEligible: Boolean,
    backupState: Boolean,
    userVerified: Boolean = true,
  ): ByteArray {
    val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
    val flags =
      AuthenticatorFlags.build(
        userPresent = true,
        userVerified = userVerified,
        backupEligible = backupEligible,
        backupState = backupState,
      )
    val signCountBytes =
      byteArrayOf(
        ((signCount shr 24) and 0xFFu).toByte(),
        ((signCount shr 16) and 0xFFu).toByte(),
        ((signCount shr 8) and 0xFFu).toByte(),
        (signCount and 0xFFu).toByte(),
      )
    return rpIdHash + flags + signCountBytes
  }

  private fun buildClientData(
    challenge: ByteArray,
    origin: String,
    type: String,
  ): Pair<String, ByteArray> {
    val clientDataJson =
      Json.encodeToString(
        JsonObject.serializer(),
        buildJsonObject {
          put("type", type)
          put(
            "challenge",
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(challenge),
          )
          put("origin", origin)
          put("crossOrigin", false)
        },
      )
    return Pair(
      clientDataJson,
      MessageDigest.getInstance("SHA-256").digest(clientDataJson.toByteArray()),
    )
  }

  private fun unwrapRawPublicKey(rawPublicKey: ByteArray): ByteArray {
    require(rawPublicKey.size == 65 && rawPublicKey.first() == 0x04.toByte()) {
      "Expected 65-byte uncompressed P-256 public key starting with 0x04, got ${rawPublicKey.size} bytes starting with 0x${rawPublicKey.first().toInt().and(0xFF).toString(16)}"
    }
    return P256_EC_OID_PREFIX + rawPublicKey
  }

  public companion object {
    public const val FLAG_USER_PRESENT: Byte = AuthenticatorFlags.FLAG_USER_PRESENT
    public const val FLAG_USER_VERIFIED: Byte = AuthenticatorFlags.FLAG_USER_VERIFIED
    public const val FLAG_ATTESTED_CREDENTIAL_DATA: Byte =
      AuthenticatorFlags.FLAG_ATTESTED_CREDENTIAL_DATA

    private val P256_EC_OID_PREFIX =
      byteArrayOf(
        0x30,
        0x59,
        0x30,
        0x13,
        0x06,
        0x07,
        0x2A.toByte(),
        0x86.toByte(),
        0x48,
        0xCE.toByte(),
        0x3D,
        0x02,
        0x01,
        0x06,
        0x08,
        0x2A.toByte(),
        0x86.toByte(),
        0x48,
        0xCE.toByte(),
        0x3D,
        0x03,
        0x01,
        0x07,
        0x03,
        0x42,
        0x00,
      )
  }
}
