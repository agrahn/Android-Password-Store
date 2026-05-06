/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.credman

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.webauthn.AuthenticatorAttestationResponse
import androidx.credentials.webauthn.FidoPublicKeyCredential
import androidx.credentials.webauthn.PublicKeyCredentialCreationOptions
import app.passwordstore.Application
import app.passwordstore.R
import app.passwordstore.util.extensions.b64Encode
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.toByteArray
import app.passwordstore.util.passkey.FidoUser
import app.passwordstore.util.passkey.PasskeyCredential
import app.passwordstore.util.services.UDCakeCredentialProviderService
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.kotlinModule
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.runCatching
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.time.Instant
import java.time.ZoneId
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.json.JSONArray
import org.json.JSONObject

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@SuppressLint("RestrictedApi")
object CredmanUtils {

  // COSE identifiers for key types/algorithms
  // https://datatracker.ietf.org/doc/html/rfc9053#name-signature-algorithms
  const val ALG_EDDSA = -8
  const val ALG_ES256 = -7
  const val ALG_RS256 = -257 // https://www.w3.org/TR/webauthn-3/#sctn-encoded-credPubKey-examples

  private val context: Context
    get() = Application.instance.applicationContext

  private val jsonMapper = ObjectMapper(JsonFactory()).registerModule(kotlinModule())

  /**
   * Creates a new pending intent of type [action]
   *
   * @param extra: Additional input parameters put as extra with name
   *   [UDCakeCredentialProviderService.CREDENTIAL_DATA_EXTRA]
   */
  private fun createPendingIntent(action: String, extra: Bundle? = null): PendingIntent {

    val intent = Intent(action).setPackage(context.packageName)

    if (extra != null) {
      intent.putExtra(UDCakeCredentialProviderService.CREDENTIAL_DATA_EXTRA, extra)
    }

    val requestCode = (100000..999999).random()

    return PendingIntent.getActivity(
      context,
      requestCode,
      intent,
      (PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT),
    )
  }

  fun processCreateCredentialRequest(
    request: BeginCreateCredentialRequest
  ): BeginCreateCredentialResponse? {
    return when (request) {
      is BeginCreatePublicKeyCredentialRequest -> {
        handleCreatePasskeyQuery(request)
      }

      else -> {
        null
      }
    }
  }

  private fun handleCreatePasskeyQuery(
    request: BeginCreatePublicKeyCredentialRequest
  ): BeginCreateCredentialResponse {

    return BeginCreateCredentialResponse.Builder()
      .addCreateEntry(
        CreateEntry.Builder(
            context.getString(R.string.key_create_passkey),
            createPendingIntent(UDCakeCredentialProviderService.CREATE_PASSKEY_INTENT_ACTION),
          )
          .setDescription(context.getString(R.string.app_name))
          .setAutoSelectAllowed(true)
          .build()
      )
      .build()
  }

  private fun appInfoToOrigin(info: CallingAppInfo): String {
    val cert = info.signingInfo.apkContentsSigners[0].toByteArray()
    val md = MessageDigest.getInstance("SHA-256")
    val certHash = md.digest(cert)

    // https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json
    val privilegedAllowlistGstatic =
      context.resources.openRawResource(R.raw.apps).bufferedReader().use { it.readText() }
    // https://raw.githubusercontent.com/bitwarden/android/refs/heads/main/app/src/main/assets/fido2_privileged_community.json
    val privilegedAllowlistOther =
      context.resources.openRawResource(R.raw.fido2_privileged_community).bufferedReader().use {
        it.readText()
      }
    // https://raw.githubusercontent.com/bitwarden/android/refs/heads/main/app/src/main/assets/fido2_privileged_google.json
    val privilegedAllowlistGoogle =
      context.resources.openRawResource(R.raw.fido2_privileged_google).bufferedReader().use {
        it.readText()
      }

    val privilegedAllowlist =
      mergeJsonArrays(
        privilegedAllowlistGstatic,
        privilegedAllowlistOther,
        privilegedAllowlistGoogle,
        arrayName = "apps",
        deduplicateByIdPath = "info.package_name",
      )

    return runCatching {
        info.getOrigin(privilegedAllowlist) ?: throw NullPointerException()
      }
      .getOrElse { error ->
        "android:apk-key-hash:${certHash.b64Encode().concatToString()}"
      }
  }

  fun createPasskeyCredential(
    requestOptions: PublicKeyCredentialCreationOptions,
    credentialHexId: String,
  ): PasskeyCredential {
    val preferenceOrderOfAlgorithms = // RP's supported key algorithms, in decending order of
      // preference
      requestOptions.pubKeyCredParams.map { it.alg.toInt() }

    // RP's most preferred algorithm that our app supports, with ALG_ES256 as fallback
    val chosenAlgorithm =
      preferenceOrderOfAlgorithms
        .filter { it in listOf(ALG_EDDSA, ALG_ES256, ALG_RS256) }
        .firstOrNull() ?: ALG_ES256

    val keyPairGenerator =
      when (chosenAlgorithm) {
        ALG_EDDSA -> // EdDSA aka Ed25519, state-of-the-art
        KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider()).also {
            it.initialize(ECGenParameterSpec("ed25519"), SecureRandom())
          }
        ALG_ES256 -> // ES256, still state-of-the-art, create Signature instance with
          // Signature.getInstance("SHA256withECDSA", "BC")
          KeyPairGenerator.getInstance("EC", BouncyCastleProvider()).also {
            it.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
          }
        else -> // RSA-2048, legacy, create Signature instance with
          // Signature.getInstance("SHA256withRSA", "BC")
          KeyPairGenerator.getInstance("RSA", BouncyCastleProvider()).also {
            it.initialize(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4), SecureRandom())
          }
      }

    val keyPair = keyPairGenerator.generateKeyPair()

    return PasskeyCredential(
      credentialId = credentialHexId.hexToByteArray(),
      keyPair = keyPair,
      algorithm = chosenAlgorithm,
      rpId = requestOptions.rp.id,
      user =
        FidoUser(
          id = requestOptions.user.id,
          name = requestOptions.user.name,
          displayName = requestOptions.user.displayName,
        ),
      createdAt = Instant.now(),
      zoneId = ZoneId.systemDefault(),
    )
  }

  /** Serialises any of the supported PublicKeys into the standard WebAuthn CBOR byte array. */
  private fun packPublicKeyToCbor(keyPair: KeyPair): ByteArray =
    keyPair.public.let { publicKey ->
      when (publicKey) {
        is ECPublicKey -> buildEccCose(publicKey as ECPublicKey)
        is RSAPublicKey -> buildRsaCose(publicKey as RSAPublicKey)
        else -> {
          // Java 15+ or BouncyCastle handles Ed25519 under "Ed25519" or "EdDSA" algorithms
          if (
            publicKey.algorithm.equals("Ed25519", ignoreCase = true) ||
              publicKey.algorithm.equals("EdDSA", ignoreCase = true)
          ) {
            buildEd25519Cose(publicKey)
          } else {
            throw IllegalArgumentException("Unsupported key type: ${publicKey.algorithm}")
          }
        }
      }
    }

  /** Packs Ed25519 (EdDSA) public key */
  private fun buildEd25519Cose(key: PublicKey): ByteArray =
    /*
     * A4 -> CBOR map with 4 pairs (0xA0 + 4)
     * 01 key: 1 (key type), 01 value: 1 (OKP)
     * 03 key: 3 (algorithm), 27 value: -8 (EdDSA)
     * 20 key: -1 (curve), 06 value: 6 (Ed25519)
     * 21 key: -2 (x-coordinate), 58 20...  value: byte header (0x58) followed by 32 (0x20) bytes of raw X
     */
    "A4010103272006215820".hexToByteArray() + getRawEd25519Bytes(key)

  private fun getRawEd25519Bytes(key: PublicKey): ByteArray =
    SubjectPublicKeyInfo.getInstance(key.getEncoded()).getPublicKeyData().getOctets()

  /** Packs ECC (NIST P-256 / ES256) public key */
  private fun buildEccCose(key: ECPublicKey): ByteArray {
    // curve points, converted from BigInteger to ByteArray
    val xBytes =
      (ByteArray(32) + key.w.affineX.toByteArray()).let { it.copyOfRange(it.size - 32, it.size) }
    val yBytes =
      (ByteArray(32) + key.w.affineY.toByteArray()).let { it.copyOfRange(it.size - 32, it.size) }

    /*
     * A5 -> CBOR map with 5 pairs (0xA0 + 5)
     * 01 key: 1 (key type), 02 value: 2 (EC2)
     * 03 key: 3 (algorithm), 26 value: -7 (ES256)
     * 20 key: -1 (curve), 01 value: 1 (P-256)
     * 21 key: -2 (x-coordinate), 58 20...  value: byte header (0x58) followed by 32 (0x20) bytes of raw X
     * 22 key: -3 (y-coordinate), 58 20...  value: byte header (0x58) followed by 32 (0x20) bytes of raw Y
     */
    return "A5010203262001215820".hexToByteArray() + xBytes + "225820".hexToByteArray() + yBytes
  }

  /** Packs RSA (RS256) Public Key */
  private fun buildRsaCose(key: RSAPublicKey): ByteArray {
    // extract and normalise modulus (n)
    val modulus = ByteArray(256) + key.modulus.toByteArray()

    // BigInteger.toByteArray() may include a 1-byte sign prefix (257 bytes total),
    // we remove it and prefixed zeros from the head to be exactly 256 bytes.
    val fixedModulus = modulus.copyOfRange(modulus.size - 256, modulus.size)

    // public exponent (e), three bytes
    val exponent = key.publicExponent.toByteArray()

    /*
     * A4 -> CBOR map with 4 pairs (0xa0 + 4)
     * 01 key: 1 (key type), 03 value: 3 (RSA)
     * 03 key: 3 (algorithm), 390100 value: -257 (RS256)
     * 20 key: -1 (Modulus), 59 0100...  value: byte string header indicating 256 bytes (0x590100),
     *    immediately followed by the 256-byte binary RSA modulus.
     * 21 key: -2 (Exponent), 43 value: byte string header indicating 3 bytes (0x43), followed by the exponent,
     *    usually 0x010001, the standard exponent 65537
     */
    return "A401030339010020590100".hexToByteArray() +
      fixedModulus +
      "2143".hexToByteArray() +
      exponent
  }

  fun buildCreatePublicKeyCredentialResponse(
    requestOptions: PublicKeyCredentialCreationOptions,
    credential: PasskeyCredential,
    callingAppInfo: CallingAppInfo?,
    clientDataHash: ByteArray?,
  ): CreatePublicKeyCredentialResponse {
    requireNotNull(callingAppInfo) { "callingAppInfo must not be null here" }

    // to be passed to FidoPublicKeyCredential
    val response =
      AuthenticatorAttestationResponse(
        requestOptions = requestOptions,
        credentialId = credential.credentialId,
        credentialPublicKey = packPublicKeyToCbor(credential.keyPair),
        origin = appInfoToOrigin(callingAppInfo),
        up = true,
        uv = true,
        be = true,
        bs = true,
        packageName = callingAppInfo.packageName,
        clientDataHash = clientDataHash,
      )

    val fidoCredential =
      FidoPublicKeyCredential(
        rawId = credential.credentialId,
        response = response,
        authenticatorAttachment = "platform",
      )

    val credentialJson =
      // this step is required for a successful registration ceremony in chromium browsers
      populateEasyAccessorFields(fidoCredential, credential)

    return CreatePublicKeyCredentialResponse(credentialJson)
  }

  /**
   * "Easily accessing credential data" fields in JSON, as defined in
   * https://github.com/w3c/webauthn/pull/1887, taken from
   * https://github.com/ko-koiwai/MyCredentialManager example
   */
  private fun populateEasyAccessorFields(
    fidoCredential: FidoPublicKeyCredential,
    credential: PasskeyCredential,
  ): String {

    val response =
      jsonMapper.readValue(fidoCredential.json(), CreatePublicKeyCredentialResponseJson::class.java)

    response.response.publicKeyAlgorithm = credential.algorithm.toLong()
    response.response.publicKey = credential.keyPair.public.encoded.b64Encode().concatToString()
    response.response.authenticatorData = getAuthData(credential)

    return jsonMapper.writeValueAsString(response)
  }

  private fun getAuthData(credential: PasskeyCredential): String {
    // all zeros -> our app is not officially registered authenticator
    val AAGUID = "00000000000000000000000000000000" // must have an even length

    val rpIdHash: ByteArray =
      MessageDigest.getInstance("SHA-256").digest(credential.rpId.toByteArray())

    val flags: ByteArray = byteArrayOf(0x5d.toByte())
    val signCount: ByteArray = byteArrayOf(0x00, 0x00, 0x00, 0x00)
    val aaguid = AAGUID.hexToByteArray()
    val credentialIdLength: ByteArray =
      byteArrayOf(0x00, credential.credentialId.size.toByte()) // = 20 bytes
    val credentialPublicKey: ByteArray = packPublicKeyToCbor(credential.keyPair)

    return (rpIdHash +
        flags +
        signCount +
        aaguid +
        credentialIdLength +
        credential.credentialId +
        credentialPublicKey)
      .b64Encode()
      .concatToString()
  }

  private data class CreatePublicKeyCredentialResponseJson(
    // RegistrationResponseJSON
    val id: String,
    val rawId: String,
    val response: Response,
    val authenticatorAttachment: String?,
    val clientExtensionResults: EmptyClass = EmptyClass(),
    val type: String,
  ) {
    data class Response(
      // AuthenticatorAttestationResponseJSON
      val clientDataJSON: String? = null,
      var authenticatorData: String? = null,
      val transports: List<String>? = arrayOf("internal").toList(),
      var publicKey: String? = null, // easy accessors fields
      var publicKeyAlgorithm: Long? = null, // easy accessors fields
      val attestationObject: String?, // easy accessors fields
    )

    class EmptyClass
  }

  private fun mergeJsonArrays(
    vararg jsonStrings: String,
    arrayName: String,
    deduplicateByIdPath: String? = null,
  ): String {
    val arrays = jsonStrings.map {
      JSONObject(it).getJSONArray(arrayName)
    }

    val elementsById = deduplicateByIdPath?.let {
      linkedMapOf<String, JSONObject>()
    }

    val mergedArray = JSONArray()

    arrays.forEach { array ->
      for (i in 0 until array.length()) {
        val element = array.get(i)

        if (elementsById != null && element is JSONObject) {
          val id =
            getNestedValue(element, deduplicateByIdPath)
              ?: "auto_${System.identityHashCode(element)}"
          elementsById[id] = element
        } else {
          mergedArray.put(element)
        }
      }
    }

    // Add deduplicated elements if deduplication was enabled
    elementsById?.let {
      it.values.forEach { mergedArray.put(it) }
    }

    return JSONObject()
      .apply {
        put(arrayName, mergedArray)
      }
      .toString()
  }

  private fun getNestedValue(obj: JSONObject, path: String): String? =
    runCatching {
        val keys = path.split(".")
        var current: Any? = obj

        for (key in keys) {
          current =
            when (current) {
              is JSONObject -> current.opt(key)
              else -> return null
            }

          if (current == null) return null
        }

        current.toString()
      }
      .get()
}
