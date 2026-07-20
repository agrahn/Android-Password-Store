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
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import androidx.credentials.webauthn.AuthenticatorAssertionResponse
import androidx.credentials.webauthn.AuthenticatorAttestationResponse
import androidx.credentials.webauthn.FidoPublicKeyCredential
import androidx.credentials.webauthn.PublicKeyCredentialCreationOptions
import app.passwordstore.Application
import app.passwordstore.R
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import app.passwordstore.util.extensions.b64Decode
import app.passwordstore.util.extensions.b64Encode
import app.passwordstore.util.extensions.base64
import app.passwordstore.util.extensions.credentialUsernames
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.passwordHistory
import app.passwordstore.util.extensions.toByteArray
import app.passwordstore.util.passkey.Algorithm
import app.passwordstore.util.passkey.PasskeyCredential
import app.passwordstore.util.services.UDCakeCredentialProviderService
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.runCatching
import java.nio.file.Paths
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
import kotlin.io.path.name
import kotlin.io.path.nameWithoutExtension
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import logcat.logcat
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider

@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
@SuppressLint("RestrictedApi")
object CredmanUtils {

  public val json: Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
  }

  private val context: Context
    get() = Application.instance.applicationContext

  /* Creates a new pending intent of type [action]
   *
   * @param [extra]: Additional input parameters put as extra with name
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
        BeginCreateCredentialResponse.Builder()
          .addCreateEntry(
            CreateEntry(
              accountName = UDCakeCredentialProviderService.ACCOUNT_ID,
              pendingIntent =
                createPendingIntent(UDCakeCredentialProviderService.CREATE_PASSKEY_INTENT_ACTION),
            )
          )
          .build()
      }
      else -> {
        null
      }
    }
  }

  fun processGetCredentialRequest(request: BeginGetCredentialRequest): BeginGetCredentialResponse {
    val callingPackageInfo = request.callingAppInfo
    val callingPackageName = callingPackageInfo?.packageName.orEmpty()
    val credentialEntries: MutableList<CredentialEntry> = mutableListOf()

    for (option in request.beginGetCredentialOptions) {
      when (option) {
        is BeginGetPublicKeyCredentialOption -> {
          credentialEntries.addAll(populatePasskeyData(callingPackageInfo, option))
        }
        else -> {
          logcat { "Request options of type ${option::class.qualifiedName} are not implemented" }
        }
      }
    }

    return BeginGetCredentialResponse(credentialEntries)
  }

  private fun populatePasskeyData(
    callingAppInfo: CallingAppInfo?,
    option: BeginGetPublicKeyCredentialOption,
  ): List<CredentialEntry> {

    val passkeyEntries = mutableListOf<CredentialEntry>()
    val requestOptions =
      json.decodeFromString<PublicKeyCredentialRequestOptions>(option.requestJson)

    val allowCredentialsHex = requestOptions.allowCredentials.map { it.idHex() }

    val passkeyCandidates = mutableListOf<String>()
    val repoPath = PasswordRepository.getRepositoryDirectory().absolutePath

    /* First, try to find valid passkey file canditates in Password Store by credential hex ID;
     * expired passkeys (deleted on the RP's side but still existing in APS) will not be listed */
    allowCredentialsHex.forEach { id ->
      passkeyCandidates.addAll(
        PasswordRepository.findFilesByName(
          rootPath = repoPath,
          fileName = "${id}.gpg",
          ignoreCase = true,
        )
      )
    }

    /* If User did not specify a username, RP sends an empty allowCredentials array. In this case
     * we try to find passkey file canditates by RP ID */
    if (allowCredentialsHex.isEmpty()) {
      passkeyCandidates.addAll(
        PasswordRepository.findFilesByParentName(
            rootPath = repoPath,
            parentName = requestOptions.rpId,
            ignoreCase = true,
          )
          .filter { file ->
            Paths.get(file).nameWithoutExtension.matches("[a-fA-F0-9]{64}".toRegex())
          }
      )
    }

    /*
        // redundant, since we set lastUsedTime on each PublicKeyCredentialEntry
        passkeyCandidates.sortByDescending {
          context.passwordHistory.getString(it.base64(), null)?.toLongOrNull() ?: 0L
        }
    */

    passkeyCandidates.forEach { passkeyPath ->
      val credentialHexId = Paths.get(passkeyPath).nameWithoutExtension
      val shortenedHexId = credentialHexId.take(7)
      val displayPath =
        PasswordRepository.getParentPath(passkeyPath, repoPath) + shortenedHexId + "…"

      val displayUser =
        context.credentialUsernames.getString(credentialHexId, null)?.let {
          AESEncryption.decrypt(it.toCharArray(), keyType = KeyType.PERSISTENT)?.concatToString()
        } ?: shortenedHexId

      val lastUsedTime =
        context.passwordHistory
          .getString(passkeyPath.base64(), null)
          ?.let { it.toLongOrNull() ?: 0L }
          ?.let { Instant.ofEpochMilli(it) }

      val data = Bundle()
      data.putString(UDCakeCredentialProviderService.CREDENTIAL_PATH, passkeyPath)
      passkeyEntries.add(
        PublicKeyCredentialEntry.Builder(
            context = context,
            username = displayPath,
            pendingIntent =
              createPendingIntent(
                UDCakeCredentialProviderService.GET_PASSKEY_INTENT_ACTION,
                data,
              ),
            beginGetPublicKeyCredentialOption = option,
          )
          .setDisplayName(displayUser)
          .also { builder -> lastUsedTime?.let { builder.setLastUsedTime(it) } }
          .build()
      )
    }

    return passkeyEntries
  }

  fun appInfoToOrigin(info: CallingAppInfo): String {
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

  // find RP's most preferred algorithm that our app supports, with ES256 as fallback
  fun getPreferredAlgorithm(requestOptions: PublicKeyCredentialCreationOptions): Algorithm {
    // RP's supported key algorithms, in decending order of preference
    val preferenceOrderOfAlgorithms =
      requestOptions.pubKeyCredParams.mapNotNull { Algorithm.fromId(it.alg.toInt()) }

    return preferenceOrderOfAlgorithms.firstOrNull() ?: Algorithm.ES256
  }

  // Serialises any of the supported PublicKeys into the standard WebAuthn CBOR byte array
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

  // Packs Ed25519 (EdDSA) public key
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

  // Packs ECC (NIST P-256 / ES256) public key
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

  // Packs RSA (RS256) Public Key
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
    credentialHexId: String,
    callingAppInfo: CallingAppInfo?,
    clientDataHash: ByteArray?,
  ): Pair<PasskeyCredential, CreatePublicKeyCredentialResponse> {
    requireNotNull(callingAppInfo) { "callingAppInfo must not be null here" }

    val credentialId = credentialHexId.hexToByteArray()

    val chosenAlgorithm = getPreferredAlgorithm(requestOptions)

    val keyPairGenerator =
      when (chosenAlgorithm) {
        Algorithm.EDDSA -> // EdDSA aka Ed25519, state-of-the-art
        KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider()).also {
            it.initialize(ECGenParameterSpec("ed25519"), SecureRandom())
          }
        Algorithm.ES256 -> // ECDSA using P-256 and SHA-256, still state-of-the-art
        KeyPairGenerator.getInstance("EC", BouncyCastleProvider()).also {
            it.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
          }
        else -> // RSA-2048, legacy
        KeyPairGenerator.getInstance("RSA", BouncyCastleProvider()).also {
            it.initialize(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4), SecureRandom())
          }
      }

    val keyPair = keyPairGenerator.generateKeyPair()
    val publicKeyCbor = packPublicKeyToCbor(keyPair)

    val passkey =
      PasskeyCredential.createNew(
        credentialId = credentialId,
        rpId = requestOptions.rp.id,
        rpName = requestOptions.rp.name,
        userId = requestOptions.user.id,
        userName = requestOptions.user.name,
        userDisplayName = requestOptions.user.displayName,
        algorithm = chosenAlgorithm,
        keyPair = keyPair,
      )

    // to be passed to FidoPublicKeyCredential
    val response =
      AuthenticatorAttestationResponse(
        requestOptions = requestOptions,
        credentialId = credentialId,
        credentialPublicKey = publicKeyCbor,
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
        rawId = credentialId,
        response = response,
        authenticatorAttachment = "platform",
      )

    val credentialJson =
      // this step is required for a successful registration ceremony in chromium browsers
      populateEasyAccessorFields(fidoCredential, passkey, keyPair.public, publicKeyCbor)

    return passkey to CreatePublicKeyCredentialResponse(credentialJson)
  }

  /**
   * "Easily accessing credential data" fields in JSON, as defined in
   * https://github.com/w3c/webauthn/pull/1887, taken from
   * https://github.com/ko-koiwai/MyCredentialManager example
   */
  private fun populateEasyAccessorFields(
    fidoCredential: FidoPublicKeyCredential,
    passkey: PasskeyCredential,
    publicKey: PublicKey,
    publicKeyCbor: ByteArray,
  ): String {

    val response =
      json.decodeFromString<CreatePublicKeyCredentialResponseJson>(fidoCredential.json())

    response.response.publicKeyAlgorithm = passkey.alg.toLong()
    response.response.publicKey = publicKey.encoded.b64Encode().concatToString()
    response.response.authenticatorData = getAuthData(passkey, publicKeyCbor)

    return json.encodeToString(response)
  }

  private fun getAuthData(passkey: PasskeyCredential, publicKeyCbor: ByteArray): String {
    // all zeros -> our app is not officially registered authenticator
    val AAGUID = "00000000000000000000000000000000" // must have an even length

    val rpIdHash: ByteArray =
      MessageDigest.getInstance("SHA-256").digest(passkey.rp.id.toByteArray())

    val flags: ByteArray = byteArrayOf(0x5d.toByte())
    val signCount: ByteArray = byteArrayOf(0x00, 0x00, 0x00, 0x00)
    val aaguid = AAGUID.hexToByteArray()
    val credentialIdLength: ByteArray = byteArrayOf(0x00, passkey.id.size.toByte())

    return (rpIdHash + flags + signCount + aaguid + credentialIdLength + passkey.id + publicKeyCbor)
      .b64Encode()
      .concatToString()
  }

  @Serializable
  private data class CreatePublicKeyCredentialResponseJson(
    // RegistrationResponseJSON
    @SerialName("id") val id: String,
    @SerialName("rawId") val rawId: String,
    @SerialName("response") val response: Response,
    @SerialName("authenticatorAttachment") val authenticatorAttachment: String?,
    @SerialName("clientExtensionResults") val clientExtensionResults: EmptyClass = EmptyClass(),
    @SerialName("type") val type: String,
  ) {
    @Serializable
    data class Response(
      // AuthenticatorAttestationResponseJSON
      @SerialName("clientDataJSON") val clientDataJSON: String? = null,
      @SerialName("authenticatorData") var authenticatorData: String? = null,
      @SerialName("transports") val transports: List<String>? = arrayOf("internal").toList(),
      @SerialName("publicKey") var publicKey: String? = null, // easy accessors fields
      @SerialName("publicKeyAlgorithm")
      var publicKeyAlgorithm: Long? = null, // easy accessors fields
      @SerialName("attestationObject") val attestationObject: String?, // easy accessors fields
    )

    @Serializable class EmptyClass
  }

  /* Our version that parses `allowCredentials` list from request; Android's version
   * misses to do that */
  @Serializable
  private data class PublicKeyCredentialRequestOptions(
    @SerialName("challenge") val challenge: String = "",
    @SerialName("timeout") val timeout: Long = 0,
    @SerialName("rpId") val rpId: String = "",
    @SerialName("allowCredentials")
    val allowCredentials: List<PublicKeyCredentialDescriptor> = emptyList(),
    @SerialName("userVerification") val userVerification: String = "",
  ) {
    @Serializable
    data class PublicKeyCredentialDescriptor(
      @SerialName("id") val id: String = "",
      @SerialName("type") val type: String = "",
      @SerialName("transports") val transports: List<String> = emptyList(),
    ) {
      fun idHex(): String? = id.toCharArray().b64Decode()?.toHexString()
    }
  }

  fun buildGetCredentialResponse(
    providerRequest: ProviderGetCredentialRequest,
    passkey: PasskeyCredential,
  ): Result<GetCredentialResponse, Throwable> = runCatching {
    val origin = appInfoToOrigin(providerRequest.callingAppInfo)
    val packageName = providerRequest.callingAppInfo.packageName

    val publicKeyRequest = providerRequest.credentialOptions.first() as GetPublicKeyCredentialOption
    val requestOptions =
      androidx.credentials.webauthn.PublicKeyCredentialRequestOptions(publicKeyRequest.requestJson)

    val response =
      AuthenticatorAssertionResponse(
        requestOptions = requestOptions,
        credentialId = passkey.id,
        origin = origin,
        up = true,
        uv = true,
        be = true,
        bs = true,
        userHandle = passkey.user.id,
        packageName = packageName,
        clientDataHash = publicKeyRequest.clientDataHash,
      )

    val signature = passkey.signData(response.dataToSign()).getOrThrow()

    response.signature = signature

    val fidoCredential =
      FidoPublicKeyCredential(
        rawId = passkey.id,
        response = response,
        authenticatorAttachment = "platform",
      )

    val passkeyCredential = PublicKeyCredential(fidoCredential.json())
    GetCredentialResponse(passkeyCredential)
  }

  private fun mergeJsonArrays(
    vararg jsonStrings: String,
    arrayName: String,
    deduplicateByIdPath: String? = null,
  ): String {
    // Parse all inputs safely into JsonObjects and extract the target arrays
    val arrays = jsonStrings.map {
      Json.parseToJsonElement(it).jsonObject[arrayName]?.jsonArray ?: JsonArray(emptyList())
    }

    // Track deduplicated elements if a path is provided
    val elementsById = deduplicateByIdPath?.let { linkedMapOf<String, JsonObject>() }
    // Track non-object elements or elements mixed in when deduplication is disabled
    val rawElements = mutableListOf<JsonElement>()

    arrays.forEach { array ->
      array.forEach { element ->
        if (elementsById != null && element is JsonObject) {
          // Find ID using the path picker, fallback to memory identity hash code if missing
          val id =
            getNestedValue(element, deduplicateByIdPath)
              ?: "auto_${System.identityHashCode(element)}"
          elementsById[id] = element
        } else {
          rawElements.add(element)
        }
      }
    }

    // Construct the immutable payload using structural builders
    val finalJson = buildJsonObject {
      put(
        arrayName,
        buildJsonArray {
          // Add raw/non-deduplicated elements first to mimic original logic behavior
          rawElements.forEach { add(it) }
          // Add your deduplicated objects
          elementsById?.values?.forEach { add(it) }
        },
      )
    }

    return finalJson.toString()
  }

  private fun getNestedValue(obj: JsonObject, path: String): String? {
    val keys = path.split(".")
    var current: JsonElement? = obj

    for (key in keys) {
      current =
        when (current) {
          is JsonObject -> current[key]
          else -> return null
        }
      if (current == null) return null
    }

    // Safely unwrap json primitives to string literal text (avoids double quotes)
    return when (current) {
      is JsonPrimitive -> current.content
      else -> current.toString()
    }
  }
}
