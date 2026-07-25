/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.provider

import app.passwordstore.passkeys.crypto.AssertionResult
import app.passwordstore.passkeys.crypto.AuthenticatorFlags
import app.passwordstore.passkeys.crypto.ClientDataBinding
import app.passwordstore.passkeys.crypto.VerifiedWebAuthnContext
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.storage.PasskeyStorage
import com.github.michaelbull.result.fold
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.Json
import logcat.LogPriority
import logcat.logcat

/** Utility functions for WebAuthn/FIDO2 passkey operations. */
public object PasskeyProviderUtils {

  internal data class CredentialEntryIdentity(val username: String, val displayName: String?)

  /** Shared JSON serializer for WebAuthn protocol messages. */
  public val json: Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
  }

  /** Decodes a base64url-encoded string to bytes. */
  public fun decodeBase64Url(value: String): ByteArray {
    return Base64.getUrlDecoder().decode(value)
  }

  /** Encodes bytes to a base64url string without padding. */
  public fun encodeBase64Url(value: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(value)
  }

  /**
   * Filters credentials based on the allowCredentials list from a WebAuthn request.
   *
   * @param credentials All available credentials
   * @param allowCredentials List of allowed credential IDs from the request
   * @return Filtered list of credentials
   */
  internal fun selectCredentials(
    credentials: List<PasskeyCredential>,
    allowCredentials: List<PublicKeyCredentialDescriptor>,
  ): List<PasskeyCredential> {
    if (allowCredentials.isEmpty()) return credentials
    val allowedIds = allowCredentials.mapTo(hashSetOf()) { it.id }
    return credentials.filter { credential ->
      encodeBase64Url(credential.credentialId) in allowedIds
    }
  }

  internal fun selectCredentialsByMetadata(
    metadata: List<PasskeyMetadata>,
    allowCredentials: List<PublicKeyCredentialDescriptor>,
  ): List<PasskeyMetadata> {
    if (allowCredentials.isEmpty()) return metadata
    val allowedIds = allowCredentials.mapTo(hashSetOf()) { it.id }
    return metadata.filter { meta -> encodeBase64Url(meta.credentialId) in allowedIds }
  }

  internal fun credentialEntryIdentity(metadata: PasskeyMetadata): CredentialEntryIdentity {
    val username = metadata.userName.ifBlank { metadata.userDisplayName.ifBlank { metadata.rpId } }
    val displayName = metadata.userDisplayName.takeIf { it.isNotBlank() && it != username }
    return CredentialEntryIdentity(username, displayName)
  }

  internal fun isAutoSelectAllowed(candidateCount: Int): Boolean = candidateCount == 1

  internal fun credentialIntentUri(credentialId: ByteArray): String =
    "aps-passkey://credential/${encodeBase64Url(credentialId)}"

  internal suspend fun loadStoredIdentity(
    storage: PasskeyStorage,
    metadata: PasskeyMetadata,
  ): PasskeyMetadata {
    if (metadata.userName.isNotBlank() || metadata.userDisplayName.isNotBlank()) return metadata
    return storage
      .loadForSigning(metadata.credentialId)
      .fold(
        success = { credential ->
          credential.use {
            metadata.copy(
              userName = credential.user.name,
              userDisplayName = credential.user.displayName,
            )
          }
        },
        failure = { error ->
          logcat(LogPriority.ERROR) {
            "loadStoredIdentity failed for rpId=${metadata.rpId}, credentialId=${encodeBase64Url(metadata.credentialId)}: ${error.message}"
          }
          metadata
        },
      )
  }

  /**
   * Builds a WebAuthn assertion response JSON for authentication.
   *
   * @param assertion The assertion result from signing
   * @param credential The credential that was used
   * @param requestJson The original request JSON
   * @return JSON-encoded assertion response
   */
  public fun buildAssertionResponse(
    assertion: AssertionResult,
    credential: PasskeyCredential,
    requestJson: String,
  ): String {
    val request = json.decodeFromString<WebAuthnGetRequest>(requestJson)
    return buildAssertionResponse(assertion, credential, request)
  }

  internal fun buildAssertionResponse(
    assertion: AssertionResult,
    credential: PasskeyCredential,
    request: WebAuthnGetRequest,
  ): String {
    val response =
      AssertionResponseJson(
        id = encodeBase64Url(assertion.credentialId),
        rawId = encodeBase64Url(assertion.credentialId),
        type = "public-key",
        response =
          AssertionResponseData(
            clientDataJSON = encodeBase64Url(assertion.clientDataJSON),
            authenticatorData = encodeBase64Url(assertion.authenticatorData),
            signature = encodeBase64Url(assertion.signature),
            userHandle = assertion.userHandle?.let(::encodeBase64Url),
          ),
      )
    return json.encodeToString(response)
  }

  /**
   * Builds a WebAuthn attestation response JSON for credential creation.
   *
   * @param credential The newly created credential
   * @param requestJson The original request JSON
   * @param verifiedContext The verified caller context providing the trusted origin
   * @return JSON-encoded attestation response
   */
  public fun buildAttestationResponse(
    credential: PasskeyCredential,
    requestJson: String,
    verifiedContext: VerifiedWebAuthnContext,
  ): String {
    val request = json.decodeFromString<WebAuthnCreateRequest>(requestJson)
    return buildAttestationResponse(credential, request, verifiedContext)
  }

  internal fun buildAttestationResponse(
    credential: PasskeyCredential,
    request: WebAuthnCreateRequest,
    verifiedContext: VerifiedWebAuthnContext,
  ): String {
    val clientDataBytes =
      when (val binding = verifiedContext.clientDataBinding) {
        is ClientDataBinding.FrameworkHash -> binding.responseClientDataJson
        is ClientDataBinding.ProviderConstructed ->
          buildClientDataJson("webauthn.create", request.challenge, verifiedContext.origin)
            .toByteArray()
      }
    val coseKey = encodeCoseEcPublicKey(credential.publicKey)
    val authData = buildAttestedAuthenticatorData(credential, coseKey)
    val spkiPublicKey = buildSpkiPublicKey(credential.publicKey)
    val response =
      AttestationResponseJson(
        id = encodeBase64Url(credential.credentialId),
        rawId = encodeBase64Url(credential.credentialId),
        type = "public-key",
        response =
          AttestationResponseData(
            clientDataJSON = encodeBase64Url(clientDataBytes),
            attestationObject = encodeBase64Url(buildAttestationObjectFromAuthData(authData)),
            transports = listOf("internal"),
            publicKeyAlgorithm = -7L,
            authenticatorData = encodeBase64Url(authData),
            publicKey = encodeBase64Url(spkiPublicKey),
          ),
      )
    return json.encodeToString(response)
  }

  private fun buildSpkiPublicKey(rawPublicKey: ByteArray): ByteArray {
    require(rawPublicKey.size == 65 && rawPublicKey.first() == 0x04.toByte()) {
      "Expected uncompressed P-256 public key"
    }
    val x = rawPublicKey.copyOfRange(1, 33)
    val y = rawPublicKey.copyOfRange(33, 65)
    val spkiPrefix =
      byteArrayOf(
        0x30,
        0x59,
        0x30,
        0x13,
        0x06,
        0x07,
        0x2A,
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
        0x04,
      )
    return spkiPrefix + x + y
  }

  private fun buildAttestationObjectFromAuthData(authData: ByteArray): ByteArray {
    val fields =
      listOf(
        cborText("fmt") to cborText("none"),
        cborText("attStmt") to cborMap(emptyList()),
        cborText("authData") to cborBytes(authData),
      )
    return cborMap(fields)
  }

  private fun buildClientDataJson(type: String, challenge: String, origin: String): String {
    return json.encodeToString(ClientDataJson(type = type, challenge = challenge, origin = origin))
  }

  private fun buildAttestedAuthenticatorData(
    credential: PasskeyCredential,
    coseKey: ByteArray,
  ): ByteArray {
    require(credential.credentialId.size <= 1023) {
      "Credential ID too large: ${credential.credentialId.size} bytes (max 1023)"
    }
    val rpIdHash = MessageDigest.getInstance("SHA-256").digest(credential.rpId.toByteArray())
    val flags =
      AuthenticatorFlags.build(
        userPresent = true,
        userVerified = true,
        backupEligible = credential.backupEligible,
        backupState = credential.backupState,
        attestedCredentialData = true,
      )
    val signCountBytes =
      byteArrayOf(
        ((credential.signCount shr 24) and 0xFFu).toByte(),
        ((credential.signCount shr 16) and 0xFFu).toByte(),
        ((credential.signCount shr 8) and 0xFFu).toByte(),
        (credential.signCount and 0xFFu).toByte(),
      )
    val aaguid =
      byteArrayOf(
        0x41,
        0x50,
        0x53,
        0x32,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
      )
    val credentialIdLength =
      byteArrayOf(
        ((credential.credentialId.size shr 8) and 0xFF).toByte(),
        (credential.credentialId.size and 0xFF).toByte(),
      )
    return rpIdHash +
      byteArrayOf(flags) +
      signCountBytes +
      aaguid +
      credentialIdLength +
      credential.credentialId +
      coseKey
  }

  private fun encodeCoseEcPublicKey(rawPublicKey: ByteArray): ByteArray {
    require(rawPublicKey.size == 65 && rawPublicKey.first() == 0x04.toByte()) {
      "Expected uncompressed P-256 public key"
    }
    val x = rawPublicKey.copyOfRange(1, 33)
    val y = rawPublicKey.copyOfRange(33, 65)
    val entries =
      listOf(
        cborInt(1) to cborInt(2),
        cborInt(3) to cborNegativeInt(-7),
        cborNegativeInt(-1) to cborInt(1),
        cborNegativeInt(-2) to cborBytes(x),
        cborNegativeInt(-3) to cborBytes(y),
      )
    return cborMap(entries)
  }

  private fun cborMap(entries: List<Pair<ByteArray, ByteArray>>): ByteArray {
    val output = ByteArrayOutputStream()
    output.write(encodeMajorType(5, entries.size.toLong()))
    for ((key, value) in entries) {
      output.write(key)
      output.write(value)
    }
    return output.toByteArray()
  }

  private fun cborText(value: String): ByteArray {
    val bytes = value.toByteArray()
    return encodeMajorType(3, bytes.size.toLong()) + bytes
  }

  private fun cborBytes(value: ByteArray): ByteArray {
    return encodeMajorType(2, value.size.toLong()) + value
  }

  private fun cborInt(value: Int): ByteArray {
    require(value >= 0) { "CBOR unsigned integer must be non-negative, got $value" }
    return encodeMajorType(0, value.toLong())
  }

  private fun cborNegativeInt(value: Int): ByteArray {
    require(value < 0) { "CBOR negative integer must be negative, got $value" }
    return encodeMajorType(1, (-1L - value))
  }

  private fun encodeMajorType(majorType: Int, value: Long): ByteArray {
    require(value >= 0) { "Value must be non-negative, got $value" }
    require(majorType in 0..7) { "Major type must be 0-7, got $majorType" }
    return when {
      value <= 23 -> byteArrayOf(((majorType shl 5) or value.toInt()).toByte())
      value <= 0xFF -> byteArrayOf(((majorType shl 5) or 24).toByte(), value.toByte())
      value <= 0xFFFF ->
        byteArrayOf(
          ((majorType shl 5) or 25).toByte(),
          ((value shr 8) and 0xFF).toByte(),
          (value and 0xFF).toByte(),
        )
      value <= 0xFFFF_FFFFL ->
        byteArrayOf(
          ((majorType shl 5) or 26).toByte(),
          ((value shr 24) and 0xFF).toByte(),
          ((value shr 16) and 0xFF).toByte(),
          ((value shr 8) and 0xFF).toByte(),
          (value and 0xFF).toByte(),
        )
      else ->
        byteArrayOf(
          ((majorType shl 5) or 27).toByte(),
          ((value shr 56) and 0xFF).toByte(),
          ((value shr 48) and 0xFF).toByte(),
          ((value shr 40) and 0xFF).toByte(),
          ((value shr 32) and 0xFF).toByte(),
          ((value shr 24) and 0xFF).toByte(),
          ((value shr 16) and 0xFF).toByte(),
          ((value shr 8) and 0xFF).toByte(),
          (value and 0xFF).toByte(),
        )
    }
  }
}
