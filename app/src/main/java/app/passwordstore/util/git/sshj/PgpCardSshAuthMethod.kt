/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git.sshj

import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.CardReader
import app.passwordstore.util.crypto.OpenPgpCardPrompt
import com.hierynomus.sshj.key.KeyAlgorithm
import java.io.IOException
import java.math.BigInteger
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import kotlinx.coroutines.runBlocking
import net.schmizz.sshj.common.Buffer.PlainBuffer
import net.schmizz.sshj.common.DisconnectReason
import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.common.SSHException
import net.schmizz.sshj.common.SSHPacket
import net.schmizz.sshj.userauth.UserAuthException
import net.schmizz.sshj.userauth.keyprovider.KeyProvider
import net.schmizz.sshj.userauth.method.AuthPublickey

/**
 * A [KeyProvider] for a smartcard-backed PGP authentication key. Only the public half is known to
 * the app; the private authentication operation happens on the card (see [CardSshAuthPublickey]),
 * so [getPrivate] is never called and returns null.
 */
class PgpCardSshKeyProvider(private val publicKey: PublicKey) : KeyProvider {
  override fun getPublic(): PublicKey = publicKey

  override fun getPrivate(): PrivateKey? = null

  override fun getType(): KeyType = KeyType.fromKey(publicKey)
}

/**
 * [AuthPublickey] that produces the authentication signature on an OpenPGP smartcard instead of
 * with a local private key. It overrides [putPubKey]/[putSig] to advertise and sign with the
 * *negotiated* public-key algorithm rather than the key's base type: for RSA these differ
 * (`rsa-sha2-512` / `rsa-sha2-256` / `ssh-rsa`), and the algorithm name in the request must match
 * the one in the signature blob. The exact data SSH signs -- `string(session id) ||
 * request-so-far` -- is handed to [signer], which drives the card. Host-key verification and
 * everything else stay on sshj's default path.
 *
 * sshj's [net.schmizz.sshj.userauth.method.KeyedAuthMethod] keeps its chosen [KeyAlgorithm] queue
 * private and drops the head on [shouldRetry] to fall back to the next algorithm. Because the card
 * replaces both [putPubKey] and [putSig], this class tracks the same queue itself so the advertised
 * key algorithm, the signed algorithm, and the retry fallback stay in lockstep.
 */
class CardSshAuthPublickey(
  private val keyProvider: KeyProvider,
  private val signer: CardSshSigner,
) : AuthPublickey(keyProvider) {

  private var algorithms: MutableList<KeyAlgorithm>? = null

  private fun currentAlgorithm(): KeyAlgorithm {
    val queue =
      algorithms
        ?: params.transport
          .getClientKeyAlgorithms(KeyType.fromKey(keyProvider.public))
          .toMutableList()
          .also { algorithms = it }
    return queue.firstOrNull()
      ?: throw UserAuthException(
        "No key algorithm configured for ${KeyType.fromKey(keyProvider.public)}"
      )
  }

  public override fun putPubKey(reqData: SSHPacket): SSHPacket {
    // Public key as 2 strings: [ negotiated key algorithm | key blob ], as sshj's putPubKey does.
    reqData
      .putString(currentAlgorithm().keyAlgorithm)
      .putString(PlainBuffer().putPublicKey(keyProvider.public).compactData)
    return reqData
  }

  public override fun putSig(reqData: SSHPacket): SSHPacket {
    val algorithmName = currentAlgorithm().keyAlgorithm
    val sessionId = params.transport.sessionID
    val dataToSign = PlainBuffer().putString(sessionId).putBuffer(reqData).compactData
    val signature = signer.sign(dataToSign, algorithmName)
    // SSH signature field: string( string(algorithm) ‖ string(signature) ).
    val signatureBlob = PlainBuffer().putString(algorithmName).putString(signature).compactData
    reqData.putString(signatureBlob)
    return reqData
  }

  override fun shouldRetry(): Boolean {
    val queue = algorithms ?: return false
    if (queue.isNotEmpty()) queue.removeAt(0)
    return queue.isNotEmpty()
  }
}

/**
 * Drives an OpenPGP smartcard over NFC to answer an SSH public-key authentication challenge with
 * INTERNAL AUTHENTICATE (PW1 mode 0x82). Mirrors the commit-signing card flow: one reader kept
 * enabled for the operation, a reused present-card dialog, inline PIN entry with the card's own
 * retry counter, and reader mode released only once the card is physically removed.
 */
class CardSshSigner(
  private val activity: FragmentActivity,
  private val dispatcherProvider: DispatcherProvider,
  private val primaryKeyId: KeyId,
  private val publicKey: PublicKey,
) {

  /**
   * Signs [dataToSign] on the card and returns the SSH signature blob. [sshAlgorithmName] is the
   * public-key algorithm the auth request advertised: for Ed25519/ECDSA it equals the key type, but
   * for RSA it is the negotiated `rsa-sha2-512` / `rsa-sha2-256` / `ssh-rsa`, which selects the
   * hash the card signs over.
   */
  fun sign(dataToSign: ByteArray, sshAlgorithmName: String): ByteArray {
    val keyType = KeyType.fromKey(publicKey)
    val cardInput: ByteArray
    val encode: (ByteArray) -> ByteArray
    when (keyType) {
      // Ed25519 signs the message directly and the raw 64-byte R‖S is the SSH signature as-is.
      KeyType.ED25519 -> {
        cardInput = dataToSign
        encode = { raw -> raw }
      }
      // ECDSA signs a hash of the message; the card returns raw r‖s which SSH wants as two mpints.
      KeyType.ECDSA256 -> {
        cardInput = digest("SHA-256", dataToSign)
        encode = { raw -> encodeEcdsaSignature(raw, fieldBytes = 32) }
      }
      KeyType.ECDSA384 -> {
        cardInput = digest("SHA-384", dataToSign)
        encode = { raw -> encodeEcdsaSignature(raw, fieldBytes = 48) }
      }
      KeyType.ECDSA521 -> {
        cardInput = digest("SHA-512", dataToSign)
        encode = { raw -> encodeEcdsaSignature(raw, fieldBytes = 66) }
      }
      // RSA: the card wraps the DigestInfo we supply in PKCS#1 v1.5 padding and returns the raw
      // modulus-sized signature, which is exactly the SSH rsa_signature_blob (string(s), no mpint).
      KeyType.RSA -> {
        cardInput = pkcs1DigestInfo(sshAlgorithmName, dataToSign)
        encode = { raw -> raw }
      }
      else ->
        throw SSHException(
          "Smartcard-based SSH authentication is not yet supported for $keyType keys"
        )
    }
    return encode(driveCard(cardInput))
  }

  private fun driveCard(input: ByteArray): ByteArray {
    val prompt = OpenPgpCardPrompt(activity, R.string.openpgp_nfc_ssh_title, dispatcherProvider)
    var reader: CardReader? = null
    var readerHandedOff = false
    try {
      val activeReader =
        runBlocking { prompt.createReader() }
          ?: throw IOException(activity.getString(R.string.openpgp_nfc_unavailable))
      reader = activeReader
      val outcome =
        runBlocking {
          prompt.runWithPin(
            reader = activeReader,
            cacheKey = "ssh:${primaryKeyId.id}",
            pinTitleRes = R.string.openpgp_card_pin_title,
            pinHintRes = R.string.openpgp_card_pin_hint,
            identityLabel = null,
            // PW1 in mode 0x82 authorises INTERNAL AUTHENTICATE (the auth key slot), unlike PSO:CDS
            // (mode 0x81) used for commit signing.
            pinMode = OpenPgpCardPrompt.PinMode.USER,
            presentMessage = activity.getString(R.string.openpgp_nfc_tap_card),
            commFailedMessage = activity.getString(R.string.openpgp_nfc_card_comm_failed),
          ) { card, currentPin ->
            card.verifyUserPin(currentPin)
            card.internalAuthenticate(input)
          }
        }
      when (outcome) {
        is OpenPgpCardPrompt.CardOutcome.Success -> {
          readerHandedOff = true
          val signature = outcome.value
          // Block until the card is lifted so reader mode stays up (keeping the activity
          // foreground) and the platform never dispatches the card's NDEF URL once the git push
          // proceeds and this activity moves on.
          runBlocking { prompt.awaitCardRemoval(outcome.card, activeReader) }
          return signature
        }
        OpenPgpCardPrompt.CardOutcome.Cancelled -> {
          readerHandedOff = true
          prompt.releaseReaderWhenCardRemoved(null, activeReader)
          throw SSHException(DisconnectReason.AUTH_CANCELLED_BY_USER)
        }
        is OpenPgpCardPrompt.CardOutcome.Blocked -> {
          readerHandedOff = true
          prompt.releaseReaderWhenCardRemoved(outcome.card, activeReader)
          throw SSHException(activity.getString(R.string.openpgp_card_pin_blocked))
        }
        is OpenPgpCardPrompt.CardOutcome.Failed -> {
          readerHandedOff = true
          prompt.releaseReaderWhenCardRemoved(outcome.card, activeReader)
          throw SSHException(outcome.error.message ?: "OpenPGP card authentication failed")
        }
      }
    } finally {
      runBlocking { prompt.dismissDialog() }
      if (!readerHandedOff && reader != null) prompt.releaseReaderWhenCardRemoved(null, reader)
    }
  }

  private fun digest(algorithm: String, data: ByteArray): ByteArray =
    MessageDigest.getInstance(algorithm).digest(data)

  /**
   * Converts the card's raw ECDSA signature (r‖s, each left-padded to [fieldBytes]) into the SSH
   * signature blob `string(mpint r) ‖ string(mpint s)`.
   */
  private fun encodeEcdsaSignature(raw: ByteArray, fieldBytes: Int): ByteArray {
    if (raw.size != fieldBytes * 2) {
      throw SSHException(
        "Unexpected ECDSA signature length ${raw.size} (expected ${fieldBytes * 2})"
      )
    }
    val r = BigInteger(1, raw.copyOfRange(0, fieldBytes))
    val s = BigInteger(1, raw.copyOfRange(fieldBytes, raw.size))
    return PlainBuffer().putMPInt(r).putMPInt(s).compactData
  }

  /**
   * Builds the PKCS#1 v1.5 DigestInfo (ASN.1 DER `hash-algorithm identifier || digest`) that an
   * OpenPGP card expects as the INTERNAL AUTHENTICATE input for an RSA key; the card supplies the
   * surrounding PKCS#1 padding frame and does the modular exponentiation. The hash follows the SSH
   * signature algorithm: `rsa-sha2-512` -> SHA-512, `rsa-sha2-256` -> SHA-256, `ssh-rsa` -> SHA-1.
   */
  private fun pkcs1DigestInfo(sshAlgorithmName: String, dataToSign: ByteArray): ByteArray {
    val (jcaDigest, digestInfoPrefix) =
      when (sshAlgorithmName) {
        "rsa-sha2-512" -> "SHA-512" to SHA512_DIGEST_INFO_PREFIX
        "rsa-sha2-256" -> "SHA-256" to SHA256_DIGEST_INFO_PREFIX
        "ssh-rsa" -> "SHA-1" to SHA1_DIGEST_INFO_PREFIX
        else -> throw SSHException("Unsupported RSA SSH signature algorithm $sshAlgorithmName")
      }
    return digestInfoPrefix + digest(jcaDigest, dataToSign)
  }

  private companion object {
    // DigestInfo DER prefixes from RFC 8017 sec. 9.2 (EMSA-PKCS1-v1_5), prepended to the raw hash.
    val SHA1_DIGEST_INFO_PREFIX =
      byteArrayOf(
        0x30,
        0x21,
        0x30,
        0x09,
        0x06,
        0x05,
        0x2b,
        0x0e,
        0x03,
        0x02,
        0x1a,
        0x05,
        0x00,
        0x04,
        0x14,
      )
    val SHA256_DIGEST_INFO_PREFIX =
      byteArrayOf(
        0x30,
        0x31,
        0x30,
        0x0d,
        0x06,
        0x09,
        0x60,
        0x86.toByte(),
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
        0x01,
        0x05,
        0x00,
        0x04,
        0x20,
      )
    val SHA512_DIGEST_INFO_PREFIX =
      byteArrayOf(
        0x30,
        0x51,
        0x30,
        0x0d,
        0x06,
        0x09,
        0x60,
        0x86.toByte(),
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
        0x03,
        0x05,
        0x00,
        0x04,
        0x40,
      )
  }
}
