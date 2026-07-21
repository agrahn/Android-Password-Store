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
import app.passwordstore.util.extensions.wipe
import com.github.michaelbull.result.get
import com.github.michaelbull.result.runCatching
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
 * [AuthPublickey] that produces the authentication signature on an OpenPGP smartcard instead of with
 * a local private key. It overrides [putSig] to assemble the exact data SSH signs — `string(session
 * id) ‖ request-so-far` — hand it to [signer], and append the resulting SSH signature blob. Host-key
 * verification and everything else stay on sshj's default path.
 */
class CardSshAuthPublickey(
  keyProvider: KeyProvider,
  private val signer: CardSshSigner,
) : AuthPublickey(keyProvider) {

  public override fun putSig(reqData: SSHPacket): SSHPacket {
    val sessionId = params.transport.sessionID
    val dataToSign = PlainBuffer().putString(sessionId).putBuffer(reqData).compactData
    val (algorithmName, signature) = signer.sign(dataToSign)
    // SSH signature field: string( string(algorithm) ‖ string(signature) ).
    val signatureBlob = PlainBuffer().putString(algorithmName).putString(signature).compactData
    reqData.putString(signatureBlob)
    return reqData
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
   * Signs [dataToSign] on the card and returns the SSH `(algorithm-name, signature-blob)` pair. The
   * algorithm name matches the public-key algorithm sshj advertises for Ed25519/ECDSA keys.
   */
  fun sign(dataToSign: ByteArray): Pair<String, ByteArray> {
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
      else ->
        throw SSHException(
          "Smartcard-based SSH authentication is not yet supported for $keyType keys"
        )
    }
    return keyType.toString() to encode(driveCard(cardInput))
  }

  private fun driveCard(input: ByteArray): ByteArray {
    val prompt = OpenPgpCardPrompt(activity, R.string.openpgp_nfc_ssh_title, dispatcherProvider)
    var reader: CardReader? = null
    var pin: CharArray? = null
    var readerHandedOff = false
    try {
      val cacheKey = "ssh:${primaryKeyId.id}"
      val activeReader =
        runBlocking { prompt.createReader() }
          ?: throw IOException(activity.getString(R.string.openpgp_nfc_unavailable))
      reader = activeReader
      val presentMessage = activity.getString(R.string.openpgp_nfc_tap_card)
      var pinFromCache = false
      var cachePin = false
      var pinErrorMessage: String? = null
      var cardMessage = presentMessage
      prompt.readCachedPin(cacheKey)?.let {
        pin = it
        pinFromCache = true
      }
      while (true) {
        if (pin == null) {
          runBlocking { prompt.dismissDialog() }
          val entry =
            runBlocking {
              prompt.askSecret(
                titleRes = R.string.openpgp_card_pin_title,
                hintRes = R.string.openpgp_card_pin_hint,
                showCacheOption = true,
                errorMessage = pinErrorMessage,
                minLength = OpenPgpCardPrompt.MIN_PIN_LENGTH,
              )
            } ?: throw SSHException(DisconnectReason.AUTH_CANCELLED_BY_USER)
          pin = entry.secret
          cachePin = entry.cache
          pinFromCache = false
          pinErrorMessage = null
          cardMessage = presentMessage
        }
        val currentPin = requireNotNull(pin) { "PIN must be set before contacting the card" }
        // PW1 in mode 0x82 authorises INTERNAL AUTHENTICATE (the auth key slot), unlike PSO:CDS
        // (mode 0x81) used for commit signing.
        val attempt =
          runBlocking {
            prompt.attempt(activeReader, cardMessage) { card ->
              card.verifyUserPin(currentPin)
              card.internalAuthenticate(input)
            }
          }
        when (attempt) {
          is OpenPgpCardPrompt.Attempt.Success -> {
            runBlocking { prompt.dismissDialog() }
            if (!pinFromCache) prompt.storeCachedPin(cacheKey, currentPin, cachePin)
            readerHandedOff = true
            val signature = attempt.value
            // Block until the card is lifted so reader mode stays up (keeping the activity
            // foreground) and the platform never dispatches the card's NDEF URL once the git push
            // proceeds and this activity moves on.
            runBlocking { prompt.awaitCardRemoval(attempt.card, activeReader) }
            return signature
          }
          OpenPgpCardPrompt.Attempt.Cancelled -> {
            readerHandedOff = true
            prompt.releaseReaderWhenCardRemoved(null, activeReader)
            throw SSHException(DisconnectReason.AUTH_CANCELLED_BY_USER)
          }
          is OpenPgpCardPrompt.Attempt.Error -> {
            val e = attempt.error
            if (OpenPgpCardPrompt.isSmartcardPinFailure(e)) {
              prompt.clearCachedPin(cacheKey)
              pin?.wipe()
              pin = null
              pinFromCache = false
              val remaining =
                OpenPgpCardPrompt.smartcardPinRetriesRemaining(e)
                  ?: runCatching { attempt.card?.readUserPinRetries() }.get()
              if (remaining == 0) {
                readerHandedOff = true
                prompt.releaseReaderWhenCardRemoved(attempt.card, activeReader)
                throw SSHException(activity.getString(R.string.openpgp_card_pin_blocked))
              }
              runCatching { attempt.card?.close() }
              pinErrorMessage =
                if (remaining != null) {
                  activity.resources.getQuantityString(
                    R.plurals.openpgp_card_wrong_pin_remaining,
                    remaining,
                    remaining,
                  )
                } else {
                  activity.getString(R.string.openpgp_card_wrong_pin)
                }
            } else if (OpenPgpCardPrompt.isRetryableCardError(e)) {
              // Keep the PIN, ask the user to present the card again.
              runCatching { attempt.card?.close() }
              cardMessage = activity.getString(R.string.openpgp_nfc_card_comm_failed)
            } else {
              readerHandedOff = true
              prompt.releaseReaderWhenCardRemoved(attempt.card, activeReader)
              throw SSHException(e?.message ?: "OpenPGP card authentication failed")
            }
          }
        }
      }
    } finally {
      pin?.wipe()
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
      throw SSHException("Unexpected ECDSA signature length ${raw.size} (expected ${fieldBytes * 2})")
    }
    val r = BigInteger(1, raw.copyOfRange(0, fieldBytes))
    val s = BigInteger(1, raw.copyOfRange(fieldBytes, raw.size))
    return PlainBuffer().putMPInt(r).putMPInt(s).compactData
  }
}
