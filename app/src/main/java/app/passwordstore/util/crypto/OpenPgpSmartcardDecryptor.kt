/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")

package app.passwordstore.util.crypto

import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPKey
import java.io.InputStream
import java.io.OutputStream
import javax.inject.Inject
import org.bouncycastle.bcpg.AEADEncDataPacket
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.PGPDataDecryptor
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder
import org.bouncycastle.util.io.Streams

class OpenPgpSmartcardDecryptor @Inject constructor() {

  fun decrypt(
    key: PGPKey,
    pin: CharArray,
    ciphertextStream: InputStream,
    outputStream: OutputStream,
    card: OpenPgpNfcCard,
    cardFingerprints: List<ByteArray>,
  ) {
    val cert = KeyUtils.tryParseCertificateOrKey(key) ?: throw PGPException("Invalid PGP key")
    val keyIds = keyIdsMatchingCard(cert, cardFingerprints)
    card.verifyUserPin(pin)

    val decoder = PGPUtil.getDecoderStream(ciphertextStream)
    val objectFactory = PGPObjectFactory(decoder, JcaKeyFingerprintCalculator())
    val encryptedDataList =
      generateSequence { objectFactory.nextObject() }
        .filterIsInstance<PGPEncryptedDataList>()
        .firstOrNull() ?: throw PGPException("No encrypted OpenPGP data found")

    val encryptedDataPackets =
      encryptedDataList.asSequence().filterIsInstance<PGPPublicKeyEncryptedData>().toList()
    val explicitMatches = encryptedDataPackets.filter { keyIds.contains(it.keyIdentifier.keyId) }
    val anonymousMatches = encryptedDataPackets.filter {
      it.keyIdentifier.isWildcard || it.keyIdentifier.keyId == 0L
    }
    // Each candidate triggers a card decipher operation. Wildcard-recipient packets (key id 0) all
    // match, so a crafted message could enqueue arbitrarily many; cap the attempts to bound the
    // work a hostile message can push onto the card.
    val candidates = (explicitMatches + anonymousMatches).distinct().take(MAX_DECRYPT_CANDIDATES)
    if (candidates.isEmpty()) throw PGPException("Message is not encrypted to this OpenPGP card")

    val decryptorFactory = OpenPgpCardDecryptorFactory(card)
    var firstFailure: Exception? = null
    val (encryptedData, sessionKey) =
      candidates.firstNotNullOfOrNull { candidate ->
        try {
          candidate to candidate.getSessionKey(decryptorFactory)
        } catch (e: Throwable) {
          if (OpenPgpNfcCard.isTransceiveFailure(e)) throw e
          if (e.isCardAuthenticationFailure()) throw e
          if (firstFailure == null) firstFailure = e as? Exception
          null
        }
      }
        ?: throw PGPException(
          "Message is not encrypted to this OpenPGP card",
          firstFailure,
        )

    // Reject messages that carry no integrity protection (legacy SED packets) outright, matching
    // the default policy of the app's main PGPainless decryption path. Without an MDC/SEIPD the
    // plaintext is unauthenticated and malleable.
    if (!encryptedData.isIntegrityProtected) {
      throw PGPException("Refusing to decrypt OpenPGP message without integrity protection")
    }

    // Streaming decryption necessarily writes the plaintext before verify() can run; [outputStream]
    // is an in-memory buffer the caller must (and does) discard when this method throws.
    encryptedData.getDataStream(JceSessionKeyDataDecryptorFactoryBuilder().build(sessionKey)).use {
      cleartext ->
      pipeLiteralData(cleartext, outputStream)
    }

    if (!encryptedData.verify()) {
      throw PGPException("OpenPGP message integrity check failed")
    }
  }

  private fun Throwable.isCardAuthenticationFailure(): Boolean =
    this is OpenPgpCardStatusException && isAuthenticationFailure ||
      cause?.isCardAuthenticationFailure() == true

  private fun keyIdsMatchingCard(
    cert: org.bouncycastle.openpgp.api.OpenPGPCertificate,
    cardFingerprints: List<ByteArray>,
  ): Set<Long> {
    if (cardFingerprints.isEmpty()) return cert.getAllKeyIdentifiers().map { it.getKeyId() }.toSet()
    val matchingKeyIds =
      cert
        .getAllKeyIdentifiers()
        .filter { keyIdentifier ->
          val fingerprint = keyIdentifier.getFingerprint() ?: return@filter false
          cardFingerprints.any { it.contentEquals(fingerprint) }
        }
        .map { it.getKeyId() }
        .toSet()
    if (matchingKeyIds.isEmpty()) {
      throw PGPException("The selected OpenPGP card does not match this key")
    }
    return matchingKeyIds
  }

  private fun pipeLiteralData(inputStream: InputStream, outputStream: OutputStream) {
    var current = PGPObjectFactory(inputStream, JcaKeyFingerprintCalculator()).nextObject()
    while (current != null) {
      when (current) {
        is PGPCompressedData -> {
          pipeLiteralData(current.dataStream, outputStream)
          return
        }
        is PGPLiteralData -> {
          current.inputStream.use { Streams.pipeAll(it, outputStream) }
          return
        }
        is PGPOnePassSignatureList -> {
          current = PGPObjectFactory(inputStream, JcaKeyFingerprintCalculator()).nextObject()
        }
        else -> throw PGPException("Unsupported OpenPGP cleartext packet")
      }
    }
    throw PGPException("No literal OpenPGP data found")
  }

  private class OpenPgpCardDecryptorFactory(private val card: OpenPgpNfcCard) :
    AbstractPublicKeyDataDecryptorFactory() {

    private val contentDecryptorFactory = BcPublicKeyDataDecryptorFactory(null)

    override fun recoverSessionData(
      keyAlgorithm: Int,
      secKeyData: Array<ByteArray>,
      pkeskVersion: Int,
    ): ByteArray {
      if (
        keyAlgorithm != PublicKeyAlgorithmTags.RSA_ENCRYPT &&
          keyAlgorithm != PublicKeyAlgorithmTags.RSA_GENERAL
      ) {
        throw PGPException("NFC OpenPGP decryption currently supports RSA card subkeys only")
      }
      val mpi = secKeyData.firstOrNull() ?: throw PGPException("Missing encrypted session key")
      if (mpi.size <= 2) throw PGPException("Malformed RSA session key")
      return card.decipher(mpi.copyOfRange(2, mpi.size))
    }

    override fun createDataDecryptor(
      withIntegrityPacket: Boolean,
      encAlgorithm: Int,
      key: ByteArray,
    ): PGPDataDecryptor =
      contentDecryptorFactory.createDataDecryptor(withIntegrityPacket, encAlgorithm, key)

    override fun createDataDecryptor(
      aeadEncDataPacket: AEADEncDataPacket,
      sessionKey: PGPSessionKey,
    ): PGPDataDecryptor = contentDecryptorFactory.createDataDecryptor(aeadEncDataPacket, sessionKey)

    override fun createDataDecryptor(
      seipd: SymmetricEncIntegrityPacket,
      sessionKey: PGPSessionKey,
    ): PGPDataDecryptor = contentDecryptorFactory.createDataDecryptor(seipd, sessionKey)
  }

  private companion object {
    // Upper bound on the number of PKESK packets we will try to decrypt on the card per message.
    private const val MAX_DECRYPT_CANDIDATES = 16
  }
}
