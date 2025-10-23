/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.KeyUtils.tryParseCertificateOrKey
import app.passwordstore.crypto.errors.CryptoHandlerException
import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.crypto.errors.NoKeysProvidedException
import app.passwordstore.crypto.errors.UnknownError
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.runCatching
import java.io.InputStream
import java.io.OutputStream
import javax.inject.Inject
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.exception.MissingDecryptionMethodException
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.util.Passphrase

public class PGPainlessCryptoHandler @Inject constructor() :
  CryptoHandler<PGPKey, PGPEncryptOptions, PGPDecryptOptions> {

  private val pgpApi = PGPainless.getInstance()

  public override fun passphraseIsCorrect(key: PGPKey, passphrase: CharArray?): Boolean =
    tryParseCertificateOrKey(key)?.let {
      if (it is OpenPGPKey)
        it.getSecretKey(it.getEncryptionKeys().first()).isPassphraseCorrect(passphrase)
      else false
    } ?: false

  /**
   * Decrypts the given [ciphertextStream] using [PGPainless] and writes the decrypted output to
   * [outputStream]. The provided [passphrase] is wrapped in a [SecretKeyRingProtector].
   *
   * @see CryptoHandler.decrypt
   */
  public override fun decrypt(
    key: PGPKey?,
    passphrase: CharArray?,
    ciphertextStream: InputStream,
    outputStream: OutputStream,
    options: PGPDecryptOptions,
  ): Result<Unit, CryptoHandlerException> =
    runCatching {
        if (key == null && passphrase == null) throw NoKeysProvidedException
        val consumerOptions = ConsumerOptions.get(pgpApi)
        if (key == null) {
          // ciphertextStream may be symmetrically encrypted
          consumerOptions.addMessagePassphrase(Passphrase(passphrase))
        } else {
          val protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase(passphrase))
          val openPgpKey = KeyUtils.tryParseCertificateOrKey(key)
          if (openPgpKey !is OpenPGPKey || openPgpKey.getEncryptionKeys().isEmpty())
            throw NoDecryptionKeyAvailableException("Key not usable for decryption")
          consumerOptions.addDecryptionKey(openPgpKey, protector)
        }

        val decryptionStream =
          pgpApi.processMessage().onInputStream(ciphertextStream).withOptions(consumerOptions)
        decryptionStream.use { Streams.pipeAll(it, outputStream) }

        return@runCatching
      }
      .mapError { error ->
        when (error) {
          is MissingDecryptionMethodException -> {
            if (key == null) // wrong passphrase provided for symmetric decryption
             IncorrectPassphraseException(error.message, error.cause)
            else NoDecryptionKeyAvailableException(error.message, error.cause)
          }
          is WrongPassphraseException -> IncorrectPassphraseException(error.message, error.cause)
          is CryptoHandlerException -> error
          else -> UnknownError(error.message, error)
        }
      }

  /**
   * Encrypts the provided [plaintextStream] and writes the encrypted output to [outputStream]. If a
   * [passphrase] is provided, [keys] are ignored and [plaintextStream] is symmetrically encrypted.
   * For asymmetric encryption the [keys] argument is defensively checked to contain at least one
   * key.
   *
   * @see CryptoHandler.encrypt
   */
  public override fun encrypt(
    keys: List<PGPKey>,
    passphrase: CharArray?,
    plaintextStream: InputStream,
    outputStream: OutputStream,
    options: PGPEncryptOptions,
  ): Result<Unit, CryptoHandlerException> =
    runCatching {
        if (keys.isEmpty() && passphrase == null) throw NoKeysProvidedException

        val certificates = // retrieve all recipients public encryption keys
          keys
            .mapNotNull(KeyUtils::tryParseCertificateOrKey)
            .mapNotNull { certOrKey ->
              when (certOrKey) {
                is OpenPGPKey -> certOrKey.toCertificate()
                else -> certOrKey
              }
            }
            .filter { !it.getEncryptionKeys().isEmpty() }
        require(keys.isEmpty() || keys.size == certificates.size) {
          "Failed to parse all keys: ${keys.size} keys were provided but only ${certificates.size} were valid"
        }

        val encryptionOptions = EncryptionOptions.encryptCommunications(pgpApi)

        if (passphrase == null) { // public key encryption
          certificates.forEach { encryptionOptions.addRecipient(it) }
        } else { // symmetric (with password) encryption
          encryptionOptions
            .overrideEncryptionMechanism(
              MessageEncryptionMechanism.integrityProtected(SymmetricKeyAlgorithmTags.AES_256)
            )
            .addMessagePassphrase(Passphrase(passphrase))
        }

        val producerOptions =
          ProducerOptions.encrypt(encryptionOptions)
            .setAsciiArmor(options.isOptionEnabled(PGPEncryptOptions.ASCII_ARMOR))

        val encryptionStream =
          pgpApi.generateMessage().onOutputStream(outputStream).withOptions(producerOptions)
        encryptionStream.use { Streams.pipeAll(plaintextStream, it) }

        val result = encryptionStream.result
        certificates.forEach { cert ->
          require(result.isEncryptedFor(cert)) {
            "Stream should be encrypted for ${cert.getKeyIdentifier().getKeyId()} but wasn't"
          }
        }
      }
      .mapError { error ->
        when (error) {
          is CryptoHandlerException -> error
          else -> UnknownError(error.message, error)
        }
      }

  /** Runs a naive check on the extension for the given [fileName] to check if it is a PGP file. */
  public override fun canHandle(fileName: String): Boolean {
    return fileName.substringAfterLast('.', "") == "gpg"
  }

  public override fun isPassphraseProtected(keys: List<PGPKey>): Boolean =
    keys.map { key -> KeyUtils.hasSecretKey(key) && !passphraseIsCorrect(key, null) }.all { it }
}
