/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.KeyUtils.hasDecKey
import app.passwordstore.crypto.KeyUtils.tryParseCertificateOrKey
import app.passwordstore.crypto.errors.CryptoException
import app.passwordstore.crypto.errors.CryptoHandlerException
import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.crypto.errors.NoKeysProvidedException
import app.passwordstore.crypto.errors.UnknownError
import app.passwordstore.crypto.errors.UnusableKeyException
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.runCatching
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyPair
import java.util.Date
import javax.inject.Inject
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter
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
  CryptoHandler<PGPKey, KeyPair, PGPEncryptOptions, PGPDecryptOptions> {

  private val pgpApi = PGPainless.getInstance()

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
          val openPgpKey = KeyUtils.tryParseCertificateOrKey(key)

          if (openPgpKey !is OpenPGPKey || !hasDecKey(openPgpKey))
            throw NoDecryptionKeyAvailableException("Key not usable for decryption")

          val decKey = extractDecKey(openPgpKey, passphrase) ?: openPgpKey

          val protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase(passphrase))

          consumerOptions.addDecryptionKey(decKey, protector)
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
  ): Result<List<PGPKey>, CryptoException> =
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
            .filter { KeyUtils.isKeyUsable(it) }

        if (certificates.isEmpty() && passphrase == null) throw UnusableKeyException

        val encryptionOptions = EncryptionOptions.encryptCommunications(pgpApi)

        if (passphrase == null) { // public key encryption
          certificates.forEach {
            encryptionOptions.addRecipient(it, EncryptionOptions.encryptToAllCapableSubkeys())
          }
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
        certificates.filter { result.isEncryptedFor(it) }.map { it.getEncoded().let { PGPKey(it) } }
      }
      .mapError { error ->
        when (error) {
          is CryptoException -> error
          else -> UnknownError(error.message, error)
        }
      }

  /** Runs a naive check on the extension for the given [fileName] to check if it is a PGP file. */
  public override fun canHandle(fileName: String): Boolean {
    return fileName.substringAfterLast('.', "") == "gpg"
  }

  /* Tests whether all decryption subkeys of the provided list of PGP keys are passphrase protected,
   * unless option anySubkey = true is given in which case it tests for the existence of at least one
   * protected subkey */
  public override fun isPassphraseProtected(keys: List<PGPKey>, anySubkey: Boolean): Boolean =
    keys
      .mapNotNull { tryParseCertificateOrKey(it) }
      .filter { it.isSecretKey() }
      .let { secretKeys ->
        !secretKeys.isEmpty() &&
          if (anySubkey)
            secretKeys.any {
              (it as OpenPGPKey).getSecretKeys().values.any {
                !it.getPGPSecretKey().isPrivateKeyEmpty() && it.isLocked()
              }
            }
          else
            secretKeys.all {
              (it as OpenPGPKey)
                .getSecretKeys()
                .values
                .filter { it.isEncryptionKey() && !it.getPGPSecretKey().isPrivateKeyEmpty() }
                .all { it.isLocked() }
            }
      }

  public override fun passphraseIsCorrect(
    key: PGPKey,
    passphrase: CharArray?,
    anySubkey: Boolean,
  ): Boolean =
    tryParseCertificateOrKey(key)?.let {
      it is OpenPGPKey &&
        it
          .getSecretKeys()
          .values
          .filter {
            (anySubkey || it.isEncryptionKey()) && !it.getPGPSecretKey().isPrivateKeyEmpty()
          }
          .any { it.isPassphraseCorrect(passphrase) }
    } ?: false

  /* Unlocks the first authentication-capable subkey of the given PGP key with its passphrase and
   * returns the key pair as java.security.KeyPair, which can be used by sshj */
  public override fun unlockJcaAuthKeyPair(
    key: PGPKey,
    passphrase: CharArray?,
  ): Result<KeyPair, CryptoHandlerException> =
    runCatching {
        val openPgpKey = KeyUtils.tryParseCertificateOrKey(key)
        if (openPgpKey !is OpenPGPKey)
          throw NoDecryptionKeyAvailableException("Key not usable for authentication")

        /* A and S subkeys as well as the primary C key are equally suitable for authentication;
         * we pick the first one matching one of the capabilities in the given ranking order */
        val authFlags = listOf(KeyFlags.AUTHENTICATION, KeyFlags.SIGN_DATA, KeyFlags.CERTIFY_OTHER)
        val subkeys = openPgpKey.getSecretKeys().values.toMutableList()
        subkeys.sortByDescending { it.getCreationTime() } // newest first
        val authKeys =
          authFlags
            .map { flag ->
              subkeys
                .filter {
                  it.hasKeyFlags(Date(), flag) && !it.getPGPSecretKey().isPrivateKeyEmpty()
                }
                .firstOrNull()
            }
            .filterNotNull()

        if (authKeys.isEmpty())
          throw NoDecryptionKeyAvailableException(
            "Key does not provide a usable authentication subkey"
          )

        if (!authKeys.first().isPassphraseCorrect(passphrase))
          throw IncorrectPassphraseException(
            "Wrong passphrase; authentication subkey cannot be unlocked"
          )

        val pgpKeyPair = authKeys.first().unlock(passphrase).getKeyPair()
        return@runCatching KeyPair(
          JcaPGPKeyConverter()
            .setProvider(BouncyCastleProvider())
            .getPublicKey(pgpKeyPair.getPublicKey()),
          JcaPGPKeyConverter()
            .setProvider(BouncyCastleProvider())
            .getPrivateKey(pgpKeyPair.getPrivateKey()),
        )
      }
      .mapError { error ->
        when (error) {
          is CryptoHandlerException -> error
          else -> UnknownError(error.message, error)
        }
      }

  private fun extractDecKey(openPgpKey: OpenPGPKey, passphrase: CharArray?): OpenPGPKey? =
    openPgpKey
      .getSecretKeys()
      .values
      .filter { it.isEncryptionKey() && it.isPassphraseCorrect(passphrase) }
      .firstOrNull()
      ?.let {
        OpenPGPKey(
          PGPSecretKeyRing(
            listOf(openPgpKey.getPrimarySecretKey().getPGPSecretKey(), it.getPGPSecretKey())
          )
        )
      }
}
