/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("BlockingMethodInNonBlockingContext")

package app.passwordstore.crypto

import androidx.annotation.VisibleForTesting
import app.passwordstore.crypto.KeyUtils.isKeyUsable
import app.passwordstore.crypto.KeyUtils.tryGetId
import app.passwordstore.crypto.KeyUtils.tryParseCertificateOrKey
import app.passwordstore.crypto.errors.InvalidKeyException
import app.passwordstore.crypto.errors.KeyAlreadyExistsException
import app.passwordstore.crypto.errors.KeyDeletionFailedException
import app.passwordstore.crypto.errors.KeyDirectoryUnavailableException
import app.passwordstore.crypto.errors.KeyNotFoundException
import app.passwordstore.crypto.errors.NoKeysAvailableException
import app.passwordstore.crypto.errors.UnusableKeyException
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.runCatching
import com.github.michaelbull.result.unwrap
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.CoroutineDispatcher
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.PGPainless
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.util.Passphrase

public class PGPKeyManager
@Inject
constructor(filesDir: String, private val dispatcher: CoroutineDispatcher) :
  KeyManager<PGPKey, PGPIdentifier> {

  private val pgpApi = PGPainless.getInstance()

  private val keyDir = File(filesDir, KEY_DIR_NAME)

  /** @see KeyManager.addKey */
  override fun addKey(key: PGPKey, replace: Boolean): Result<PGPKey, Throwable> = runCatching {
    if (!keyDirExists()) throw KeyDirectoryUnavailableException
    val incomingCertOrKey = tryParseCertificateOrKey(key) ?: throw UnusableKeyException
    val incomingKey = incomingCertOrKey.getEncoded().let { PGPKey(it) }
    if (!isKeyUsable(incomingKey)) throw UnusableKeyException
    val keyFile = File(keyDir, "${tryGetId(incomingCertOrKey)}.$KEY_EXTENSION")
    val existingKey = if (keyFile.exists()) PGPKey(keyFile.readBytes()) else null
    val existingCertOrKey = existingKey?.let { tryParseCertificateOrKey(existingKey) }
    if (existingCertOrKey != null) {
      when {
        !existingCertOrKey.isSecretKey() && incomingCertOrKey.isSecretKey() -> {
          keyFile.writeBytes(incomingKey.contents)
          return@runCatching incomingKey
        }
        !existingCertOrKey.isSecretKey() && !incomingCertOrKey.isSecretKey() -> {
          val updatedCertificate = OpenPGPCertificate.join(existingCertOrKey, incomingCertOrKey)
          val keyBytes = updatedCertificate.toAsciiArmoredString().toByteArray()
          keyFile.writeBytes(keyBytes)
          return@runCatching PGPKey(keyBytes)
        }
      }
      // Check for replace flag first and if it is false, throw an error
      if (!replace)
        throw KeyAlreadyExistsException(
          tryGetId(incomingCertOrKey)?.toString() ?: "Failed to retrieve key ID"
        )
      if (!keyFile.delete()) throw KeyDeletionFailedException
    }

    keyFile.writeBytes(incomingKey.contents)

    incomingKey
  }

  /** @see KeyManager.removeKey */
  override fun removeKey(identifier: PGPIdentifier): Result<Unit, Throwable> = runCatching {
    if (!keyDirExists()) throw KeyDirectoryUnavailableException
    val key = getKeyById(identifier).unwrap()
    val keyFile = File(keyDir, "${tryGetId(key)}.$KEY_EXTENSION")
    if (keyFile.exists()) {
      if (!keyFile.delete()) throw KeyDeletionFailedException
    }
  }

  /** @see KeyManager.generateKey */
  override fun generateKey(userId: String, passphrase: CharArray?): Result<PGPKey, Throwable> =
    runCatching {
      val pgpPassphrase = Passphrase(passphrase)
      // Make a copy because underlying CharArray gets invalidated/nulled upon
      // PGPainless.generateKey()
      val pgpPassphraseCopy = Passphrase(passphrase?.copyOf())

      val secretKeys = pgpApi.generateKey().modernKeyRing(userId, pgpPassphrase)

      val protector = SecretKeyRingProtector.unlockAnyKeyWith(pgpPassphraseCopy)
      var key =
        pgpApi
          .modify(secretKeys)
          .setExpirationDate(null, protector) // never expire
          .done()

      addKey(PGPKey(key.getEncoded()), false).unwrap()
    }

  override fun changeKeyPassphrase(
    identifier: PGPIdentifier,
    oldPassphrase: CharArray?,
    newPassphrase: CharArray?,
  ): Result<PGPKey, Throwable> = runCatching {
    val key = getKeyById(identifier).unwrap()
    val openPgpKey = tryParseCertificateOrKey(key) ?: throw InvalidKeyException
    if (openPgpKey !is OpenPGPKey || !openPgpKey.isSecretKey()) throw InvalidKeyException
    val modifiedOpenPgpKey =
      pgpApi
        .modify(openPgpKey)
        .changePassphraseFromOldPassphrase(Passphrase(oldPassphrase))
        .withSecureDefaultSettings()
        .toNewPassphrase(Passphrase(newPassphrase))
        .done()
        .getEncoded()
    addKey(PGPKey(modifiedOpenPgpKey), true).unwrap()
  }

  /** @see KeyManager.getKeyById */
  override fun getKeyById(id: PGPIdentifier, withArmor: Boolean): Result<PGPKey, Throwable> =
    runCatching {
      if (!keyDirExists()) throw KeyDirectoryUnavailableException
      val keyFiles = keyDir.listFiles()
      if (keyFiles.isNullOrEmpty()) throw NoKeysAvailableException
      val keys = keyFiles.map { file -> PGPKey(file.readBytes()) }

      for (key in keys) {
        val certificateOrKey = tryParseCertificateOrKey(key) ?: continue
        if (
          id is PGPIdentifier.KeyId &&
            certificateOrKey.getAllKeyIdentifiers().any { id.id == it.getKeyId() } ||
            id is PGPIdentifier.UserId &&
              certificateOrKey.getAllUserIds().any {
                id.email == it.getUserId() || id.email == PGPIdentifier.splitUserId(it.getUserId())
              }
        ) {
          if (withArmor)
            return@runCatching PGPKey(certificateOrKey.toAsciiArmoredString().toByteArray())
          else return@runCatching key
        }
      }

      throw KeyNotFoundException("$id")
    }

  /** @see KeyManager.getAllKeys */
  override fun getAllKeys(): Result<List<PGPKey>, Throwable> = runCatching {
    if (!keyDirExists()) throw KeyDirectoryUnavailableException
    val keyFiles = keyDir.listFiles()
    if (keyFiles.isNullOrEmpty()) return@runCatching emptyList()
    keyFiles.map { keyFile -> PGPKey(keyFile.readBytes()) }.toList()
  }

  /** Checks if [keyDir] exists and attempts to create it if not. */
  private fun keyDirExists(): Boolean {
    return keyDir.exists() || keyDir.mkdirs()
  }

  public companion object {

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal const val KEY_DIR_NAME: String = "keys"
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal const val KEY_EXTENSION: String = "key"
  }
}
