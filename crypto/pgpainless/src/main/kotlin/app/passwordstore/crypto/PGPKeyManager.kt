/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("BlockingMethodInNonBlockingContext")

package app.passwordstore.crypto

import androidx.annotation.VisibleForTesting
import app.passwordstore.crypto.KeyUtils.hasSecretKey
import app.passwordstore.crypto.KeyUtils.isKeyUsable
import app.passwordstore.crypto.KeyUtils.tryGetId
import app.passwordstore.crypto.KeyUtils.tryParseKeyring
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
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.pgpainless.PGPainless
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.util.KeyRingUtils
import org.pgpainless.util.ArmorUtils
import org.pgpainless.util.Passphrase

public class PGPKeyManager
@Inject
constructor(filesDir: String, private val dispatcher: CoroutineDispatcher) :
  KeyManager<PGPKey, PGPIdentifier> {

  private val keyDir = File(filesDir, KEY_DIR_NAME)

  /** @see KeyManager.addKey */
  override fun addKey(key: PGPKey, replace: Boolean): Result<PGPKey, Throwable> = runCatching {
    if (!keyDirExists()) throw KeyDirectoryUnavailableException
    if (!isKeyUsable(key)) throw UnusableKeyException
    val keyFile = File(keyDir, "${tryGetId(key)}.$KEY_EXTENSION")
    if (keyFile.exists()) {
      val existingKeyBytes = keyFile.readBytes()
      val existingKey = PGPKey(existingKeyBytes)
      when {
        !hasSecretKey(existingKey) && hasSecretKey(key) -> {
          keyFile.writeBytes(key.contents)
          return@runCatching key
        }
        !hasSecretKey(existingKey) && !hasSecretKey(key) -> {
          val incomingKeyRing = tryParseKeyring(key) ?: throw InvalidKeyException
          val existingKeyRing = tryParseKeyring(existingKey) ?: throw InvalidKeyException
          val updatedPublicKey =
            PGPainless.mergeCertificate(
              existingKeyRing as PGPPublicKeyRing,
              incomingKeyRing as PGPPublicKeyRing,
            )
          val keyBytes = PGPainless.asciiArmor(updatedPublicKey).encodeToByteArray()
          keyFile.writeBytes(keyBytes)
          return@runCatching key
        }
      }
      // Check for replace flag first and if it is false, throw an error
      if (!replace)
        throw KeyAlreadyExistsException(tryGetId(key)?.toString() ?: "Failed to retrieve key ID")
      if (!keyFile.delete()) throw KeyDeletionFailedException
    }

    keyFile.writeBytes(key.contents)

    key
  }

  /** @see KeyManager.generateKey */
  override fun generateKey(userId: String, passphrase: CharArray?): Result<PGPKey, Throwable> =
    runCatching {
      val keyRing = PGPainless.generateKeyRing().modernKeyRing(userId, Passphrase(passphrase))
      val protector = SecretKeyRingProtector.unlockEachKeyWith(Passphrase(passphrase), keyRing)
      val key =
        PGPainless.modifyKeyRing(keyRing).setExpirationDate(null, protector).done().getEncoded()
      addKey(PGPKey(key), false).unwrap()
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

  override fun changeKeyPassphrase(
    identifier: PGPIdentifier,
    oldPassphrase: CharArray?,
    newPassphrase: CharArray?,
  ): Result<PGPKey, Throwable> = runCatching {
    val key = getKeyById(identifier).unwrap()
    val keyRing = PGPainless.readKeyRing().secretKeyRing(key.contents) ?: throw InvalidKeyException
    val modifiedKeyRing =
      PGPainless.modifyKeyRing(keyRing)
        .changePassphraseFromOldPassphrase(Passphrase(oldPassphrase))
        .withSecureDefaultSettings()
        .toNewPassphrase(Passphrase(newPassphrase))
        .done()
        .getEncoded()
    addKey(PGPKey(modifiedKeyRing), true).unwrap()
  }

  /** @see KeyManager.getKeyById */
  override fun getKeyById(id: PGPIdentifier, withArmor: Boolean): Result<PGPKey, Throwable> =
    runCatching {
      if (!keyDirExists()) throw KeyDirectoryUnavailableException
      val keyFiles = keyDir.listFiles()
      if (keyFiles.isNullOrEmpty()) throw NoKeysAvailableException
      val keys = keyFiles.map { file -> PGPKey(file.readBytes()) }

      when (id) {
        is PGPIdentifier.KeyId -> {
          for (key in keys) {
            val keyRing = tryParseKeyring(key) ?: continue
            if (
              KeyRingUtils.keyRingContainsKeyWithId(
                KeyRingUtils.publicKeys(keyRing),
                id.id.toLong(),
              )
            ) {
              if (withArmor) {
                if (keyRing is PGPSecretKeyRing)
                  return@runCatching PGPKey(
                    ArmorUtils.toAsciiArmoredString(keyRing as PGPSecretKeyRing).toByteArray()
                  )
                else
                  return@runCatching PGPKey(
                    ArmorUtils.toAsciiArmoredString(keyRing as PGPPublicKeyRing).toByteArray()
                  )
              } else return@runCatching key
            }
          }
        }
        is PGPIdentifier.UserId -> {
          for (key in keys) {
            val keyRing = tryParseKeyring(key) ?: continue
            if (
              PGPainless.inspectKeyRing(keyRing).userIds.any {
                id.email == it || id.email == PGPIdentifier.splitUserId(it)
              }
            ) {
              if (withArmor) {
                if (keyRing is PGPSecretKeyRing)
                  return@runCatching PGPKey(
                    ArmorUtils.toAsciiArmoredString(keyRing as PGPSecretKeyRing).toByteArray()
                  )
                else
                  return@runCatching PGPKey(
                    ArmorUtils.toAsciiArmoredString(keyRing as PGPPublicKeyRing).toByteArray()
                  )
              } else return@runCatching key
            }
          }
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

  /** @see KeyManager.getKeyId */
  override fun getKeyId(key: PGPKey): PGPIdentifier? = tryGetId(key)

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
