/*
 * Copyright (C) 2014-2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.passkeys.crypto.PasskeyDecryptionError
import app.passwordstore.passkeys.crypto.PasskeyPgpDecryptor
import app.passwordstore.passkeys.crypto.PgpUnlockContext
import app.passwordstore.passkeys.security.BoundedInputStream
import app.passwordstore.passkeys.security.BoundedSensitiveOutputStream
import app.passwordstore.passkeys.security.PasskeyInputLimits
import app.passwordstore.passkeys.security.SensitiveBytes
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import com.github.michaelbull.result.get
import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.pgpainless.decryption_verification.MessageInspector
import org.pgpainless.exception.WrongPassphraseException

public class PgpainlessPasskeyDecryptor(
  private val cryptoHandler: PGPainlessCryptoHandler,
  private val keyManager: PGPKeyManager,
) : PasskeyPgpDecryptor {

  override suspend fun decrypt(
    file: File,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits,
  ): Result<SensitiveBytes, PasskeyDecryptionError> =
    withContext(Dispatchers.IO) {
      try {
        val fileLen = file.length()
        if (fileLen == 0L) {
          return@withContext Err(PasskeyDecryptionError.MalformedCiphertext)
        }
        if (fileLen > limits.maxCiphertextBytes) {
          return@withContext Err(
            PasskeyDecryptionError.CiphertextTooLarge(fileLen, limits.maxCiphertextBytes)
          )
        }
        val ciphertext =
          file.inputStream().use { fis ->
            val bounded = BoundedInputStream(fis, limits.maxCiphertextBytes)
            bounded.readBoundedBytes(fileLen.toInt())
          }
        try {
          decryptCiphertext(ciphertext, unlockContext, file.name, limits)
        } finally {
          ciphertext.fill(0)
        }
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Unexpected error decrypting ${file.name}: ${e.message}" }
        Err(mapExceptionToError(e))
      }
    }

  override suspend fun decryptFromBytes(
    ciphertext: ByteArray,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits,
  ): Result<SensitiveBytes, PasskeyDecryptionError> =
    withContext(Dispatchers.IO) {
      try {
        if (ciphertext.size > limits.maxCiphertextBytes) {
          return@withContext Err(
            PasskeyDecryptionError.CiphertextTooLarge(
              ciphertext.size.toLong(),
              limits.maxCiphertextBytes,
            )
          )
        }
        decryptCiphertext(ciphertext, unlockContext, "<bytes>", limits)
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Unexpected error decrypting bytes: ${e.message}" }
        Err(mapExceptionToError(e))
      }
    }

  override suspend fun decryptFromStream(
    ciphertextStream: InputStream,
    ciphertextLength: Long,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits,
  ): Result<SensitiveBytes, PasskeyDecryptionError> =
    withContext(Dispatchers.IO) {
      try {
        if (ciphertextLength > limits.maxCiphertextBytes) {
          return@withContext Err(
            PasskeyDecryptionError.CiphertextTooLarge(ciphertextLength, limits.maxCiphertextBytes)
          )
        }
        val ciphertext =
          BoundedInputStream(ciphertextStream, limits.maxCiphertextBytes)
            .readBoundedBytes(ciphertextLength.toInt())
        try {
          decryptCiphertext(ciphertext, unlockContext, "<stream>", limits)
        } finally {
          ciphertext.fill(0)
        }
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Unexpected error decrypting stream: ${e.message}" }
        Err(mapExceptionToError(e))
      }
    }

  private suspend fun decryptCiphertext(
    ciphertext: ByteArray,
    unlockContext: PgpUnlockContext,
    sourceName: String,
    limits: PasskeyInputLimits,
  ): Result<SensitiveBytes, PasskeyDecryptionError> {
    val recipientKeyIds = inspectRecipientKeyIds(ciphertext, limits)
    if (recipientKeyIds.isEmpty()) {
      return Err(PasskeyDecryptionError.NoRecipientPackets)
    }

    val allKeys = keyManager.getAllKeys().get() ?: emptyList()
    val matchingKeys = findMatchingSecretKeys(allKeys, recipientKeyIds)

    if (matchingKeys.isEmpty()) {
      return Err(
        PasskeyDecryptionError.MissingSecretKey(recipientKeyIds.map { it.toString() }.toSet())
      )
    }

    var lastError: PasskeyDecryptionError? = null

    for ((key, keyId) in matchingKeys) {
      val passphrase = unlockContext.unlockKey(keyId.toString())

      try {
        val plaintext = attemptBoundedDecryption(key, passphrase, ciphertext, limits)
        return Ok(plaintext)
      } catch (e: WrongPassphraseException) {
        lastError = PasskeyDecryptionError.IncorrectPassphrase(keyId.toString())
        logcat(LogPriority.DEBUG) {
          "Wrong passphrase for key ${keyId}, trying next matching key"
        }
        continue
      } catch (e: IncorrectPassphraseException) {
        lastError = PasskeyDecryptionError.IncorrectPassphrase(keyId.toString())
        logcat(LogPriority.DEBUG) {
          "Incorrect passphrase for key ${keyId}, trying next matching key"
        }
        continue
      } catch (e: app.passwordstore.passkeys.security.BoundedOutputLimitExceededException) {
        return Err(PasskeyDecryptionError.PlaintextTooLarge(limits.maxPlaintextBytes))
      } catch (e: Exception) {
        lastError = mapExceptionToError(e)
        logcat(LogPriority.DEBUG) {
          "Decryption failed with key ${keyId}: ${e.message}, trying next"
        }
        continue
      } finally {
        passphrase?.fill('\u0000')
      }
    }

    return Err(lastError ?: PasskeyDecryptionError.MalformedCiphertext)
  }

  private fun findMatchingSecretKeys(
    allKeys: List<PGPKey>,
    recipientKeyIds: Set<Long>,
  ): List<Pair<PGPKey, Long>> {
    val matchingKeys = mutableListOf<Pair<PGPKey, Long>>()

    for (key in allKeys) {
      val certOrKey = KeyUtils.tryParseCertificateOrKey(key) ?: continue
      if (certOrKey !is OpenPGPKey) continue
      if (!KeyUtils.isSecretKey(certOrKey)) continue
      if (!KeyUtils.hasDecKey(certOrKey)) continue

      val secretKeyIds = certOrKey.getSecretKeys().keys.map { it.getKeyId() }.toSet()

      for (recipientId in recipientKeyIds) {
        if (secretKeyIds.contains(recipientId)) {
          matchingKeys.add(key to recipientId)
          break
        }
      }
    }

    return matchingKeys
  }

  private fun attemptBoundedDecryption(
    key: PGPKey,
    passphrase: CharArray?,
    ciphertext: ByteArray,
    limits: PasskeyInputLimits,
  ): SensitiveBytes {
    val inputStream = ByteArrayInputStream(ciphertext)
    val outputStream = BoundedSensitiveOutputStream(limits.maxPlaintextBytes.toInt())

    try {
      cryptoHandler
        .decrypt(
          key = key,
          passphrase = passphrase,
          ciphertextStream = inputStream,
          outputStream = outputStream,
          options = PGPDecryptOptions.Builder().build(),
        )
        .fold(
          success = {
            return outputStream.transferOwnership()
          },
          failure = { throw it },
        )
    } catch (e: app.passwordstore.passkeys.security.BoundedOutputLimitExceededException) {
      throw e
    } finally {
      outputStream.close()
    }

    throw IllegalStateException("Decryption failed without exception")
  }

  private fun mapExceptionToError(e: Exception): PasskeyDecryptionError {
    return when (e) {
      is WrongPassphraseException,
      is IncorrectPassphraseException -> PasskeyDecryptionError.IncorrectPassphrase("unknown")
      is org.pgpainless.exception.MessageNotIntegrityProtectedException ->
        PasskeyDecryptionError.IntegrityCheckFailed
      is app.passwordstore.passkeys.security.BoundedOutputLimitExceededException ->
        PasskeyDecryptionError.PlaintextTooLarge(e.maxBytes)
      is org.bouncycastle.openpgp.PGPException -> {
        if (e.message?.contains("modification detection code") == true) {
          PasskeyDecryptionError.IntegrityCheckFailed
        } else {
          PasskeyDecryptionError.MalformedCiphertext
        }
      }
      else -> PasskeyDecryptionError.MalformedCiphertext
    }
  }
}

internal fun inspectRecipientKeyIds(
  ciphertext: ByteArray,
  limits: PasskeyInputLimits = PasskeyInputLimits.DEFAULT,
): Set<Long> {
  return try {
    if (ciphertext.size > limits.maxCiphertextBytes) {
      return emptySet()
    }
    val info =
      MessageInspector().determineEncryptionInfoForMessage(ByteArrayInputStream(ciphertext))
    info.keyIds.toSet()
  } catch (e: Exception) {
    logcat("PgpainlessPasskeyDecryptor", LogPriority.WARN) {
      "Failed to extract recipient key IDs: ${e.message}"
    }
    emptySet()
  }
}
