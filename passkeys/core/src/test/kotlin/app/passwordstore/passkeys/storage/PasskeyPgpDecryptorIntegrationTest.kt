/*
 * Copyright (C) 2014-2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.crypto.PasskeyDecryptionError
import app.passwordstore.passkeys.crypto.PasskeyPgpDecryptor
import app.passwordstore.passkeys.crypto.PgpUnlockContext
import app.passwordstore.passkeys.security.PasskeyInputLimits
import app.passwordstore.passkeys.security.SensitiveBytes
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.unwrapError
import java.io.File
import java.io.InputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class PasskeyPgpDecryptorIntegrationTest {

  @Test
  fun `decryption no longer uses first key only`() = runBlocking {
    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        var keysTried = mutableListOf<String>()

        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> {
          keysTried.add("key1")
          keysTried.add("key2")
          keysTried.add("key3")
          return Ok(SensitiveBytes(ByteArray(0)))
        }

        override suspend fun decryptFromStream(
          ciphertextStream: InputStream,
          ciphertextLength: Long,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> = Ok(SensitiveBytes(ByteArray(0)))
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? = null
      }

    mockDecryptor.decrypt(file, mockUnlockContext)

    assertEquals(3, mockDecryptor.keysTried.size)
    assertTrue(mockDecryptor.keysTried.contains("key1"))
    assertTrue(mockDecryptor.keysTried.contains("key2"))
    assertTrue(mockDecryptor.keysTried.contains("key3"))
  }

  @Test
  fun `missing secret key returns typed error`() = runBlocking {
    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> {
          return Err(PasskeyDecryptionError.MissingSecretKey(setOf("0x1234567890ABCDEF")))
        }

        override suspend fun decryptFromStream(
          ciphertextStream: InputStream,
          ciphertextLength: Long,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> =
          Err(PasskeyDecryptionError.MissingSecretKey(setOf()))
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? = null
      }

    val result = mockDecryptor.decrypt(file, mockUnlockContext)

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<PasskeyDecryptionError.MissingSecretKey>(error)
    assertEquals(setOf("0x1234567890ABCDEF"), error.recipientIds)
  }

  @Test
  fun `incorrect passphrase returns typed error`() = runBlocking {
    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> {
          return Err(PasskeyDecryptionError.IncorrectPassphrase("0x1234567890ABCDEF"))
        }

        override suspend fun decryptFromStream(
          ciphertextStream: InputStream,
          ciphertextLength: Long,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> =
          Err(PasskeyDecryptionError.MalformedCiphertext)
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? = null
      }

    val result = mockDecryptor.decrypt(file, mockUnlockContext)

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<PasskeyDecryptionError.IncorrectPassphrase>(error)
    assertEquals("0x1234567890ABCDEF", error.keyId)
  }

  @Test
  fun `integrity check failure returns typed error`() = runBlocking {
    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> {
          return Err(PasskeyDecryptionError.IntegrityCheckFailed)
        }

        override suspend fun decryptFromStream(
          ciphertextStream: InputStream,
          ciphertextLength: Long,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> =
          Err(PasskeyDecryptionError.IntegrityCheckFailed)
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? = null
      }

    val result = mockDecryptor.decrypt(file, mockUnlockContext)

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<PasskeyDecryptionError.IntegrityCheckFailed>(error)
    Unit
  }

  @Test
  fun `malformed ciphertext returns typed error`() = runBlocking {
    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> {
          return Err(PasskeyDecryptionError.MalformedCiphertext)
        }

        override suspend fun decryptFromStream(
          ciphertextStream: InputStream,
          ciphertextLength: Long,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> =
          Err(PasskeyDecryptionError.MalformedCiphertext)
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? = null
      }

    val result = mockDecryptor.decrypt(file, mockUnlockContext)

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<PasskeyDecryptionError.MalformedCiphertext>(error)
    Unit
  }

  @Test
  fun `unlock context is invoked for each key attempt`() = runBlocking {
    val unlockAttempts = mutableListOf<String>()

    val mockDecryptor =
      object : PasskeyPgpDecryptor {
        override suspend fun decrypt(
          file: File,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> {
          unlockContext.unlockKey("key1")
          unlockContext.unlockKey("key2")
          return Ok(SensitiveBytes(ByteArray(0)))
        }

        override suspend fun decryptFromStream(
          ciphertextStream: InputStream,
          ciphertextLength: Long,
          unlockContext: PgpUnlockContext,
          limits: PasskeyInputLimits,
        ): Result<SensitiveBytes, PasskeyDecryptionError> = Ok(SensitiveBytes(ByteArray(0)))
      }

    val file = File.createTempFile("test", ".gpg")
    file.deleteOnExit()

    val mockUnlockContext =
      object : PgpUnlockContext {
        override suspend fun unlockKey(keyId: String): CharArray? {
          unlockAttempts.add(keyId)
          return null
        }
      }

    mockDecryptor.decrypt(file, mockUnlockContext)

    assertEquals(2, unlockAttempts.size)
    assertEquals("key1", unlockAttempts[0])
    assertEquals("key2", unlockAttempts[1])
  }
}
