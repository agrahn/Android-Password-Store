/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.crypto.CryptoHandler
import app.passwordstore.crypto.CryptoOptions
import app.passwordstore.passkeys.crypto.PasskeyDecryptionError
import app.passwordstore.passkeys.crypto.PasskeyPgpDecryptor
import app.passwordstore.passkeys.crypto.PgpUnlockContext
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import app.passwordstore.passkeys.model.StoredCredential
import app.passwordstore.passkeys.security.PasskeyConcurrencyLimiter
import app.passwordstore.passkeys.security.PasskeyInputLimits
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.io.ByteArrayInputStream
import java.io.File
import kotlin.time.Instant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat

public class FilePasskeyStorage<
  Key,
  Identifier,
  KeyPair,
  EncOpts : CryptoOptions,
  DecryptOpts : CryptoOptions,
>(
  private val repositoryRoot: File,
  private val cryptoHandler: CryptoHandler<Key, Identifier, KeyPair, EncOpts, DecryptOpts>,
  private val passkeyPgpDecryptor: PasskeyPgpDecryptor,
  private val pgpUnlockContext: PgpUnlockContext,
  private val recipientResolver: PassRecipientResolver<Key>,
  private val encryptionOptions: EncOpts,
  private val config: PasskeyStorageConfig = PasskeyStorageConfig(),
  private val inputLimits: PasskeyInputLimits = PasskeyInputLimits.DEFAULT,
  private val concurrencyLimiter: PasskeyConcurrencyLimiter = PasskeyConcurrencyLimiter.DEFAULT,
  private val atomicWriter: DefaultAtomicCredentialWriter =
    DefaultAtomicCredentialWriter(repositoryRoot),
  private val generationProvider: RepositoryGenerationProvider? = null,
  private val confinedStore: NoFollowFileStore =
    NoFollowFileStore(
      repositoryRoot,
      config.passkeyDirectory,
      config.fileExtension,
      atomicWriter,
      inputLimits,
      generationProvider,
    ),
) : PasskeyStorage {

  private val passkeyDir: File
    get() = File(repositoryRoot, config.passkeyDirectory)

  override suspend fun listMetadata(rpId: String?): Result<List<PasskeyMetadata>, Throwable> =
    withContext(Dispatchers.IO) {
      confinedStore
        .scanMetadata(rpId)
        .fold(
          success = { scanned ->
            Ok(
              scanned.map { file ->
                PasskeyMetadata(
                  credentialId = file.ref.credentialId.copyOf(),
                  rpId = file.ref.canonicalRpId,
                  userName = "",
                  userDisplayName = "",
                  createdAt = Instant.fromEpochMilliseconds(file.lastModifiedMillis),
                  signCount = 0u,
                  fileLastModified = file.lastModifiedMillis,
                )
              }
            )
          },
          failure = { error ->
            logcat(LogPriority.ERROR) { "Metadata scan failed: ${error.message}" }
            mapScanError(error)
          },
        )
    }

  override suspend fun listMetadataWithRefs(
    rpId: String?
  ): Result<List<PasskeyMetadataWithRef>, Throwable> =
    withContext(Dispatchers.IO) {
      confinedStore
        .scanMetadata(rpId)
        .fold(
          success = { scanned ->
            val results = mutableListOf<PasskeyMetadataWithRef>()
            for (file in scanned) {
              val versionResult =
                confinedStore
                  .resolveVersion(file.ref)
                  .fold(
                    success = { it },
                    failure = { null },
                  )
              val version =
                when (versionResult) {
                  is SourceVersionResult.Stable -> versionResult.version
                  else -> null
                }
              results.add(
                PasskeyMetadataWithRef(
                  metadata =
                    PasskeyMetadata(
                      credentialId = file.ref.credentialId.copyOf(),
                      rpId = file.ref.canonicalRpId,
                      userName = "",
                      userDisplayName = "",
                      createdAt = Instant.fromEpochMilliseconds(file.lastModifiedMillis),
                      signCount = 0u,
                      fileLastModified = file.lastModifiedMillis,
                    ),
                  fileRef = file.ref,
                  sourceVersion = version,
                )
              )
            }
            Ok(results)
          },
          failure = { error -> mapScanError(error) },
        )
    }

  override suspend fun loadForSigning(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable> =
    withContext(Dispatchers.IO) {
      val scanResult = confinedStore.scanMetadata(null)
      scanResult.fold(
        success = { scanned ->
          val matches = scanned.filter { it.ref.credentialId.contentEquals(credentialId) }
          if (matches.isEmpty()) {
            return@withContext Err(IllegalArgumentException("Credential not found"))
          }
          if (matches.size > 1) {
            return@withContext Err(SecurityException("Duplicate credential ID detected"))
          }
          val match = matches.first()
          loadFromExactRef(match.ref, expectedVersion = null)
        },
        failure = { error -> mapScanError(error) },
      )
    }

  override suspend fun loadForSigningExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion?,
  ): Result<SensitivePasskeyCredential, Throwable> =
    withContext(Dispatchers.IO) {
      loadFromExactRef(ref, expectedVersion)
    }

  override suspend fun loadCredentialMetadata(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion?,
  ): Result<PasskeyMetadata, Throwable> =
    withContext(Dispatchers.IO) {
      val opened = confinedStore.openExact(ref, expectedVersion)
      opened.fold(
        success = file@{ file ->
            try {
              concurrencyLimiter.decryptionSemaphore.acquire()
              val decryptResult =
                try {
                  val fileSize = file.fileSize()
                  val stream = file.inputStream()
                  passkeyPgpDecryptor.decryptFromStream(
                    stream,
                    fileSize,
                    pgpUnlockContext,
                    inputLimits,
                  )
                } finally {
                  concurrencyLimiter.decryptionSemaphore.release()
                }

              val sensitivePlaintext =
                decryptResult.fold(
                  success = { it },
                  failure = { error ->
                    return@file Err(
                      IllegalStateException("Decryption failed: ${formatDecryptionError(error)}")
                    )
                      as Result<PasskeyMetadata, Throwable>
                  },
                )

              try {
                sensitivePlaintext.borrow { plaintext ->
                  Ok(StoredCredential.metadataFromCbor(plaintext))
                    as Result<PasskeyMetadata, Throwable>
                }
              } finally {
                sensitivePlaintext.close()
              }
            } finally {
              file.close()
            }
          },
        failure = { error ->
          when (error) {
            is FileStoreError.VersionMismatch ->
              Err(SecurityException("File version changed between validation and open"))
            is FileStoreError.SymlinkInPath -> Err(SecurityException("Symlink rejected"))
            is FileStoreError.FileNotFound -> Err(IllegalArgumentException("Credential not found"))
            is FileStoreError.RepositoryRootSymlinked ->
              Err(SecurityException("Repository root is symlinked"))
            is FileStoreError.PathOutsideRepository ->
              Err(SecurityException("Path outside repository"))
            is FileStoreError.NotRegularFile -> Err(SecurityException("Not a regular file"))
            else -> Err(RuntimeException(error.message))
          }
        },
      )
    }

  private suspend fun loadFromExactRef(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion?,
  ): Result<SensitivePasskeyCredential, Throwable> {
    val opened = confinedStore.openExact(ref, expectedVersion)
    return opened.fold(
      success = file@{ file ->
          try {
            concurrencyLimiter.decryptionSemaphore.acquire()
            val decryptResult =
              try {
                val fileSize = file.fileSize()
                val stream = file.inputStream()
                passkeyPgpDecryptor.decryptFromStream(
                  stream,
                  fileSize,
                  pgpUnlockContext,
                  inputLimits,
                )
              } finally {
                concurrencyLimiter.decryptionSemaphore.release()
              }

            val sensitivePlaintext =
              decryptResult.fold(
                success = { it },
                failure = { error ->
                  return@file Err(
                    IllegalStateException("Decryption failed: ${formatDecryptionError(error)}")
                  )
                },
              )

            val stored =
              try {
                sensitivePlaintext.borrow { plaintext ->
                  StoredCredential.fromCbor(plaintext)
                }
              } finally {
                sensitivePlaintext.close()
              }

            try {
              PayloadBindingValidator.validate(
                  requestRpId = ref.canonicalRpId,
                  requestCredentialId = ref.credentialId,
                  fileRef = ref,
                  stored = stored,
                )
                .fold(
                  success = {},
                  failure = { error ->
                    return@file Err(
                      SecurityException("Payload binding validation failed: ${error.message}")
                    )
                  },
                )

              Ok(
                SensitivePasskeyCredential.fromStoredCredential(
                  stored,
                  file.version.modifiedAtMillis,
                )
              )
            } finally {
              stored.close()
            }
          } finally {
            file.close()
          }
        },
      failure = { error ->
        when (error) {
          is FileStoreError.VersionMismatch ->
            Err(SecurityException("File version changed between validation and open"))
          is FileStoreError.SymlinkInPath -> Err(SecurityException("Symlink rejected"))
          is FileStoreError.FileNotFound -> Err(IllegalArgumentException("Credential not found"))
          is FileStoreError.RepositoryRootSymlinked ->
            Err(SecurityException("Repository root is symlinked"))
          is FileStoreError.PathOutsideRepository ->
            Err(SecurityException("Path outside repository"))
          is FileStoreError.NotRegularFile -> Err(SecurityException("Not a regular file"))
          else -> Err(RuntimeException(error.message))
        }
      },
    )
  }

  override suspend fun saveCredential(
    credential: PasskeyCredential,
    privateKey: ByteArray,
  ): Result<Unit, Throwable> =
    withContext(Dispatchers.IO) {
      try {
        val dir = passkeyDir
        if (!dir.exists()) {
          if (!dir.mkdirs()) {
            return@withContext Err(IllegalStateException("Failed to create passkey directory"))
          }
        }

        val storedCred = StoredCredential.fromPasskeyCredential(credential, privateKey)
        val sanitizedRpDir = sanitizeRpId(credential.rpId)
        val rpDir = File(dir, sanitizedRpDir)
        if (!rpDir.exists()) {
          if (!rpDir.mkdirs()) {
            storedCred.close()
            return@withContext Err(IllegalStateException("Failed to create RP directory"))
          }
        }

        val ref =
          PasskeyFileRef.fromRpIdAndCredentialId(
            rpId = credential.rpId,
            credentialId = storedCred.id,
            sanitizedRpDir = sanitizedRpDir,
            fileExtension = config.fileExtension,
          )

        val plaintext =
          try {
            storedCred.toCbor()
          } finally {
            storedCred.close()
          }

        try {
          val recipients =
            recipientResolver
              .resolveFor(File(rpDir, ref.credentialIdHex() + config.fileExtension))
              .fold(
                success = { it },
                failure = { error ->
                  logcat(LogPriority.ERROR) { "Recipient resolution failed: $error" }
                  return@withContext Err(recipientPolicyErrorToException(error))
                },
              )

          return@withContext confinedStore
            .createOrReplace(ref) { outputStream ->
              val plaintextStream = ByteArrayInputStream(plaintext)
              cryptoHandler
                .encrypt(
                  keys = recipients,
                  passphrase = null,
                  plaintextStream = plaintextStream,
                  outputStream = outputStream,
                  options = encryptionOptions,
                )
                .fold(
                  success = {},
                  failure = { throw it },
                )
            }
            .fold(
              success = {
                logcat { "Saved passkey for ${credential.rpId}/${ref.credentialIdHex()}" }
                Ok(Unit)
              },
              failure = { error ->
                logcat(LogPriority.ERROR) { "Confined write failed: ${error.message}" }
                mapFileStoreError(error)
              },
            )
        } finally {
          plaintext.fill(0)
        }
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Failed to save credential: ${e.message}" }
        Err(e)
      }
    }

  override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> =
    withContext(Dispatchers.IO) {
      val scanResult = confinedStore.scanMetadata(null)
      scanResult.fold(
        success = { scanned ->
          val matches = scanned.filter { it.ref.credentialId.contentEquals(credentialId) }
          if (matches.isEmpty()) {
            return@withContext Ok(false)
          }
          if (matches.size > 1) {
            return@withContext Err(SecurityException("Duplicate credential ID detected"))
          }
          val match = matches.first()
          confinedStore
            .deleteExact(match.ref)
            .fold(
              success = { deleted ->
                if (deleted) {
                  logcat { "Deleted passkey ${match.ref.credentialIdHex()}" }
                  cleanupEmptyDirectories(
                    File(passkeyDir, match.ref.relativePath.substringBeforeLast('/'))
                  )
                }
                Ok(deleted)
              },
              failure = { error ->
                logcat(LogPriority.ERROR) { "Confined delete failed: ${error.message}" }
                mapFileStoreError(error)
              },
            )
        },
        failure = { error -> mapScanError(error) },
      )
    }

  override suspend fun deleteCredentialExact(ref: PasskeyFileRef): Result<Boolean, Throwable> =
    withContext(Dispatchers.IO) {
      confinedStore
        .deleteExact(ref)
        .fold(
          success = { deleted ->
            if (deleted) {
              logcat { "Deleted passkey ${ref.credentialIdHex()}" }
              cleanupEmptyDirectories(File(passkeyDir, ref.relativePath.substringBeforeLast('/')))
            }
            Ok(deleted)
          },
          failure = { error ->
            logcat(LogPriority.ERROR) { "Confined delete failed: ${error.message}" }
            mapFileStoreError(error)
          },
        )
    }

  override suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable> =
    withContext(Dispatchers.IO) {
      val scanResult = confinedStore.scanMetadata(null)
      scanResult.fold(
        success = { scanned ->
          val matches = scanned.filter { it.ref.credentialId.contentEquals(credentialId) }
          if (matches.isEmpty()) {
            return@withContext Err(IllegalArgumentException("Credential not found"))
          }
          if (matches.size > 1) {
            return@withContext Err(SecurityException("Duplicate credential ID detected"))
          }
          val match = matches.first()
          updateSignCountExact(match.ref, newSignCount)
        },
        failure = { error -> mapScanError(error) },
      )
    }

  public suspend fun updateSignCountExact(
    ref: PasskeyFileRef,
    newSignCount: ULong,
  ): Result<Unit, Throwable> =
    withContext(Dispatchers.IO) {
      val opened = confinedStore.openExact(ref, null)
      opened.fold(
        success = { file ->
          try {
            concurrencyLimiter.decryptionSemaphore.acquire()
            val sensitivePlaintext =
              try {
                val fileSize = file.fileSize()
                val stream = file.inputStream()
                passkeyPgpDecryptor
                  .decryptFromStream(stream, fileSize, pgpUnlockContext, inputLimits)
                  .fold(
                    success = { it },
                    failure = { error ->
                      return@withContext Err(
                        IllegalStateException("Decryption failed: ${formatDecryptionError(error)}")
                      )
                        as Result<Unit, Throwable>
                    },
                  )
              } finally {
                concurrencyLimiter.decryptionSemaphore.release()
              }

            val credential =
              try {
                sensitivePlaintext.borrow { plaintext ->
                  StoredCredential.fromCbor(plaintext)
                }
              } finally {
                sensitivePlaintext.close()
              }

            val updatedPlaintext =
              try {
                credential.copy(signCount = newSignCount.toUInt()).toCbor()
              } finally {
                credential.close()
              }

            try {
              val recipients =
                recipientResolver
                  .resolveFor(
                    File(repositoryRoot, "${config.passkeyDirectory}/${ref.relativePath}")
                  )
                  .fold(
                    success = { it },
                    failure = { error ->
                      return@withContext Err(recipientPolicyErrorToException(error))
                        as Result<Unit, Throwable>
                    },
                  )

              confinedStore
                .createOrReplace(ref) { outputStream ->
                  val plaintextStream = ByteArrayInputStream(updatedPlaintext)
                  cryptoHandler
                    .encrypt(
                      keys = recipients,
                      passphrase = null,
                      plaintextStream = plaintextStream,
                      outputStream = outputStream,
                      options = encryptionOptions,
                    )
                    .fold(
                      success = {},
                      failure = { throw it },
                    )
                }
                .fold(
                  success = {
                    Ok(Unit) as Result<Unit, Throwable>
                  },
                  failure = { error ->
                    mapFileStoreError(error) as Result<Unit, Throwable>
                  },
                )
            } finally {
              updatedPlaintext.fill(0)
            }
          } finally {
            file.close()
          }
        },
        failure = { error ->
          Err(RuntimeException(error.message))
        },
      )
    }

  override suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): Result<SourceVersionResult, Throwable> =
    withContext(Dispatchers.IO) {
      val scanResult = confinedStore.scanMetadata(null)
      scanResult.fold(
        success = { scanned ->
          val matches = scanned.filter { it.ref.credentialId.contentEquals(credentialId) }
          if (matches.isEmpty()) {
            return@withContext Ok(SourceVersionResult.Missing)
              as Result<SourceVersionResult, Throwable>
          }
          if (matches.size > 1) {
            return@withContext Err(SecurityException("Duplicate credential ID detected"))
              as Result<SourceVersionResult, Throwable>
          }
          confinedStore
            .resolveVersion(matches.first().ref)
            .fold(
              success = { Ok(it) as Result<SourceVersionResult, Throwable> },
              failure = {
                Err(RuntimeException(it.message)) as Result<SourceVersionResult, Throwable>
              },
            )
        },
        failure = { error -> mapScanError(error) as Result<SourceVersionResult, Throwable> },
      )
    }

  override suspend fun resolveSourceVersionExact(
    ref: PasskeyFileRef
  ): Result<SourceVersionResult, Throwable> =
    withContext(Dispatchers.IO) {
      confinedStore
        .resolveVersion(ref)
        .fold(
          success = { Ok(it) as Result<SourceVersionResult, Throwable> },
          failure = {
            Err(RuntimeException(it.message)) as Result<SourceVersionResult, Throwable>
          },
        )
    }

  public suspend fun recoverStaleArtifacts(): List<File> {
    val dir = passkeyDir
    if (!dir.exists() || !dir.isDirectory) return emptyList()
    return atomicWriter.cleanupStaleTempFiles(dir)
  }

  private fun mapScanError(error: FileStoreError): Result<Nothing, Throwable> {
    return when (error) {
      is FileStoreError.DuplicateCredentialId ->
        Err(SecurityException("Duplicate credential ID detected"))
      is FileStoreError.SymlinkInPath -> Err(SecurityException("Symlink rejected"))
      is FileStoreError.RepositoryRootSymlinked ->
        Err(SecurityException("Repository root is symlinked"))
      else -> Err(RuntimeException(error.message))
    }
  }

  private fun formatDecryptionError(error: PasskeyDecryptionError): String {
    return when (error) {
      is PasskeyDecryptionError.NoRecipientPackets -> "No recipient packets found"
      is PasskeyDecryptionError.MissingSecretKey ->
        "No matching secret key for recipients: ${error.recipientIds.joinToString()}"
      is PasskeyDecryptionError.KeyLocked -> "Key ${error.keyId} is locked"
      is PasskeyDecryptionError.IncorrectPassphrase -> "Incorrect passphrase for key ${error.keyId}"
      is PasskeyDecryptionError.IntegrityCheckFailed -> "Integrity check failed"
      is PasskeyDecryptionError.MalformedCiphertext -> "Malformed ciphertext"
      is PasskeyDecryptionError.UnsupportedFormat -> "Unsupported format: ${error.reason}"
      is PasskeyDecryptionError.CiphertextTooLarge ->
        "Ciphertext size ${error.actual} exceeds maximum ${error.maximum} bytes"
      is PasskeyDecryptionError.PlaintextTooLarge ->
        "Plaintext exceeds maximum ${error.maximum} bytes"
    }
  }

  private fun cleanupEmptyDirectories(dir: File?) {
    var current = dir
    while (current != null && current != passkeyDir) {
      if (current.isDirectory && current.listFiles()?.isEmpty() == true) {
        current.delete()
        current = current.parentFile
      } else {
        break
      }
    }
  }

  private fun mapFileStoreError(error: FileStoreError): Result<Nothing, Throwable> {
    return when (error) {
      is FileStoreError.DurabilityIndeterminate ->
        Err(DurabilityIndeterminateException(error.observedVersion, error.message))
      else -> Err(RuntimeException(error.message))
    }
  }
}

internal fun recipientPolicyErrorToException(error: RecipientPolicyError): Exception {
  return when (error) {
    is RecipientPolicyError.TargetOutsideRepository ->
      SecurityException("Target outside repository")
    is RecipientPolicyError.SymlinkRejected -> SecurityException("Symlink rejected")
    is RecipientPolicyError.GpgIdNotFound -> IllegalStateException("No .gpg-id found")
    is RecipientPolicyError.MalformedGpgId ->
      IllegalStateException("Malformed .gpg-id at line ${error.line}: ${error.reason}")
    is RecipientPolicyError.RecipientNotFound -> MissingRecipientKeyException(error.identifier)
    is RecipientPolicyError.AmbiguousRecipient ->
      IllegalStateException("Ambiguous recipient: ${error.identifier}")
    is RecipientPolicyError.RecipientUnusable ->
      IllegalStateException("Recipient unusable: ${error.identifier}")
    is RecipientPolicyError.EmptyRecipientSet ->
      IllegalStateException("Empty recipient set in .gpg-id")
  }
}
