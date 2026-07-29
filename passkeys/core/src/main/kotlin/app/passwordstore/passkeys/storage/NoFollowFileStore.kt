/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.security.BoundedInputStream
import app.passwordstore.passkeys.security.PasskeyInputLimits
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.io.File
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import logcat.LogPriority
import logcat.logcat

public class NoFollowFileStore(
  private val repositoryRoot: File,
  private val passkeyDirectory: String = "fido2",
  private val fileExtension: String = ".gpg",
  private val atomicWriter: DefaultAtomicCredentialWriter =
    DefaultAtomicCredentialWriter(repositoryRoot),
  private val inputLimits: PasskeyInputLimits = PasskeyInputLimits.DEFAULT,
  private val generationProvider: RepositoryGenerationProvider? = null,
) : ConfinedPasskeyFileStore {

  private val readMutex = Mutex()
  private val writeMutex = Mutex()

  private val rootPath: Path
    get() = repositoryRoot.toPath().toAbsolutePath().normalize()

  private val passkeyRootPath: Path
    get() = rootPath.resolve(passkeyDirectory)

  override suspend fun scanMetadata(
    rpId: String?
  ): Result<List<ScannedCredentialFile>, FileStoreError> {
    return readMutex.withLock {
      try {
        if (!validateRoot()) {
          return@withLock Err(FileStoreError.RepositoryRootSymlinked)
        }

        val passkeyRoot = passkeyRootPath
        if (!safeIsDirectory(passkeyRoot)) {
          return@withLock Ok(emptyList())
        }

        val dirsToScan =
          if (rpId != null) {
            val sanitized = sanitizeRpId(rpId)
            val rpDir = passkeyRoot.resolve(sanitized)
            if (!safeIsDirectory(rpDir)) {
              return@withLock Ok(emptyList())
            }
            if (hasSymlinkComponent(rpDir, passkeyRoot)) {
              return@withLock Err(FileStoreError.SymlinkInPath)
            }
            listOf(sanitized to rpId)
          } else {
            collectRpDirectories(passkeyRoot)
          }

        val results = mutableListOf<ScannedCredentialFile>()
        val seenCredentialIds = HashMap<String, MutableList<PasskeyFileRef>>()

        for ((rpDirName, rawRpId) in dirsToScan) {
          val rpDir = passkeyRoot.resolve(rpDirName)

          if (hasSymlinkComponent(rpDir, passkeyRoot)) {
            logcat(LogPriority.WARN) { "Symlink in RP directory path, skipping: $rpDirName" }
            continue
          }

          if (!safeIsDirectory(rpDir)) continue

          val entries = safeListFiles(rpDir)
          for (entry in entries) {
            val fileName = entry.fileName.toString()

            if (atomicWriter.isInternalArtifact(fileName)) continue

            val ext = fileExtension.removePrefix(".")
            if (!fileName.endsWith(".$ext")) continue

            val hexId = fileName.removeSuffix(".$ext")
            val credentialId = hexToBytes(hexId) ?: continue

            val entryPath = rpDir.resolve(fileName)
            if (Files.isSymbolicLink(entryPath)) {
              logcat(LogPriority.WARN) { "Symlink rejected for credential file: $fileName" }
              continue
            }

            if (!Files.isRegularFile(entryPath, LinkOption.NOFOLLOW_LINKS)) continue

            val ref =
              PasskeyFileRef(
                canonicalRpId = rawRpId,
                credentialId = credentialId,
                relativePath = "$rpDirName/$fileName",
              )

            val idKey = hexId
            seenCredentialIds.getOrPut(idKey) { mutableListOf() }.add(ref)

            val attrs =
              try {
                Files.readAttributes(
                  entryPath,
                  java.nio.file.attribute.BasicFileAttributes::class.java,
                  LinkOption.NOFOLLOW_LINKS,
                )
              } catch (_: Exception) {
                continue
              }

            results.add(
              ScannedCredentialFile(
                ref = ref,
                fileSize = attrs.size(),
                lastModifiedMillis = attrs.lastModifiedTime().toMillis(),
              )
            )
          }
        }

        for ((_, refs) in seenCredentialIds) {
          if (refs.size > 1) {
            return@withLock Err(FileStoreError.DuplicateCredentialId)
          }
        }

        Ok(results)
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Metadata scan failed: ${e.message}" }
        Err(FileStoreError.IoError(e.message ?: "Unknown error"))
      }
    }
  }

  override suspend fun openExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion?,
  ): Result<OpenedPasskeyFile, FileStoreError> {
    return readMutex.withLock {
      try {
        if (!validateRoot()) {
          return@withLock Err(FileStoreError.RepositoryRootSymlinked)
        }

        val filePath =
          resolveAndValidate(ref)
            .fold(
              success = { it },
              failure = {
                return@withLock Err(it)
              },
            )

        val attrs =
          try {
            Files.readAttributes(
              filePath,
              java.nio.file.attribute.BasicFileAttributes::class.java,
              LinkOption.NOFOLLOW_LINKS,
            )
          } catch (e: Exception) {
            return@withLock Err(FileStoreError.IoError(e.message ?: "Cannot read file attributes"))
          }

        if (attrs.size() == 0L) {
          return@withLock Err(FileStoreError.IoError("Ciphertext file is empty"))
        }
        if (attrs.size() > inputLimits.maxCiphertextBytes) {
          return@withLock Err(
            FileStoreError.IoError(
              "File size ${attrs.size()} exceeds maximum ${inputLimits.maxCiphertextBytes} bytes"
            )
          )
        }

        val digest = MessageDigest.getInstance("SHA-256")
        val contentBytes =
          Files.newInputStream(filePath, LinkOption.NOFOLLOW_LINKS).use { rawStream ->
            val bounded = BoundedInputStream(rawStream, inputLimits.maxCiphertextBytes)
            bounded.readBoundedBytes(attrs.size().toInt())
          }
        digest.update(contentBytes)

        val version =
          CredentialSourceVersion(
            repositoryGeneration = currentRepositoryGeneration(),
            canonicalPath = filePath.toString(),
            fileSize = attrs.size(),
            modifiedAtMillis =
              Files.getLastModifiedTime(filePath, LinkOption.NOFOLLOW_LINKS).toMillis(),
            ciphertextDigest = digest.digest(),
          )

        if (expectedVersion != null && expectedVersion != version) {
          contentBytes.fill(0)
          return@withLock Err(FileStoreError.VersionMismatch)
        }

        Ok(OpenedPasskeyFile(ref, version, contentBytes))
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "openExact failed for ${ref.relativePath}: ${e.message}" }
        Err(FileStoreError.IoError(e.message ?: "Unknown error"))
      }
    }
  }

  override suspend fun createOrReplace(
    ref: PasskeyFileRef,
    writer: suspend (OutputStream) -> Unit,
  ): Result<DurableFileVersion, FileStoreError> {
    return writeMutex.withLock {
      try {
        if (!validateRoot()) {
          return@withLock Err(FileStoreError.RepositoryRootSymlinked)
        }

        val filePath =
          resolveAndValidate(ref, allowMissingTarget = true)
            .fold(
              success = { it },
              failure = {
                return@withLock Err(it)
              },
            )

        val targetFile = filePath.toFile()
        val parentDir = targetFile.parentFile
        if (!parentDir.exists()) {
          if (!parentDir.mkdirs()) {
            return@withLock Err(FileStoreError.IoError("Failed to create parent directory"))
          }
        }

        if (hasSymlinkComponent(filePath, rootPath)) {
          return@withLock Err(FileStoreError.SymlinkInPath)
        }

        return@withLock atomicWriter
          .replace(targetFile) { outputStream ->
            writer(outputStream)
          }
          .fold(
            success = { Ok(it) },
            failure = { error ->
              when (error) {
                is AtomicWriteError.DurabilityIndeterminate ->
                  Err(FileStoreError.DurabilityIndeterminate(error.observedVersion, error.message))
                else -> Err(FileStoreError.IoError(error.message))
              }
            },
          )
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "createOrReplace failed: ${e.message}" }
        Err(FileStoreError.IoError(e.message ?: "Unknown error"))
      }
    }
  }

  override suspend fun deleteExact(ref: PasskeyFileRef): Result<Boolean, FileStoreError> {
    return writeMutex.withLock {
      try {
        if (!validateRoot()) {
          return@withLock Err(FileStoreError.RepositoryRootSymlinked)
        }

        val filePath =
          resolveAndValidate(ref)
            .fold(
              success = { it },
              failure = {
                return@withLock Err(it)
              },
            )

        val targetFile = filePath.toFile()
        if (!targetFile.exists()) {
          return@withLock Ok(false)
        }

        return@withLock atomicWriter
          .deleteAtomic(targetFile)
          .fold(
            success = { Ok(it) },
            failure = { error ->
              when (error) {
                is AtomicWriteError.DurabilityIndeterminate ->
                  Err(FileStoreError.DurabilityIndeterminate(error.observedVersion, error.message))
                else -> Err(FileStoreError.IoError(error.message))
              }
            },
          )
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "deleteExact failed: ${e.message}" }
        Err(FileStoreError.IoError(e.message ?: "Unknown error"))
      }
    }
  }

  override suspend fun resolveVersion(
    ref: PasskeyFileRef
  ): Result<SourceVersionResult, FileStoreError> {
    return readMutex.withLock {
      try {
        if (!validateRoot()) {
          return@withLock Err(FileStoreError.RepositoryRootSymlinked)
        }

        val filePath =
          resolveAndValidate(ref)
            .fold(
              success = { it },
              failure = { error ->
                return@withLock when (error) {
                  is FileStoreError.FileNotFound -> Ok(SourceVersionResult.Missing)
                  else -> Err(error)
                }
              },
            )

        if (!Files.exists(filePath, LinkOption.NOFOLLOW_LINKS)) {
          return@withLock Ok(SourceVersionResult.Missing)
        }

        if (Files.isSymbolicLink(filePath)) {
          return@withLock Err(FileStoreError.SymlinkInPath)
        }

        if (!Files.isRegularFile(filePath, LinkOption.NOFOLLOW_LINKS)) {
          return@withLock Err(FileStoreError.NotRegularFile)
        }

        val attrs =
          Files.readAttributes(
            filePath,
            java.nio.file.attribute.BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
          )

        if (attrs.size() == 0L) {
          return@withLock Err(FileStoreError.IoError("Ciphertext file is empty"))
        }
        if (attrs.size() > inputLimits.maxCiphertextBytes) {
          return@withLock Err(
            FileStoreError.IoError(
              "File size ${attrs.size()} exceeds maximum ${inputLimits.maxCiphertextBytes} bytes"
            )
          )
        }

        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(filePath, LinkOption.NOFOLLOW_LINKS).use { rawStream ->
          val bounded = BoundedInputStream(rawStream, inputLimits.maxCiphertextBytes)
          val contentBytes = bounded.readBoundedBytes(attrs.size().toInt())
          digest.update(contentBytes)
          contentBytes.fill(0)
        }

        val version =
          CredentialSourceVersion(
            repositoryGeneration = currentRepositoryGeneration(),
            canonicalPath = filePath.toString(),
            fileSize = attrs.size(),
            modifiedAtMillis =
              Files.getLastModifiedTime(filePath, LinkOption.NOFOLLOW_LINKS).toMillis(),
            ciphertextDigest = digest.digest(),
          )
        Ok(SourceVersionResult.Stable(version))
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "resolveVersion failed: ${e.message}" }
        Err(FileStoreError.IoError(e.message ?: "Unknown error"))
      }
    }
  }

  private fun validateRoot(): Boolean {
    val root = repositoryRoot.toPath()
    if (Files.isSymbolicLink(root)) return false
    return true
  }

  private fun resolveAndValidate(
    ref: PasskeyFileRef,
    allowMissingTarget: Boolean = false,
  ): Result<Path, FileStoreError> {
    val passkeyRoot = passkeyRootPath

    if (!safeIsDirectory(passkeyRoot)) {
      return Err(FileStoreError.NotDirectory)
    }

    val segments = ref.relativePath.split("/")
    var current = passkeyRoot

    for ((index, segment) in segments.withIndex()) {
      if (segment.isBlank() || segment == "." || segment == "..") {
        return Err(FileStoreError.MalformedPath)
      }

      val next = current.resolve(segment)

      if (Files.isSymbolicLink(next)) {
        return Err(FileStoreError.SymlinkInPath)
      }

      if (!Files.exists(next, LinkOption.NOFOLLOW_LINKS)) {
        if (allowMissingTarget && index == segments.lastIndex) {
          current = next
          continue
        }
        return Err(FileStoreError.FileNotFound)
      }

      if (index < segments.lastIndex && !Files.isDirectory(next, LinkOption.NOFOLLOW_LINKS)) {
        return Err(FileStoreError.NotDirectory)
      }

      current = next
    }

    if (
      Files.exists(current, LinkOption.NOFOLLOW_LINKS) &&
        !Files.isRegularFile(current, LinkOption.NOFOLLOW_LINKS)
    ) {
      return Err(FileStoreError.NotRegularFile)
    }

    val normalized = current.toAbsolutePath().normalize()
    val passkeyRootNormalized = passkeyRoot.toAbsolutePath().normalize()
    if (!normalized.startsWith(passkeyRootNormalized)) {
      return Err(FileStoreError.PathOutsideRepository)
    }

    return Ok(current)
  }

  private fun safeIsDirectory(path: Path): Boolean {
    return try {
      Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
    } catch (_: Exception) {
      false
    }
  }

  private fun hasSymlinkComponent(path: Path, root: Path): Boolean {
    val rootNormalized = root.toAbsolutePath().normalize()
    val pathNormalized = path.toAbsolutePath().normalize()

    if (!pathNormalized.startsWith(rootNormalized)) return true

    val relativePath = rootNormalized.relativize(pathNormalized)
    var current = rootNormalized

    for (segment in relativePath) {
      current = current.resolve(segment)
      if (Files.isSymbolicLink(current)) return true
    }

    return false
  }

  private fun safeListFiles(dir: Path): List<Path> {
    return try {
      val entries = mutableListOf<Path>()
      Files.newDirectoryStream(dir).use { stream ->
        for (entry in stream) {
          entries.add(entry)
        }
      }
      entries
    } catch (_: Exception) {
      emptyList()
    }
  }

  private fun collectRpDirectories(passkeyRoot: Path): List<Pair<String, String>> {
    val results = mutableListOf<Pair<String, String>>()
    val entries = safeListFiles(passkeyRoot)

    for (entry in entries) {
      if (Files.isSymbolicLink(entry)) continue
      if (!Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) continue

      val dirName = entry.fileName.toString()
      if (dirName.isBlank() || dirName.startsWith(".")) continue

      results.add(dirName to unsanitizeRpId(dirName))
    }

    return results
  }

  private fun currentRepositoryGeneration(): RepositoryGeneration {
    val provider = generationProvider
    return if (provider != null) {
      RepositoryGeneration(
        repositoryIdentity = provider.repositoryIdentity(),
        gitHead = null,
        worktreeGeneration = provider.currentWorktreeGeneration(),
      )
    } else {
      RepositoryGeneration(
        repositoryIdentity = repositoryRoot.canonicalPath,
        gitHead = null,
        worktreeGeneration = 0L,
      )
    }
  }

  private fun unsanitizeRpId(sanitized: String): String {
    return sanitized
  }
}
