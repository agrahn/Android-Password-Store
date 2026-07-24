/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold
import java.io.File
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import logcat.LogPriority
import logcat.logcat

public class DefaultAtomicCredentialWriter(
  private val repositoryRoot: File,
  private val faultInjector: FaultInjector? = null,
  private val directorySyncer: DirectorySyncer = DirectorySyncer.PLATFORM,
) : AtomicCredentialWriter {

  private val credentialMutexes = HashMap<String, Mutex>()
  private val globalMutex = Mutex()

  private suspend fun mutexFor(canonicalPath: String): Mutex {
    return globalMutex.withLock {
      credentialMutexes.getOrPut(canonicalPath) { Mutex() }
    }
  }

  private fun validateTarget(target: File): Result<ValidatedTarget, AtomicWriteError> {
    val canonicalTarget =
      try {
        target.canonicalFile
      } catch (e: Exception) {
        return Err(AtomicWriteError.IoError("Cannot resolve canonical path: ${e.message}"))
      }

    val canonicalRoot =
      try {
        repositoryRoot.canonicalFile
      } catch (e: Exception) {
        return Err(AtomicWriteError.IoError("Cannot resolve repository root: ${e.message}"))
      }

    if (
      !canonicalTarget.path.startsWith(canonicalRoot.path + File.separator) &&
        canonicalTarget.path != canonicalRoot.path
    ) {
      return Err(AtomicWriteError.TargetOutsideRepository)
    }

    if (isSymlinkInPath(target) || isSymlink(target)) {
      return Err(AtomicWriteError.SymlinkRejected)
    }

    val parentDir =
      canonicalTarget.parentFile ?: return Err(AtomicWriteError.IoError("No parent directory"))

    return Ok(ValidatedTarget(canonicalTarget, parentDir))
  }

  private data class ValidatedTarget(val canonicalTarget: File, val parentDir: File)

  override suspend fun replace(
    target: File,
    writeCiphertext: suspend (OutputStream) -> Unit,
  ): Result<DurableFileVersion, AtomicWriteError> {
    val validated =
      validateTarget(target)
        .fold(
          success = { it },
          failure = {
            return Err(it)
          },
        )
    val canonicalTarget = validated.canonicalTarget
    val parentDir = validated.parentDir

    if (!parentDir.exists()) {
      val created = parentDir.mkdirs()
      if (!created && !parentDir.exists()) {
        return Err(AtomicWriteError.IoError("Failed to create parent directory"))
      }
    }

    val mutex = mutexFor(canonicalTarget.path)
    return mutex.withLock {
      replaceLocked(canonicalTarget, parentDir, writeCiphertext)
    }
  }

  private suspend fun replaceLocked(
    target: File,
    parentDir: File,
    writeCiphertext: suspend (OutputStream) -> Unit,
  ): Result<DurableFileVersion, AtomicWriteError> {
    val tempFile =
      createExclusiveTempFile(parentDir, target)
        ?: return Err(AtomicWriteError.TempCreateFailed("Could not create exclusive temp file"))

    try {
      if (isSymlink(tempFile)) {
        tempFile.delete()
        return Err(AtomicWriteError.SymlinkRejected)
      }

      val digest = MessageDigest.getInstance("SHA-256")

      val fos = FileOutputStream(tempFile)
      val countingStream = CountingOutputStream(fos)
      val digestingStream = DigestingOutputStream(countingStream, digest)

      try {
        faultInjector?.beforeEncryption()

        writeCiphertext(digestingStream)

        faultInjector?.afterEncryptionBeforeClose()

        digestingStream.flush()
        countingStream.flush()
        fos.flush()

        faultInjector?.afterCloseBeforeSync()

        val fd: FileDescriptor = fos.fd
        try {
          fd.sync()
        } catch (e: Exception) {
          logcat(LogPriority.ERROR) { "File fsync failed: ${e.message}" }
          return Err(AtomicWriteError.FileSyncFailed("fsync on temp file failed: ${e.message}"))
        }

        faultInjector?.afterFileSync()
      } finally {
        fos.close()
      }

      val fileSize = tempFile.length()
      val ciphertextDigest = digest.digest()

      faultInjector?.beforeRename()

      try {
        val targetPath = target.toPath()
        val tempPath = tempFile.toPath()
        try {
          Files.move(
            tempPath,
            targetPath,
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING,
          )
        } catch (e: java.nio.file.AtomicMoveNotSupportedException) {
          logcat(LogPriority.ERROR) {
            "Atomic move not supported on this filesystem, failing closed: ${e.message}"
          }
          return Err(AtomicWriteError.AtomicMoveUnsupported)
        }
      } catch (e: Exception) {
        tempFile.delete()
        return Err(AtomicWriteError.RenameFailed("Atomic rename failed: ${e.message}"))
      }

      faultInjector?.afterRename()

      val modifiedAtMillis = target.lastModified()
      val observedVersion =
        DurableFileVersion(
          canonicalPath = target.canonicalPath,
          fileSize = fileSize,
          modifiedAtMillis = modifiedAtMillis,
          ciphertextDigest = ciphertextDigest,
        )

      try {
        faultInjector?.beforeDirectorySync()
        directorySyncer.sync(parentDir)
        faultInjector?.afterDirectorySync()
      } catch (e: Exception) {
        logcat(LogPriority.ERROR) { "Directory fsync failed after rename: ${e.message}" }
        return Err(
          AtomicWriteError.DurabilityIndeterminate(
            observedVersion = observedVersion,
            message = "Directory fsync failed after rename: ${e.message}",
          )
        )
      }

      return Ok(observedVersion)
    } catch (e: Exception) {
      if (tempFile.exists()) {
        tempFile.delete()
      }
      return Err(AtomicWriteError.EncryptionFailed("Encryption/write failed: ${e.message}"))
    }
  }

  private fun createExclusiveTempFile(parentDir: File, target: File): File? {
    val baseName = target.name
    val maxAttempts = 10
    val secureRandom = java.security.SecureRandom()
    for (i in 0 until maxAttempts) {
      val randomSuffix = secureRandom.nextLong().toString(36)
      val tempName = ".${baseName}.tmp-$randomSuffix"
      val tempFile = File(parentDir, tempName)
      try {
        if (tempFile.createNewFile()) {
          try {
            val posixPerms = java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")
            Files.setPosixFilePermissions(tempFile.toPath(), posixPerms)
          } catch (_: Exception) {
            tempFile.setReadable(false, false)
            tempFile.setReadable(true, true)
            tempFile.setWritable(false, false)
            tempFile.setWritable(true, true)
          }
          return tempFile
        }
      } catch (_: Exception) {
        continue
      }
    }
    return null
  }

  private fun isSymlink(file: File): Boolean {
    return try {
      Files.isSymbolicLink(file.toPath())
    } catch (_: Exception) {
      false
    }
  }

  private fun isSymlinkInPath(file: File): Boolean {
    val root = repositoryRoot.canonicalFile
    var current = file.parentFile
    while (current != null && current.path != root.path && current.path.startsWith(root.path)) {
      if (isSymlink(current)) return true
      current = current.parentFile
    }
    return false
  }

  public suspend fun deleteAtomic(target: File): Result<Boolean, AtomicWriteError> {
    val validated =
      validateTarget(target)
        .fold(
          success = { it },
          failure = {
            return Err(it)
          },
        )
    val canonicalTarget = validated.canonicalTarget
    val parentDir = validated.parentDir

    if (!canonicalTarget.exists()) {
      return Ok(false)
    }

    val mutex = mutexFor(canonicalTarget.path)
    return mutex.withLock {
      try {
        faultInjector?.beforeDelete()

        val deleted = canonicalTarget.delete()
        if (!deleted) {
          return@withLock Err(AtomicWriteError.IoError("Failed to delete target file"))
        }

        try {
          directorySyncer.sync(parentDir)
        } catch (e: Exception) {
          logcat(LogPriority.ERROR) { "Directory fsync failed after delete: ${e.message}" }
          return@withLock Err(
            AtomicWriteError.DurabilityIndeterminate(
              observedVersion = null,
              message = "Directory fsync failed after delete: ${e.message}",
            )
          )
        }

        Ok(true)
      } catch (e: Exception) {
        Err(AtomicWriteError.IoError("Delete failed: ${e.message}"))
      }
    }
  }

  public suspend fun cleanupStaleTempFiles(dir: File, maxAgeMs: Long = 60_000L): List<File> {
    val now = System.currentTimeMillis()
    val stale = mutableListOf<File>()
    if (!dir.exists() || !dir.isDirectory) return stale

    dir
      .walkTopDown()
      .filter { file ->
        file.isFile && isTempFileName(file.name)
      }
      .forEach { file ->
        val age = now - file.lastModified()
        if (age > maxAgeMs) {
          if (file.delete()) {
            stale.add(file)
            logcat { "Cleaned up stale temp file: ${file.path}" }
          }
        }
      }
    return stale
  }

  public fun isTempFileName(name: String): Boolean {
    return name.startsWith(".") && name.contains(".tmp-")
  }

  public fun isTombstoneFileName(name: String): Boolean {
    return name.startsWith(".") && name.endsWith(".tombstone")
  }

  public fun isInternalArtifact(name: String): Boolean {
    return isTempFileName(name) || isTombstoneFileName(name)
  }
}

public interface FaultInjector {
  public suspend fun beforeEncryption() {}

  public suspend fun afterEncryptionBeforeClose() {}

  public suspend fun afterCloseBeforeSync() {}

  public suspend fun afterFileSync() {}

  public suspend fun beforeRename() {}

  public suspend fun afterRename() {}

  public suspend fun beforeDirectorySync() {}

  public suspend fun afterDirectorySync() {}

  public suspend fun beforeDelete() {}
}

private class CountingOutputStream(private val delegate: OutputStream) : OutputStream() {
  var bytesWritten: Long = 0L
    private set

  override fun write(b: Int) {
    delegate.write(b)
    bytesWritten++
  }

  override fun write(b: ByteArray) {
    delegate.write(b)
    bytesWritten += b.size
  }

  override fun write(b: ByteArray, off: Int, len: Int) {
    delegate.write(b, off, len)
    bytesWritten += len
  }

  override fun flush() {
    delegate.flush()
  }

  override fun close() {
    delegate.close()
  }
}

private class DigestingOutputStream(
  private val delegate: OutputStream,
  private val digest: MessageDigest,
) : OutputStream() {

  override fun write(b: Int) {
    delegate.write(b)
    digest.update(b.toByte())
  }

  override fun write(b: ByteArray) {
    delegate.write(b)
    digest.update(b)
  }

  override fun write(b: ByteArray, off: Int, len: Int) {
    delegate.write(b, off, len)
    digest.update(b, off, len)
  }

  override fun flush() {
    delegate.flush()
  }

  override fun close() {
    delegate.close()
  }
}
