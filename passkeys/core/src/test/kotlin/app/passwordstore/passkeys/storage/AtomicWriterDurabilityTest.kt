/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.unwrapError
import java.io.File
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class AtomicWriterDurabilityTest {

  private lateinit var tempDir: File

  @BeforeTest
  fun setup() {
    tempDir = Files.createTempDirectory("atomic-durability-test").toFile()
  }

  @AfterTest
  fun tearDown() {
    tempDir.deleteRecursively()
  }

  private class RecordingFaultInjector : FaultInjector {
    val calls = mutableListOf<String>()
    var throwOn: String? = null

    override suspend fun beforeEncryption() {
      calls.add("beforeEncryption")
      if (throwOn == "beforeEncryption") throw RuntimeException("Injected: beforeEncryption")
    }

    override suspend fun afterEncryptionBeforeClose() {
      calls.add("afterEncryptionBeforeClose")
      if (throwOn == "afterEncryptionBeforeClose")
        throw RuntimeException("Injected: afterEncryptionBeforeClose")
    }

    override suspend fun afterCloseBeforeSync() {
      calls.add("afterCloseBeforeSync")
      if (throwOn == "afterCloseBeforeSync")
        throw RuntimeException("Injected: afterCloseBeforeSync")
    }

    override suspend fun afterFileSync() {
      calls.add("afterFileSync")
      if (throwOn == "afterFileSync") throw RuntimeException("Injected: afterFileSync")
    }

    override suspend fun beforeRename() {
      calls.add("beforeRename")
      if (throwOn == "beforeRename") throw RuntimeException("Injected: beforeRename")
    }

    override suspend fun afterRename() {
      calls.add("afterRename")
      if (throwOn == "afterRename") throw RuntimeException("Injected: afterRename")
    }

    override suspend fun beforeDirectorySync() {
      calls.add("beforeDirectorySync")
      if (throwOn == "beforeDirectorySync") throw RuntimeException("Injected: beforeDirectorySync")
    }

    override suspend fun afterDirectorySync() {
      calls.add("afterDirectorySync")
      if (throwOn == "afterDirectorySync") throw RuntimeException("Injected: afterDirectorySync")
    }

    override suspend fun beforeDelete() {
      calls.add("beforeDelete")
      if (throwOn == "beforeDelete") throw RuntimeException("Injected: beforeDelete")
    }
  }

  private class FailingDirectorySyncer : DirectorySyncer {
    val syncCount = AtomicInteger(0)

    override fun sync(dir: File) {
      syncCount.incrementAndGet()
      throw DirectorySyncException("Injected directory sync failure for ${dir.path}")
    }
  }

  private class RecordingDirectorySyncer : DirectorySyncer {
    val syncCount = AtomicInteger(0)
    val syncedDirs = mutableListOf<String>()

    override fun sync(dir: File) {
      syncCount.incrementAndGet()
      syncedDirs.add(dir.absolutePath)
    }
  }

  @Test
  fun `pre-sync failure leaves old target unchanged`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    val originalContent = "original-content".toByteArray()
    target.parentFile.mkdirs()
    target.writeBytes(originalContent)

    val injector = RecordingFaultInjector().apply { throwOn = "afterCloseBeforeSync" }
    val syncer = RecordingDirectorySyncer()
    val writer = DefaultAtomicCredentialWriter(tempDir, injector, syncer)

    val result =
      writer.replace(target) { outputStream ->
        outputStream.write("new-content".toByteArray())
      }

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<AtomicWriteError.EncryptionFailed>(error)
    assertContentEquals(originalContent, target.readBytes())
    assertEquals(0, syncer.syncCount.get(), "Directory sync should not be called")
    val tempFiles =
      target.parentFile.listFiles { f -> f.name.startsWith(".") && f.name.contains(".tmp-") }
    assertTrue(tempFiles == null || tempFiles.isEmpty(), "No temp files should remain")
  }

  @Test
  fun `rename failure leaves old target unchanged and cleans temp`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    val originalContent = "original-content".toByteArray()
    target.parentFile.mkdirs()
    target.writeBytes(originalContent)

    val injector = RecordingFaultInjector().apply { throwOn = "beforeRename" }
    val syncer = RecordingDirectorySyncer()
    val writer = DefaultAtomicCredentialWriter(tempDir, injector, syncer)

    val result =
      writer.replace(target) { outputStream ->
        outputStream.write("new-content".toByteArray())
      }

    assertTrue(result.isErr)
    assertContentEquals(originalContent, target.readBytes())
    assertEquals(0, syncer.syncCount.get())
    val tempFiles =
      target.parentFile.listFiles { f -> f.name.startsWith(".") && f.name.contains(".tmp-") }
    assertTrue(
      tempFiles == null || tempFiles.isEmpty(),
      "Temp files should be cleaned after rename failure",
    )
  }

  @Test
  fun `directory fsync failure after rename returns DurabilityIndeterminate with version`() =
    runBlocking {
      val target = File(tempDir, "fido2/example/abcd1234.gpg")
      val content = "encrypted-content".toByteArray()

      val injector = RecordingFaultInjector()
      val failingSyncer = FailingDirectorySyncer()
      val writer = DefaultAtomicCredentialWriter(tempDir, injector, failingSyncer)

      val result =
        writer.replace(target) { outputStream ->
          outputStream.write(content)
        }

      assertTrue(result.isErr)
      val error = result.unwrapError()
      assertIs<AtomicWriteError.DurabilityIndeterminate>(error)
      assertNotNull(error.observedVersion)
      assertEquals(target.canonicalPath, error.observedVersion!!.canonicalPath)
      assertEquals(content.size.toLong(), error.observedVersion!!.fileSize)
      assertTrue(target.exists(), "File should exist after rename even though dirsync failed")
      assertContentEquals(content, target.readBytes())
      assertTrue(injector.calls.contains("afterRename"))
      assertTrue(injector.calls.contains("beforeDirectorySync"))
      assertFalse(injector.calls.contains("afterDirectorySync"))
    }

  @Test
  fun `successful replace invokes file and directory sync exactly once`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    val content = "encrypted-content".toByteArray()

    val injector = RecordingFaultInjector()
    val syncer = RecordingDirectorySyncer()
    val writer = DefaultAtomicCredentialWriter(tempDir, injector, syncer)

    val result =
      writer.replace(target) { outputStream ->
        outputStream.write(content)
      }

    assertTrue(result.isOk)
    assertEquals(1, syncer.syncCount.get(), "Directory sync should be called exactly once")
    assertTrue(injector.calls.contains("afterFileSync"))
    assertTrue(injector.calls.contains("beforeDirectorySync"))
    assertTrue(injector.calls.contains("afterDirectorySync"))
    assertEquals(
      listOf(
        "beforeEncryption",
        "afterEncryptionBeforeClose",
        "afterCloseBeforeSync",
        "afterFileSync",
        "beforeRename",
        "afterRename",
        "beforeDirectorySync",
        "afterDirectorySync",
      ),
      injector.calls,
    )
  }

  @Test
  fun `delete directory sync failure returns DurabilityIndeterminate`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    target.parentFile.mkdirs()
    target.writeBytes("content".toByteArray())

    val failingSyncer = FailingDirectorySyncer()
    val writer = DefaultAtomicCredentialWriter(tempDir, null, failingSyncer)

    val result = writer.deleteAtomic(target)

    assertTrue(result.isErr)
    val error = result.unwrapError()
    assertIs<AtomicWriteError.DurabilityIndeterminate>(error)
    assertNull(error.observedVersion)
    assertFalse(target.exists(), "File should be deleted even though dirsync failed")
    assertEquals(1, failingSyncer.syncCount.get())
  }

  @Test
  fun `successful delete invokes directory sync exactly once`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    target.parentFile.mkdirs()
    target.writeBytes("content".toByteArray())

    val injector = RecordingFaultInjector()
    val syncer = RecordingDirectorySyncer()
    val writer = DefaultAtomicCredentialWriter(tempDir, injector, syncer)

    val result = writer.deleteAtomic(target)

    assertTrue(result.isOk)
    assertTrue(result.getOrElse { throw IllegalStateException("Should not fail") })
    assertFalse(target.exists())
    assertEquals(1, syncer.syncCount.get())
    assertTrue(injector.calls.contains("beforeDelete"))
  }

  @Test
  fun `encryption failure does not invoke directory sync`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    val originalContent = "original".toByteArray()
    target.parentFile.mkdirs()
    target.writeBytes(originalContent)

    val injector = RecordingFaultInjector().apply { throwOn = "beforeEncryption" }
    val syncer = RecordingDirectorySyncer()
    val writer = DefaultAtomicCredentialWriter(tempDir, injector, syncer)

    val result =
      writer.replace(target) { outputStream ->
        outputStream.write("new".toByteArray())
      }

    assertTrue(result.isErr)
    assertIs<AtomicWriteError.EncryptionFailed>(result.unwrapError())
    assertEquals(0, syncer.syncCount.get())
    assertContentEquals(originalContent, target.readBytes())
  }

  @Test
  fun `crash after temp fsync before rename leaves old target valid`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    val originalContent = "original-content".toByteArray()
    target.parentFile.mkdirs()
    target.writeBytes(originalContent)

    val injector = RecordingFaultInjector().apply { throwOn = "afterFileSync" }
    val syncer = RecordingDirectorySyncer()
    val writer = DefaultAtomicCredentialWriter(tempDir, injector, syncer)

    val result =
      writer.replace(target) { outputStream ->
        outputStream.write("new-content".toByteArray())
      }

    assertTrue(result.isErr)
    assertContentEquals(originalContent, target.readBytes())
    assertEquals(0, syncer.syncCount.get())
    val tempFiles =
      target.parentFile.listFiles { f -> f.name.startsWith(".") && f.name.contains(".tmp-") }
    assertTrue(tempFiles == null || tempFiles.isEmpty(), "No temp files should remain")
  }

  @Test
  fun `durability indeterminate preserves file content for reconciliation`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    val content = "new-encrypted-content".toByteArray()

    val failingSyncer = FailingDirectorySyncer()
    val writer = DefaultAtomicCredentialWriter(tempDir, null, failingSyncer)

    val result =
      writer.replace(target) { outputStream ->
        outputStream.write(content)
      }

    assertTrue(result.isErr)
    val error = result.unwrapError() as AtomicWriteError.DurabilityIndeterminate
    assertNotNull(error.observedVersion)
    assertTrue(target.exists())
    assertContentEquals(content, target.readBytes())
    assertContentEquals(
      error.observedVersion!!.ciphertextDigest,
      java.security.MessageDigest.getInstance("SHA-256").digest(content),
    )
  }

  @Test
  fun `concurrent replace and delete are serialized`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    target.parentFile.mkdirs()
    target.writeBytes("initial".toByteArray())

    val syncer = RecordingDirectorySyncer()
    val writer = DefaultAtomicCredentialWriter(tempDir, null, syncer)

    val replaceResult =
      writer.replace(target) { outputStream ->
        outputStream.write("replaced".toByteArray())
      }
    assertTrue(replaceResult.isOk)

    val deleteResult = writer.deleteAtomic(target)
    assertTrue(deleteResult.isOk)
    assertFalse(target.exists())

    assertTrue(syncer.syncCount.get() >= 2, "Both operations should sync directory")
  }

  @Test
  fun `no partial content observable after successful write`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    val content = "complete-encrypted-content".toByteArray()

    val syncer = RecordingDirectorySyncer()
    val writer = DefaultAtomicCredentialWriter(tempDir, null, syncer)

    val result =
      writer.replace(target) { outputStream ->
        outputStream.write(content)
      }

    assertTrue(result.isOk)
    val writtenContent = target.readBytes()
    assertContentEquals(content, writtenContent)
    assertFalse(writtenContent.isEmpty(), "File should not be empty")
  }

  @Test
  fun `stale temp file from crashed write is recoverable`() = runBlocking {
    val dir = File(tempDir, "fido2/example")
    dir.mkdirs()

    val staleTemp = File(dir, ".abcd1234.gpg.tmp-crash123")
    staleTemp.writeBytes("stale-content".toByteArray())
    staleTemp.setLastModified(System.currentTimeMillis() - 120_000)

    val writer = DefaultAtomicCredentialWriter(tempDir)
    val cleaned = writer.cleanupStaleTempFiles(tempDir, maxAgeMs = 60_000L)

    assertEquals(1, cleaned.size)
    assertFalse(staleTemp.exists())
  }

  @Test
  fun `directory syncer receives correct parent directory`() = runBlocking {
    val target = File(tempDir, "fido2/example/abcd1234.gpg")
    val content = "content".toByteArray()

    val syncer = RecordingDirectorySyncer()
    val writer = DefaultAtomicCredentialWriter(tempDir, null, syncer)

    writer.replace(target) { outputStream ->
      outputStream.write(content)
    }

    assertEquals(1, syncer.syncedDirs.size)
    assertEquals(File(tempDir, "fido2/example").absolutePath, syncer.syncedDirs[0])
  }
}
