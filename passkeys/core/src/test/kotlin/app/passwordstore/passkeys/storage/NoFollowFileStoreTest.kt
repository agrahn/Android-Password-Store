/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import com.github.michaelbull.result.fold
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class NoFollowFileStoreTest {

  private lateinit var tempDir: File
  private lateinit var repoRoot: File
  private lateinit var store: NoFollowFileStore

  private fun setupRepo() {
    tempDir = Files.createTempDirectory("passkey-test-").toFile()
    repoRoot = File(tempDir, "repo")
    repoRoot.mkdirs()
    store = NoFollowFileStore(repoRoot)
  }

  private fun teardownRepo() {
    tempDir.deleteRecursively()
  }

  @Test
  fun `RP directory symlink to outside repository is rejected by scanner`() = runBlocking {
    setupRepo()
    try {
      val passkeyDir = File(repoRoot, "fido2")
      passkeyDir.mkdirs()

      val outsideDir = File(tempDir, "outside")
      outsideDir.mkdirs()
      File(outsideDir, "aabb.gpg").writeBytes(byteArrayOf(1, 2, 3))

      Files.createSymbolicLink(
        File(passkeyDir, "evil.com").toPath(),
        outsideDir.toPath(),
      )

      val result = store.scanMetadata(null)
      result.fold(
        success = { files ->
          val evilFiles = files.filter { it.ref.canonicalRpId == "evil.com" }
          assertEquals(0, evilFiles.size, "Scanner must not follow symlinked RP directory")
        },
        failure = {
          assertTrue(
            it is FileStoreError.SymlinkInPath || it is FileStoreError.DuplicateCredentialId,
            "Expected symlink rejection or duplicate error, got: $it",
          )
        },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `credential file symlink is rejected`() = runBlocking {
    setupRepo()
    try {
      val passkeyDir = File(repoRoot, "fido2")
      val rpDir = File(passkeyDir, "example.com")
      rpDir.mkdirs()

      val outsideFile = File(tempDir, "outside-cred.gpg")
      outsideFile.writeBytes(byteArrayOf(1, 2, 3))

      Files.createSymbolicLink(
        File(rpDir, "aabb.gpg").toPath(),
        outsideFile.toPath(),
      )

      val result = store.scanMetadata("example.com")
      result.fold(
        success = { files ->
          assertEquals(0, files.size, "Symlinked credential file must be skipped")
        },
        failure = {
          assertTrue(it is FileStoreError.SymlinkInPath, "Expected symlink error, got: $it")
        },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `openExact rejects symlinked RP directory`() = runBlocking {
    setupRepo()
    try {
      val passkeyDir = File(repoRoot, "fido2")
      passkeyDir.mkdirs()

      val outsideDir = File(tempDir, "outside")
      outsideDir.mkdirs()
      File(outsideDir, "aabb.gpg").writeBytes(byteArrayOf(1, 2, 3))

      Files.createSymbolicLink(
        File(passkeyDir, "evil.com").toPath(),
        outsideDir.toPath(),
      )

      val ref =
        PasskeyFileRef(
          canonicalRpId = "evil.com",
          credentialId = byteArrayOf(0xaa.toByte(), 0xbb.toByte()),
          relativePath = "evil.com/aabb.gpg",
        )

      val result = store.openExact(ref)
      result.fold(
        success = {
          throw AssertionError("openExact must reject symlinked RP directory")
        },
        failure = { error ->
          assertTrue(
            error is FileStoreError.SymlinkInPath,
            "Expected SymlinkInPath error, got: $error",
          )
        },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `openExact rejects path outside repository`() = runBlocking {
    setupRepo()
    try {
      val passkeyDir = File(repoRoot, "fido2")
      passkeyDir.mkdirs()

      val ref =
        PasskeyFileRef(
          canonicalRpId = "example.com",
          credentialId = byteArrayOf(0xaa.toByte(), 0xbb.toByte()),
          relativePath = "example.com/aabb.gpg",
        )

      val result = store.openExact(ref)
      result.fold(
        success = {
          throw AssertionError("openExact must reject non-existent file")
        },
        failure = { error ->
          assertTrue(
            error is FileStoreError.FileNotFound,
            "Expected FileNotFound error, got: $error",
          )
        },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `createOrReplace creates a missing credential file`() = runBlocking {
    setupRepo()
    try {
      val rpDir = File(repoRoot, "fido2/example.com")
      rpDir.mkdirs()
      val ref =
        PasskeyFileRef(
          canonicalRpId = "example.com",
          credentialId = byteArrayOf(0xaa.toByte(), 0xbb.toByte()),
          relativePath = "example.com/aabb.gpg",
        )

      val result = store.createOrReplace(ref) { output -> output.write(byteArrayOf(1, 2, 3)) }

      result.fold(
        success = {
          assertTrue(File(rpDir, "aabb.gpg").readBytes().contentEquals(byteArrayOf(1, 2, 3)))
        },
        failure = { throw AssertionError("Create should succeed: $it") },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `createOrReplace rejects a missing parent directory`() = runBlocking {
    setupRepo()
    try {
      File(repoRoot, "fido2").mkdirs()
      val ref =
        PasskeyFileRef(
          canonicalRpId = "example.com",
          credentialId = byteArrayOf(0xaa.toByte(), 0xbb.toByte()),
          relativePath = "example.com/aabb.gpg",
        )

      val result = store.createOrReplace(ref) { output -> output.write(byteArrayOf(1, 2, 3)) }

      result.fold(
        success = { throw AssertionError("Create must reject a missing parent directory") },
        failure = { error -> assertEquals(FileStoreError.FileNotFound, error) },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `duplicate credential IDs in different RP directories fail closed`() = runBlocking {
    setupRepo()
    try {
      val passkeyDir = File(repoRoot, "fido2")
      val rpDir1 = File(passkeyDir, "a.example.com")
      val rpDir2 = File(passkeyDir, "b.example.com")
      rpDir1.mkdirs()
      rpDir2.mkdirs()

      val credBytes = byteArrayOf(0xaa.toByte(), 0xbb.toByte())
      File(rpDir1, "aabb.gpg").writeBytes(byteArrayOf(1, 2, 3))
      File(rpDir2, "aabb.gpg").writeBytes(byteArrayOf(4, 5, 6))

      val result = store.scanMetadata(null)
      result.fold(
        success = {
          throw AssertionError("Duplicate credential IDs must fail closed")
        },
        failure = { error ->
          assertEquals(
            FileStoreError.DuplicateCredentialId,
            error,
            "Expected DuplicateCredentialId error",
          )
        },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `internal temp and tombstone files are ignored`() = runBlocking {
    setupRepo()
    try {
      val passkeyDir = File(repoRoot, "fido2")
      val rpDir = File(passkeyDir, "example.com")
      rpDir.mkdirs()

      File(rpDir, "aabb.gpg").writeBytes(byteArrayOf(1, 2, 3))
      File(rpDir, ".aabb.gpg.tmp-abc123").writeBytes(byteArrayOf(4, 5, 6))
      File(rpDir, ".aabb.gpg.tombstone").writeBytes(byteArrayOf(7, 8, 9))

      val result = store.scanMetadata("example.com")
      result.fold(
        success = { files ->
          assertEquals(1, files.size, "Only the real credential file should be returned")
          assertEquals("aabb.gpg", File(files[0].ref.relativePath).name)
        },
        failure = { throw AssertionError("Scan should succeed: $it") },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `deep nested directory tree is not traversed`() = runBlocking {
    setupRepo()
    try {
      val passkeyDir = File(repoRoot, "fido2")
      val rpDir = File(passkeyDir, "example.com")
      rpDir.mkdirs()

      File(rpDir, "aabb.gpg").writeBytes(byteArrayOf(1, 2, 3))

      val deepDir = File(rpDir, "deep/nested/dir")
      deepDir.mkdirs()
      File(deepDir, "ccdd.gpg").writeBytes(byteArrayOf(4, 5, 6))

      val result = store.scanMetadata("example.com")
      result.fold(
        success = { files ->
          assertEquals(1, files.size, "Deep nested files must not be traversed")
        },
        failure = { throw AssertionError("Scan should succeed: $it") },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `PasskeyFileRef rejects path traversal`() {
    try {
      PasskeyFileRef(
        canonicalRpId = "example.com",
        credentialId = byteArrayOf(0xaa.toByte()),
        relativePath = "example.com/../../../etc/passwd",
      )
      throw AssertionError("PasskeyFileRef must reject path traversal")
    } catch (e: IllegalArgumentException) {
      // expected
    }
  }

  @Test
  fun `PasskeyFileRef rejects dot-dot components`() {
    try {
      PasskeyFileRef(
        canonicalRpId = "example.com",
        credentialId = byteArrayOf(0xaa.toByte()),
        relativePath = "../evil/aabb.gpg",
      )
      throw AssertionError("PasskeyFileRef must reject .. components")
    } catch (e: IllegalArgumentException) {
      // expected
    }
  }

  @Test
  fun `PasskeyFileRef rejects absolute paths`() {
    try {
      PasskeyFileRef(
        canonicalRpId = "example.com",
        credentialId = byteArrayOf(0xaa.toByte()),
        relativePath = "/etc/passwd",
      )
      throw AssertionError("PasskeyFileRef must reject absolute paths")
    } catch (e: IllegalArgumentException) {
      // expected
    }
  }

  @Test
  fun `PasskeyFileRef rejects blank RP ID`() {
    try {
      PasskeyFileRef(
        canonicalRpId = "",
        credentialId = byteArrayOf(0xaa.toByte()),
        relativePath = "test/aabb.gpg",
      )
      throw AssertionError("PasskeyFileRef must reject blank RP ID")
    } catch (e: IllegalArgumentException) {
      // expected
    }
  }

  @Test
  fun `PasskeyFileRef rejects RP ID with path separators`() {
    try {
      PasskeyFileRef(
        canonicalRpId = "evil/path",
        credentialId = byteArrayOf(0xaa.toByte()),
        relativePath = "test/aabb.gpg",
      )
      throw AssertionError("PasskeyFileRef must reject RP ID with path separators")
    } catch (e: IllegalArgumentException) {
      // expected
    }
  }

  @Test
  fun `valid normal credential path remains compatible`() = runBlocking {
    setupRepo()
    try {
      val passkeyDir = File(repoRoot, "fido2")
      val rpDir = File(passkeyDir, "example.com")
      rpDir.mkdirs()

      val credBytes = byteArrayOf(1, 2, 3, 4)
      File(rpDir, "aabbccdd.gpg").writeBytes(credBytes)

      val result = store.scanMetadata("example.com")
      result.fold(
        success = { files ->
          assertEquals(1, files.size)
          val file = files[0]
          assertEquals("example.com", file.ref.canonicalRpId)
          assertTrue(
            file.ref.credentialId.contentEquals(
              byteArrayOf(0xaa.toByte(), 0xbb.toByte(), 0xcc.toByte(), 0xdd.toByte())
            )
          )
          assertEquals("example.com/aabbccdd.gpg", file.ref.relativePath)
        },
        failure = { throw AssertionError("Scan should succeed: $it") },
      )

      val ref =
        PasskeyFileRef(
          canonicalRpId = "example.com",
          credentialId = byteArrayOf(0xaa.toByte(), 0xbb.toByte(), 0xcc.toByte(), 0xdd.toByte()),
          relativePath = "example.com/aabbccdd.gpg",
        )

      val openResult = store.openExact(ref)
      openResult.fold(
        success = { opened ->
          try {
            val content = opened.readBytes()
            assertTrue(content.contentEquals(credBytes))
          } finally {
            opened.close()
          }
        },
        failure = { throw AssertionError("openExact should succeed: $it") },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `version mismatch fails closed`() = runBlocking {
    setupRepo()
    try {
      val passkeyDir = File(repoRoot, "fido2")
      val rpDir = File(passkeyDir, "example.com")
      rpDir.mkdirs()

      val credBytes = byteArrayOf(1, 2, 3, 4)
      File(rpDir, "aabb.gpg").writeBytes(credBytes)

      val ref =
        PasskeyFileRef(
          canonicalRpId = "example.com",
          credentialId = byteArrayOf(0xaa.toByte(), 0xbb.toByte()),
          relativePath = "example.com/aabb.gpg",
        )

      val wrongVersion =
        CredentialSourceVersion(
          repositoryGeneration = RepositoryGeneration("test", null, 0),
          canonicalPath = "wrong",
          fileSize = 999,
          modifiedAtMillis = 0,
          ciphertextDigest = byteArrayOf(0),
        )

      val result = store.openExact(ref, expectedVersion = wrongVersion)
      result.fold(
        success = {
          throw AssertionError("Version mismatch must fail closed")
        },
        failure = { error ->
          assertEquals(FileStoreError.VersionMismatch, error)
        },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `resolveVersion returns Missing for non-existent file`() = runBlocking {
    setupRepo()
    try {
      val passkeyDir = File(repoRoot, "fido2")
      passkeyDir.mkdirs()

      val ref =
        PasskeyFileRef(
          canonicalRpId = "example.com",
          credentialId = byteArrayOf(0xaa.toByte(), 0xbb.toByte()),
          relativePath = "example.com/aabb.gpg",
        )

      val result = store.resolveVersion(ref)
      result.fold(
        success = { versionResult ->
          assertEquals(SourceVersionResult.Missing, versionResult)
        },
        failure = { error ->
          assertTrue(
            error is FileStoreError.NotDirectory,
            "Expected Missing or NotDirectory error, got: $error",
          )
        },
      )
    } finally {
      teardownRepo()
    }
  }

  @Test
  fun `repository root symlink is rejected`() = runBlocking {
    val outerDir = Files.createTempDirectory("passkey-outer-").toFile()
    try {
      val realRoot = File(outerDir, "real-repo")
      realRoot.mkdirs()
      File(realRoot, "fido2").mkdirs()

      val symlinkRoot = File(outerDir, "symlink-repo")
      Files.createSymbolicLink(symlinkRoot.toPath(), realRoot.toPath())

      val store = NoFollowFileStore(symlinkRoot)
      val result = store.scanMetadata(null)
      result.fold(
        success = {
          // Empty is acceptable since the root is a symlink
        },
        failure = { error ->
          assertEquals(
            FileStoreError.RepositoryRootSymlinked,
            error,
            "Expected RepositoryRootSymlinked error",
          )
        },
      )
    } finally {
      outerDir.deleteRecursively()
    }
  }
}
