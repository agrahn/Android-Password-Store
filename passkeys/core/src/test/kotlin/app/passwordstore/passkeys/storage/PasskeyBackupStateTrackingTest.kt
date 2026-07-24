/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.getOrElse
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlinx.coroutines.runBlocking

class PasskeyBackupStateTrackingTest {

  @Test
  fun `newly created storage has no backup state`() {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())

    assertFalse(storage.isRepositoryBackedUp())
    assertFalse(storage.isInMergeConflict())
  }

  @Test
  fun `successful sync with remote sets backup state`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(true)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )

    assertTrue(storage.isRepositoryBackedUp())
  }

  @Test
  fun `sync without remote does not set backup state`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(false)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )

    assertFalse(storage.isRepositoryBackedUp())
  }

  @Test
  fun `sync with no head change does not set backup state`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(true)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "abc123",
        worktreeChanged = false,
        conflicts = emptyList(),
      )
    )

    assertFalse(storage.isRepositoryBackedUp())
  }

  @Test
  fun `credential save resets backup state`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(true)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )
    assertTrue(storage.isRepositoryBackedUp())

    storage.onCredentialSaved()
    assertFalse(storage.isRepositoryBackedUp())
  }

  @Test
  fun `credential update resets backup state`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(true)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )
    assertTrue(storage.isRepositoryBackedUp())

    storage.onCredentialUpdated()
    assertFalse(storage.isRepositoryBackedUp())
  }

  @Test
  fun `merge conflict resets backup state`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(true)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )
    assertTrue(storage.isRepositoryBackedUp())

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "def456",
        newHead = "ghi789",
        worktreeChanged = true,
        conflicts = listOf("fido2/example.com/cred.gpg"),
      )
    )

    assertFalse(storage.isRepositoryBackedUp())
    assertTrue(storage.isInMergeConflict())
  }

  @Test
  fun `effectiveBackupState returns false for device-bound credential`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(true)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )

    assertFalse(storage.effectiveBackupState(credentialBackupEligible = false))
  }

  @Test
  fun `effectiveBackupState returns true for syncable credential after push`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(true)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )

    assertTrue(storage.effectiveBackupState(credentialBackupEligible = true))
  }

  @Test
  fun `effectiveBackupState returns false during merge conflict`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(true)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = listOf("fido2/example.com/cred.gpg"),
      )
    )

    assertFalse(storage.effectiveBackupState(credentialBackupEligible = true))
  }

  @Test
  fun `repository reinitialize resets backup state`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(true)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )
    assertTrue(storage.isRepositoryBackedUp())

    storage.onRepositoryReinitialized()
    assertFalse(storage.isRepositoryBackedUp())
  }

  @Test
  fun `credential delete resets backup state`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(true)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )
    assertTrue(storage.isRepositoryBackedUp())

    storage.onCredentialDeleted()
    assertFalse(storage.isRepositoryBackedUp())
  }

  @Test
  fun `gpg id change resets backup state`() = runBlocking {
    val storage = IndexedPasskeyStorage(InMemoryPasskeyStorage())
    storage.setHasRemote(true)

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "abc123",
        newHead = "def456",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )
    assertTrue(storage.isRepositoryBackedUp())

    storage.onGpgIdChanged()
    assertFalse(storage.isRepositoryBackedUp())
  }

  @Test
  fun `full lifecycle - create, push, assert, modify, push again`() = runBlocking {
    val innerStorage = InMemoryPasskeyStorage()
    val storage = IndexedPasskeyStorage(innerStorage)
    storage.setHasRemote(true)

    val privateKey = ByteArray(32) { it.toByte() }
    val credential =
      PasskeyCredential(
        credentialId = ByteArray(32) { it.toByte() },
        publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
        rpId = "example.com",
        user = FidoUser(id = "uid".toByteArray(), name = "user", displayName = "User"),
        createdAt = Clock.System.now(),
        backupEligible = true,
        backupState = false,
      )

    innerStorage.saveCredential(credential, privateKey).getOrElse {
      throw AssertionError("Save failed")
    }
    storage.onCredentialSaved()
    assertFalse(storage.isRepositoryBackedUp(), "After save, not backed up")
    assertFalse(
      storage.effectiveBackupState(credential.backupEligible),
      "Effective BS should be false before push",
    )

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = null,
        newHead = "commit1",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )
    assertTrue(storage.isRepositoryBackedUp(), "After push, backed up")
    assertTrue(
      storage.effectiveBackupState(credential.backupEligible),
      "Effective BS should be true after push",
    )

    storage.onCredentialUpdated()
    assertFalse(storage.isRepositoryBackedUp(), "After local update, not backed up")
    assertFalse(
      storage.effectiveBackupState(credential.backupEligible),
      "Effective BS should be false after local modification",
    )

    storage.onGitSyncCompleted(
      GitSyncResult(
        oldHead = "commit1",
        newHead = "commit2",
        worktreeChanged = true,
        conflicts = emptyList(),
      )
    )
    assertTrue(storage.isRepositoryBackedUp(), "After second push, backed up again")
    assertTrue(
      storage.effectiveBackupState(credential.backupEligible),
      "Effective BS should be true after second push",
    )
  }
}
