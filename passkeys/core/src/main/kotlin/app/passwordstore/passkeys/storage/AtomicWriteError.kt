/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public sealed interface AtomicWriteError {
  public val message: String

  public data object TargetOutsideRepository : AtomicWriteError {
    override val message: String = "Target path is outside the repository root"
  }

  public data object SymlinkRejected : AtomicWriteError {
    override val message: String = "Symlink detected in target, parent, or temp path"
  }

  public data class TempCreateFailed(override val message: String) : AtomicWriteError

  public data class EncryptionFailed(override val message: String) : AtomicWriteError

  public data class FileSyncFailed(override val message: String) : AtomicWriteError

  public data object AtomicMoveUnsupported : AtomicWriteError {
    override val message: String = "Atomic file move is not supported on this filesystem"
  }

  public data class RenameFailed(override val message: String) : AtomicWriteError

  public data object ConcurrentModification : AtomicWriteError {
    override val message: String = "Concurrent modification detected for this credential"
  }

  public data class VerificationFailed(override val message: String) : AtomicWriteError

  public data class DurabilityIndeterminate(
    val observedVersion: DurableFileVersion? = null,
    override val message: String =
      "Durability could not be verified; observed version: ${observedVersion?.canonicalPath ?: "unknown"}",
  ) : AtomicWriteError

  public data class IoError(override val message: String) : AtomicWriteError
}
