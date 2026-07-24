/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public sealed interface FileStoreError {
  public val message: String

  public data object SymlinkInPath : FileStoreError {
    override val message: String = "Symlink detected in path component"
  }

  public data object PathOutsideRepository : FileStoreError {
    override val message: String = "Resolved path is outside the repository root"
  }

  public data object NotRegularFile : FileStoreError {
    override val message: String = "Target is not a regular file"
  }

  public data object NotDirectory : FileStoreError {
    override val message: String = "Expected directory but found non-directory"
  }

  public data object FileNotFound : FileStoreError {
    override val message: String = "File not found at expected path"
  }

  public data object DuplicateCredentialId : FileStoreError {
    override val message: String = "Duplicate credential ID detected in multiple locations"
  }

  public data object MalformedPath : FileStoreError {
    override val message: String = "Path contains invalid components"
  }

  public data object RepositoryRootSymlinked : FileStoreError {
    override val message: String = "Repository root itself is a symlink or has been replaced"
  }

  public data object VersionMismatch : FileStoreError {
    override val message: String = "File version changed between validation and operation"
  }

  public data object RootChanged : FileStoreError {
    override val message: String = "Repository root has changed since validation"
  }

  public data class DurabilityIndeterminate(
    val observedVersion: DurableFileVersion? = null,
    override val message: String =
      "Durability could not be verified; observed version: ${observedVersion?.canonicalPath ?: "unknown"}",
  ) : FileStoreError

  public data class IoError(override val message: String) : FileStoreError

  public data class PayloadBindingMismatch(override val message: String) : FileStoreError
}
