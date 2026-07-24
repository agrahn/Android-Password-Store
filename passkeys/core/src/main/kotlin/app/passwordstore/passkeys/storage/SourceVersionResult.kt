/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public sealed interface SourceVersionResult {
  public data class Stable(val version: CredentialSourceVersion) : SourceVersionResult

  public data object Missing : SourceVersionResult

  public data class Unavailable(val reason: SourceVersionError) : SourceVersionResult
}

public sealed interface SourceVersionError {
  public data object RepositoryRootSymlinked : SourceVersionError

  public data object IoError : SourceVersionError

  public data class FilesystemError(val detail: String) : SourceVersionError
}
