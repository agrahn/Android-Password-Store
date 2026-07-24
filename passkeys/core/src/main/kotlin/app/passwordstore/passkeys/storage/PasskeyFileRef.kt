/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public data class PasskeyFileRef(
  val canonicalRpId: String,
  val credentialId: ByteArray,
  val relativePath: String,
) {

  init {
    require(canonicalRpId.isNotBlank()) { "RP ID must not be blank" }
    require(!canonicalRpId.contains('/')) { "RP ID must not contain path separators" }
    require(!canonicalRpId.contains('\\')) { "RP ID must not contain path separators" }
    require(!canonicalRpId.contains("..")) { "RP ID must not contain path traversal" }
    require(credentialId.isNotEmpty()) { "Credential ID must not be empty" }
    require(relativePath.isNotBlank()) { "Relative path must not be blank" }
    require(!relativePath.startsWith("/")) { "Relative path must not be absolute" }
    require(!relativePath.contains("\\")) { "Relative path must not contain backslashes" }
    validateRelativePathSegments(relativePath)
  }

  public fun credentialIdHex(): String {
    return credentialId.joinToString("") { byte -> "%02x".format(byte) }
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is PasskeyFileRef) return false
    if (canonicalRpId != other.canonicalRpId) return false
    if (!credentialId.contentEquals(other.credentialId)) return false
    if (relativePath != other.relativePath) return false
    return true
  }

  override fun hashCode(): Int {
    var result = canonicalRpId.hashCode()
    result = 31 * result + credentialId.contentHashCode()
    result = 31 * result + relativePath.hashCode()
    return result
  }

  public companion object {
    private const val MAX_DEPTH = 2

    private fun validateRelativePathSegments(path: String) {
      val segments = path.split('/')
      require(segments.size <= MAX_DEPTH) {
        "Relative path exceeds maximum depth of $MAX_DEPTH"
      }
      for (segment in segments) {
        require(segment.isNotBlank()) { "Path must not contain empty segments" }
        require(segment != "." && segment != "..") { "Path must not contain . or .. components" }
        require(!segment.startsWith(".")) { "Path must not contain hidden segments" }
      }
    }

    public fun fromRpIdAndCredentialId(
      rpId: String,
      credentialId: ByteArray,
      sanitizedRpDir: String,
      fileExtension: String,
    ): PasskeyFileRef {
      val hexId = credentialId.joinToString("") { byte -> "%02x".format(byte) }
      val relativePath = "$sanitizedRpDir/$hexId$fileExtension"
      return PasskeyFileRef(
        canonicalRpId = rpId,
        credentialId = credentialId.copyOf(),
        relativePath = relativePath,
      )
    }
  }
}
