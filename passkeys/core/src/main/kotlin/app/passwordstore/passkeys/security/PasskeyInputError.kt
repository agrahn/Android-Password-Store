/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.security

public sealed interface PasskeyInputError {
  public val message: String

  public data object EmptyCiphertext : PasskeyInputError {
    override val message: String = "Ciphertext file is empty"
  }

  public data class CiphertextTooLarge(val actual: Long, val maximum: Long) : PasskeyInputError {
    override val message: String = "Ciphertext size $actual exceeds maximum $maximum bytes"
  }

  public data class PlaintextTooLarge(val maximum: Long) : PasskeyInputError {
    override val message: String = "Plaintext exceeds maximum $maximum bytes"
  }

  public data class AssetLinksTooLarge(val maximum: Long) : PasskeyInputError {
    override val message: String = "Asset Links response exceeds maximum $maximum bytes"
  }

  public data class TooManyAssetLinkStatements(val maximum: Int) : PasskeyInputError {
    override val message: String = "Asset Links statement count exceeds maximum $maximum"
  }

  public data class TooManyAssetLinkRelations(val maximum: Int) : PasskeyInputError {
    override val message: String = "Asset Links relation count exceeds maximum $maximum"
  }

  public data class TooManyAssetLinkFingerprints(val maximum: Int) : PasskeyInputError {
    override val message: String = "Asset Links fingerprint count exceeds maximum $maximum"
  }

  public data class CborLimitExceeded(val kind: String, val maximum: Long) : PasskeyInputError {
    override val message: String = "CBOR limit exceeded: $kind (max $maximum)"
  }

  public data object TrailingCborData : PasskeyInputError {
    override val message: String = "Trailing data after CBOR root object"
  }

  public data object DuplicateCborKey : PasskeyInputError {
    override val message: String = "Duplicate key in CBOR map"
  }

  public data object OperationCancelled : PasskeyInputError {
    override val message: String = "Operation was cancelled"
  }
}
