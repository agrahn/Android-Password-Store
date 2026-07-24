/*
 * Copyright (C) 2014-2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

public sealed interface PasskeyDecryptionError {
  public data object NoRecipientPackets : PasskeyDecryptionError

  public data class MissingSecretKey(val recipientIds: Set<String>) : PasskeyDecryptionError

  public data class KeyLocked(val keyId: String) : PasskeyDecryptionError

  public data class IncorrectPassphrase(val keyId: String) : PasskeyDecryptionError

  public data object IntegrityCheckFailed : PasskeyDecryptionError

  public data object MalformedCiphertext : PasskeyDecryptionError

  public data class UnsupportedFormat(val reason: String) : PasskeyDecryptionError

  public data class CiphertextTooLarge(val actual: Long, val maximum: Long) :
    PasskeyDecryptionError {
    override fun toString(): String = "CiphertextTooLarge(actual=$actual, maximum=$maximum)"
  }

  public data class PlaintextTooLarge(val maximum: Long) : PasskeyDecryptionError {
    override fun toString(): String = "PlaintextTooLarge(maximum=$maximum)"
  }
}
