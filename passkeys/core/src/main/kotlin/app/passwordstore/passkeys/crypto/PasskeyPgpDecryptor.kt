/*
 * Copyright (C) 2014-2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

import app.passwordstore.passkeys.security.PasskeyInputLimits
import app.passwordstore.passkeys.security.SensitiveBytes
import com.github.michaelbull.result.Result
import java.io.File
import java.io.InputStream

public interface PasskeyPgpDecryptor {

  public suspend fun decrypt(
    file: File,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits = PasskeyInputLimits.DEFAULT,
  ): Result<SensitiveBytes, PasskeyDecryptionError>

  public suspend fun decryptFromBytes(
    ciphertext: ByteArray,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits = PasskeyInputLimits.DEFAULT,
  ): Result<SensitiveBytes, PasskeyDecryptionError> {
    return decrypt(
      java.io.File.createTempFile("passkey-decrypt-", ".tmp").also {
        it.deleteOnExit()
        it.writeBytes(ciphertext)
      },
      unlockContext,
      limits,
    )
  }

  public suspend fun decryptFromStream(
    ciphertextStream: InputStream,
    ciphertextLength: Long,
    unlockContext: PgpUnlockContext,
    limits: PasskeyInputLimits = PasskeyInputLimits.DEFAULT,
  ): Result<SensitiveBytes, PasskeyDecryptionError>
}

public interface PgpUnlockContext {
  public suspend fun unlockKey(keyId: String): CharArray?
}
