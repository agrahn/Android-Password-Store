/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.errors.CryptoException
import app.passwordstore.crypto.errors.CryptoHandlerException
import com.github.michaelbull.result.Result
import java.io.InputStream
import java.io.OutputStream

/** Generic interface to implement cryptographic operations on top of. */
public interface CryptoHandler<Key, EncOpts : CryptoOptions, DecryptOpts : CryptoOptions> {

  public fun passphraseIsCorrect(key: Key, passphrase: CharArray?): Boolean

  /**
   * Decrypt the given [ciphertextStream] using a [key] and a [passphrase], and writes the resultant
   * plaintext to [outputStream]. The returned [Result] should be checked to ensure it is **not** an
   * instance of [com.github.michaelbull.result.Err] before the contents of [outputStream] are used.
   */
  public fun decrypt(
    key: Key?,
    passphrase: CharArray?,
    ciphertextStream: InputStream,
    outputStream: OutputStream,
    options: DecryptOpts,
  ): Result<Unit, CryptoHandlerException>

  /**
   * Encrypt the given [plaintextStream] to the provided [keys], and writes the encrypted ciphertext
   * to [outputStream]. The returned [Result] should be checked to ensure it is **not** an instance
   * of [com.github.michaelbull.result.Err] before the contents of [outputStream] are used. A list
   * of keys is returned for which the message was successfully encrypted. If [passphrase] is
   * provided, [keys] are ignored and [plaintextStream] is symmetrically encrypted to
   * [outputStream].
   */
  public fun encrypt(
    keys: List<Key>,
    passphrase: CharArray?,
    plaintextStream: InputStream,
    outputStream: OutputStream,
    options: EncOpts,
  ): Result<List<Key>, CryptoException>

  /** Given a [fileName], return whether this instance can handle it. */
  public fun canHandle(fileName: String): Boolean

  /**
   * Inspects the given [keys] and returns `false` if none of them require a passphrase to decrypt.
   */
  public fun isPassphraseProtected(keys: List<Key>): Boolean
}
