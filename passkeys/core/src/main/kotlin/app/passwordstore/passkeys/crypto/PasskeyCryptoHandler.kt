/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.security.SensitiveBytes
import com.github.michaelbull.result.Result

public interface PasskeyCryptoHandler {

  public fun generateKeyPair(): Pair<ByteArray, ByteArray>

  public fun sign(
    privateKey: ByteArray,
    authenticatorData: ByteArray,
    clientDataHash: ByteArray,
  ): Result<ByteArray, Throwable>

  public fun verify(
    publicKey: ByteArray,
    signature: ByteArray,
    authenticatorData: ByteArray,
    clientDataHash: ByteArray,
  ): Result<Boolean, Throwable>

  public fun createCredential(
    rpId: String,
    userId: ByteArray,
    userName: String,
    userDisplayName: String,
    challenge: ByteArray,
  ): Result<CreatedPasskeyCredential, Throwable>

  public fun getAssertion(
    credential: PasskeyCredential,
    privateKey: ByteArray,
    rpId: String,
    challenge: ByteArray,
    origin: String,
    userVerified: Boolean = true,
  ): Result<AssertionResult, Throwable>

  public fun getAssertionWithFrameworkHash(
    credential: PasskeyCredential,
    privateKey: ByteArray,
    rpId: String,
    clientDataHash: ByteArray,
    responseClientDataJson: ByteArray,
    userVerified: Boolean = true,
  ): Result<AssertionResult, Throwable>

  public fun signAssertion(
    privateKey: ByteArray,
    authenticatorData: ByteArray,
    clientDataHash: ByteArray,
  ): Result<ByteArray, Throwable>

  public fun derivePublicKey(privateKey: ByteArray): Result<ByteArray, Throwable>
}

public class CreatedPasskeyCredential(
  public val credential: PasskeyCredential,
  private val privateKey: SensitiveBytes,
) : AutoCloseable {

  public fun <T> usePrivateKey(block: (ByteArray) -> T): T {
    return privateKey.borrow { key -> block(key) }
  }

  public suspend fun <T> usePrivateKeySuspend(block: suspend (ByteArray) -> T): T {
    return privateKey.borrow { key -> block(key) }
  }

  override fun close() {
    privateKey.close()
  }

  override fun toString(): String =
    "CreatedPasskeyCredential(credential=$credential, privateKey=<REDACTED>)"
}

public data class AssertionResult(
  public val credentialId: ByteArray,
  public val authenticatorData: ByteArray,
  public val signature: ByteArray,
  public val userHandle: ByteArray?,
  public val clientDataJSON: ByteArray,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is AssertionResult) return false
    if (!credentialId.contentEquals(other.credentialId)) return false
    if (!authenticatorData.contentEquals(other.authenticatorData)) return false
    if (!signature.contentEquals(other.signature)) return false
    if (userHandle != null) {
      if (other.userHandle == null) return false
      if (!userHandle.contentEquals(other.userHandle)) return false
    } else if (other.userHandle != null) return false
    if (!clientDataJSON.contentEquals(other.clientDataJSON)) return false
    return true
  }

  override fun hashCode(): Int {
    var result = credentialId.contentHashCode()
    result = 31 * result + authenticatorData.contentHashCode()
    result = 31 * result + signature.contentHashCode()
    result = 31 * result + (userHandle?.contentHashCode() ?: 0)
    result = 31 * result + clientDataJSON.contentHashCode()
    return result
  }
}
