/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.model

import app.passwordstore.passkeys.security.SensitiveBytes
import kotlin.time.Instant

public class SensitivePasskeyCredential(
  public val credentialId: ByteArray,
  public val publicKey: ByteArray,
  public val rpId: String,
  public val user: FidoUser,
  public val signCount: ULong,
  public val createdAt: Instant,
  public val transports: List<String>,
  public val uvInitialized: Boolean,
  public val backupEligible: Boolean,
  public val backupState: Boolean,
  public val fileLastModified: Long,
  public val credProtect: Int? = null,
  privateKey: SensitiveBytes,
) : AutoCloseable {

  @Volatile private var privateKey: SensitiveBytes? = privateKey

  public fun <T> usePrivateKey(block: (ByteArray) -> T): T {
    val keyOwner = privateKey ?: throw IllegalStateException("Credential has been closed")
    return keyOwner.borrow { key -> block(key) }
  }

  public suspend fun <T> usePrivateKeySuspend(block: suspend (ByteArray) -> T): T {
    val keyOwner = privateKey ?: throw IllegalStateException("Credential has been closed")
    return keyOwner.borrow { key -> block(key) }
  }

  public fun toPublicCredential(): PasskeyCredential {
    return PasskeyCredential(
      credentialId = credentialId.copyOf(),
      publicKey = publicKey.copyOf(),
      rpId = rpId,
      user = user,
      signCount = signCount,
      createdAt = createdAt,
      transports = transports,
      uvInitialized = uvInitialized,
      backupEligible = backupEligible,
      backupState = backupState,
    )
  }

  override fun close() {
    privateKey?.close()
    privateKey = null
  }

  override fun toString(): String =
    "SensitivePasskeyCredential(credentialId=<redacted>, rpId=$rpId, privateKey=<REDACTED>)"

  public companion object {
    public fun fromStoredCredential(
      stored: StoredCredential,
      fileLastModified: Long = 0L,
    ): SensitivePasskeyCredential {
      val keyCopy = stored.privateKey.copyOf()
      val sensitiveKey = SensitiveBytes(keyCopy)
      val publicKeyCopy =
        stored.publicKey?.copyOf() ?: StoredCredential.deriveP256PublicKey(keyCopy)
      try {
        val result =
          SensitivePasskeyCredential(
            credentialId = stored.id.copyOf(),
            publicKey = publicKeyCopy,
            rpId = stored.rp.id,
            user =
              FidoUser(
                id = stored.user.id.copyOf(),
                name = stored.user.name ?: "",
                displayName = stored.user.displayName ?: "",
              ),
            signCount = stored.signCount.toULong(),
            createdAt = Instant.fromEpochSeconds(stored.created),
            transports = listOf("internal"),
            uvInitialized = true,
            backupEligible = stored.backupEligible,
            backupState = stored.backupState,
            fileLastModified = fileLastModified,
            credProtect = stored.extensions.credProtect,
            privateKey = sensitiveKey,
          )
        stored.wipe()
        return result
      } catch (e: Throwable) {
        sensitiveKey.close()
        throw e
      }
    }
  }
}
