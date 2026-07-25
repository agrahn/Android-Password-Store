/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.fold

public interface PasskeyStorage {

  public suspend fun listMetadata(rpId: String? = null): Result<List<PasskeyMetadata>, Throwable>

  public suspend fun loadForSigning(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable>

  public suspend fun loadForSigningExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion? = null,
  ): Result<SensitivePasskeyCredential, Throwable> {
    return loadForSigning(ref.credentialId)
  }

  public suspend fun saveCredential(
    credential: PasskeyCredential,
    privateKey: ByteArray,
  ): Result<Unit, Throwable>

  public suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable>

  public suspend fun deleteCredentialExact(ref: PasskeyFileRef): Result<Boolean, Throwable> {
    return deleteCredential(ref.credentialId)
  }

  public suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable>

  public suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): Result<SourceVersionResult, Throwable> {
    return Ok(SourceVersionResult.Missing)
  }

  public suspend fun resolveSourceVersionExact(
    ref: PasskeyFileRef
  ): Result<SourceVersionResult, Throwable> {
    return resolveSourceVersion(ref.credentialId)
  }

  public suspend fun loadCredentialMetadata(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion? = null,
  ): Result<PasskeyMetadata, Throwable> {
    return loadForSigningExact(ref, expectedVersion)
      .fold(
        success = { credential ->
          credential.use {
            Ok(
              PasskeyMetadata(
                credentialId = credential.credentialId,
                rpId = credential.rpId,
                userName = credential.user.name,
                userDisplayName = credential.user.displayName,
                createdAt = credential.createdAt,
                signCount = credential.signCount,
                backupEligible = credential.backupEligible,
                backupState = credential.backupState,
              )
            )
          }
        },
        failure = { Err(it) },
      )
  }

  public suspend fun listMetadataWithRefs(
    rpId: String? = null
  ): Result<List<PasskeyMetadataWithRef>, Throwable> {
    return listMetadata(rpId)
      .fold(
        success = { list ->
          Ok(list.map { PasskeyMetadataWithRef(metadata = it, fileRef = null) })
        },
        failure = { Err(it) },
      )
  }
}

public data class PasskeyStorageConfig(
  public val passkeyDirectory: String = "fido2",
  public val fileExtension: String = ".gpg",
)

public data class PasskeyMetadataWithRef(
  val metadata: PasskeyMetadata,
  val fileRef: PasskeyFileRef?,
  val sourceVersion: CredentialSourceVersion? = null,
)

internal fun hexToBytes(hex: String): ByteArray? {
  if (hex.length % 2 != 0) return null
  return try {
    ByteArray(hex.length / 2) { i ->
      hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
  } catch (_: Exception) {
    null
  }
}

internal fun sanitizeRpId(rpId: String): String {
  val sanitized = rpId.filter { it.isLetterOrDigit() || it == '.' || it == '-' }
  return sanitized.ifEmpty { "_" }
}
