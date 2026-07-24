/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import app.passwordstore.passkeys.model.PasskeyMetadata
import app.passwordstore.passkeys.model.SensitivePasskeyCredential
import app.passwordstore.passkeys.security.SensitiveBytes
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import java.security.MessageDigest
import kotlin.time.Clock
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

public class InMemoryPasskeyStorage : PasskeyStorage {

  private val publicCredentials = mutableMapOf<String, PasskeyCredential>()
  private val privateKeys = mutableMapOf<String, ByteArray>()
  private val modificationTimestamps = mutableMapOf<String, Long>()

  private fun credentialIdKey(id: ByteArray): String {
    return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(id)
  }

  override suspend fun listMetadata(rpId: String?): Result<List<PasskeyMetadata>, Throwable> =
    withContext(Dispatchers.Default) {
      val filtered =
        if (rpId != null) {
          publicCredentials.values.filter { it.rpId == rpId }
        } else {
          publicCredentials.values.toList()
        }
      Ok(filtered.map { PasskeyMetadata.fromPasskeyCredential(it) })
    }

  override suspend fun loadForSigning(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable> =
    withContext(Dispatchers.Default) {
      val key = credentialIdKey(credentialId)
      val credential = publicCredentials[key]
      val privateKey = privateKeys[key]
      if (credential != null && privateKey != null) {
        Ok(
          SensitivePasskeyCredential(
            credentialId = credential.credentialId.copyOf(),
            publicKey = credential.publicKey.copyOf(),
            rpId = credential.rpId,
            user = credential.user,
            signCount = credential.signCount,
            createdAt = credential.createdAt,
            transports = credential.transports,
            uvInitialized = credential.uvInitialized,
            backupEligible = credential.backupEligible,
            backupState = credential.backupState,
            fileLastModified = 0L,
            privateKey = SensitiveBytes(privateKey.copyOf()),
          )
        )
      } else {
        Err(IllegalArgumentException("Credential not found"))
      }
    }

  override suspend fun saveCredential(
    credential: PasskeyCredential,
    privateKey: ByteArray,
  ): Result<Unit, Throwable> =
    withContext(Dispatchers.Default) {
      val key = credentialIdKey(credential.credentialId)
      publicCredentials[key] = credential
      privateKeys[key] = privateKey.copyOf()
      modificationTimestamps[key] = Clock.System.now().toEpochMilliseconds()
      Ok(Unit)
    }

  override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> =
    withContext(Dispatchers.Default) {
      val key = credentialIdKey(credentialId)
      val existed = publicCredentials.containsKey(key)
      publicCredentials.remove(key)
      privateKeys[key]?.fill(0)
      privateKeys.remove(key)
      modificationTimestamps.remove(key)
      Ok(existed)
    }

  override suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable> =
    withContext(Dispatchers.Default) {
      val key = credentialIdKey(credentialId)
      val existing = publicCredentials[key]
      if (existing != null) {
        publicCredentials[key] = existing.copy(signCount = newSignCount)
        Ok(Unit)
      } else {
        Err(IllegalArgumentException("Credential not found"))
      }
    }

  override suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): Result<SourceVersionResult, Throwable> =
    withContext(Dispatchers.Default) {
      val key = credentialIdKey(credentialId)
      val credential = publicCredentials[key]
      val privateKey = privateKeys[key]
      if (credential != null && privateKey != null) {
        val digest = MessageDigest.getInstance("SHA-256").digest(privateKey)
        val modTime = modificationTimestamps[key] ?: 0L
        Ok(
          SourceVersionResult.Stable(
            CredentialSourceVersion(
              repositoryGeneration =
                RepositoryGeneration(
                  repositoryIdentity = "in-memory",
                  gitHead = null,
                  worktreeGeneration = publicCredentials.size.toLong(),
                ),
              canonicalPath = "in-memory://$key",
              fileSize = privateKey.size.toLong(),
              modifiedAtMillis = modTime,
              ciphertextDigest = digest,
            )
          )
        )
      } else {
        Ok(SourceVersionResult.Missing)
      }
    }

  override suspend fun listMetadataWithRefs(
    rpId: String?
  ): Result<List<PasskeyMetadataWithRef>, Throwable> =
    withContext(Dispatchers.Default) {
      val filtered =
        if (rpId != null) {
          publicCredentials.values.filter { it.rpId == rpId }
        } else {
          publicCredentials.values.toList()
        }
      val results = filtered.map { cred ->
        val metadata = PasskeyMetadata.fromPasskeyCredential(cred)
        val key = credentialIdKey(cred.credentialId)
        val privateKey = privateKeys[key]
        val ref =
          PasskeyFileRef(
            canonicalRpId = cred.rpId,
            credentialId = cred.credentialId.copyOf(),
            relativePath =
              "${sanitizeRpId(cred.rpId)}/${cred.credentialId.joinToString("") { "%02x".format(it) }}.gpg",
          )
        val version =
          if (privateKey != null) {
            val digest = MessageDigest.getInstance("SHA-256").digest(privateKey)
            val modTime = modificationTimestamps[key] ?: 0L
            CredentialSourceVersion(
              repositoryGeneration =
                RepositoryGeneration("in-memory", null, publicCredentials.size.toLong()),
              canonicalPath = "in-memory://$key",
              fileSize = privateKey.size.toLong(),
              modifiedAtMillis = modTime,
              ciphertextDigest = digest,
            )
          } else null
        PasskeyMetadataWithRef(metadata = metadata, fileRef = ref, sourceVersion = version)
      }
      Ok(results)
    }

  override suspend fun loadForSigningExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion?,
  ): Result<SensitivePasskeyCredential, Throwable> = loadForSigning(ref.credentialId)

  override suspend fun resolveSourceVersionExact(
    ref: PasskeyFileRef
  ): Result<SourceVersionResult, Throwable> = resolveSourceVersion(ref.credentialId)

  override suspend fun deleteCredentialExact(ref: PasskeyFileRef): Result<Boolean, Throwable> =
    deleteCredential(ref.credentialId)

  public fun clear() {
    publicCredentials.clear()
    privateKeys.values.forEach { it.fill(0) }
    privateKeys.clear()
    modificationTimestamps.clear()
  }

  public fun count(): Int = publicCredentials.size

  public companion object {
    public fun withTestCredentials(
      vararg creds: Pair<PasskeyCredential, ByteArray>
    ): InMemoryPasskeyStorage {
      val storage = InMemoryPasskeyStorage()
      creds.forEach { (cred, key) ->
        val k = storage.credentialIdKey(cred.credentialId)
        storage.publicCredentials[k] = cred
        storage.privateKeys[k] = key.copyOf()
        storage.modificationTimestamps[k] = Clock.System.now().toEpochMilliseconds()
      }
      return storage
    }

    public fun createTestCredential(
      rpId: String = "example.com",
      userName: String = "testuser",
      credentialId: ByteArray = "test-cred-id".toByteArray(),
    ): Pair<PasskeyCredential, ByteArray> {
      val privateKey = ByteArray(32) { it.toByte() }
      val credential =
        PasskeyCredential(
          credentialId = credentialId,
          publicKey = ByteArray(65) { if (it == 0) 0x04.toByte() else it.toByte() },
          rpId = rpId,
          user = FidoUser(id = "user-id".toByteArray(), name = userName, displayName = "Test User"),
          signCount = 0u,
          createdAt = Clock.System.now(),
          transports = listOf("internal"),
          uvInitialized = true,
        )
      return credential to privateKey
    }
  }
}
