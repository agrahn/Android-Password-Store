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
import com.github.michaelbull.result.getOrElse
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat

public class IndexedPasskeyStorage(
  private val delegate: PasskeyStorage,
  private val generationProvider: RepositoryGenerationProvider? = null,
) : PasskeyStorage, PasskeyRepositoryState {

  private data class IndexedEntry(
    val metadata: PasskeyMetadata,
    val sourceVersion: CredentialSourceVersion?,
    val fileRef: PasskeyFileRef?,
  )

  private val metadataIndex = ConcurrentHashMap<String, IndexedEntry>()
  private val rpIdIndex = ConcurrentHashMap<String, MutableSet<String>>()
  @Volatile private var indexLoaded = false
  @Volatile private var trackedGeneration: RepositoryGeneration? = null
  @Volatile private var inMergeConflict = false
  @Volatile private var repositoryBackedUp = false
  @Volatile private var hasRemoteConfigured = false
  private val indexLoadMutex = Mutex()

  private fun resetBackupState() {
    repositoryBackedUp = false
  }

  private fun credentialKey(id: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(id)
  }

  private suspend fun ensureIndexLoaded() {
    if (generationProvider == null) {
      loadIndexIfNeeded()
      return
    }
    val currentGen = resolveCurrentGeneration() ?: return
    if (indexLoaded && trackedGeneration == currentGen) return
    indexLoadMutex.withLock {
      if (indexLoaded && trackedGeneration == currentGen) return
      rebuildIndex(currentGen)
    }
  }

  private suspend fun loadIndexIfNeeded() {
    if (indexLoaded) return
    indexLoadMutex.withLock {
      if (indexLoaded) return
      rebuildIndex(trackedGeneration)
    }
  }

  private suspend fun resolveCurrentGeneration(): RepositoryGeneration? {
    val provider = generationProvider ?: return null
    return try {
      RepositoryGeneration(
        repositoryIdentity = provider.repositoryIdentity(),
        gitHead = provider.currentGitHead(),
        worktreeGeneration = provider.currentWorktreeGeneration(),
      )
    } catch (e: Exception) {
      logcat(LogPriority.WARN) { "Failed to resolve repository generation: $e" }
      null
    }
  }

  private suspend fun rebuildIndex(generation: RepositoryGeneration?) {
    withContext(Dispatchers.IO) {
      metadataIndex.clear()
      rpIdIndex.clear()
      if (generationProvider != null) {
        inMergeConflict = generationProvider.isInMergeOrRebaseState()
      }
      delegate
        .listMetadataWithRefs()
        .fold(
          success = { entries ->
            entries.forEach { entry ->
              indexMetadata(entry.metadata, entry.sourceVersion, entry.fileRef)
            }
            indexLoaded = true
            trackedGeneration = generation
          },
          failure = { error ->
            logcat(LogPriority.ERROR) { "Failed to load passkey index: $error" }
            indexLoaded = false
          },
        )
    }
  }

  private fun indexMetadata(
    metadata: PasskeyMetadata,
    version: CredentialSourceVersion? = null,
    fileRef: PasskeyFileRef? = null,
  ) {
    val key = credentialKey(metadata.credentialId)
    metadataIndex[key] = IndexedEntry(metadata, version, fileRef)
    rpIdIndex.getOrPut(metadata.rpId) { ConcurrentHashMap.newKeySet() }.add(key)
  }

  private fun removeFromIndex(metadata: PasskeyMetadata) {
    val key = credentialKey(metadata.credentialId)
    metadataIndex.remove(key)
    val rpSet = rpIdIndex[metadata.rpId]
    rpSet?.remove(key)
    if (rpSet?.isEmpty() == true) {
      rpIdIndex.remove(metadata.rpId)
    }
  }

  override suspend fun listMetadata(rpId: String?): Result<List<PasskeyMetadata>, Throwable> {
    ensureIndexLoaded()

    return withContext(Dispatchers.Default) {
      try {
        val metadata =
          if (rpId != null) {
            rpIdIndex[rpId]?.mapNotNull { metadataIndex[it]?.metadata } ?: emptyList()
          } else {
            metadataIndex.values.map { it.metadata }
          }
        Ok(metadata)
      } catch (e: Exception) {
        Err(e)
      }
    }
  }

  override suspend fun listMetadataWithRefs(
    rpId: String?
  ): Result<List<PasskeyMetadataWithRef>, Throwable> {
    ensureIndexLoaded()

    return withContext(Dispatchers.Default) {
      try {
        val entries =
          if (rpId != null) {
            rpIdIndex[rpId]?.mapNotNull { metadataIndex[it] } ?: emptyList()
          } else {
            metadataIndex.values.toList()
          }
        Ok(
          entries.map { entry ->
            PasskeyMetadataWithRef(
              metadata = entry.metadata,
              fileRef = entry.fileRef,
              sourceVersion = entry.sourceVersion,
            )
          }
        )
      } catch (e: Exception) {
        Err(e)
      }
    }
  }

  override suspend fun loadForSigning(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable> {
    val key = credentialKey(credentialId)
    val entry = metadataIndex[key]

    return if (entry?.fileRef != null) {
      delegate.loadForSigningExact(entry.fileRef, entry.sourceVersion)
    } else {
      delegate.loadForSigning(credentialId)
    }
  }

  override suspend fun loadForSigningExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion?,
  ): Result<SensitivePasskeyCredential, Throwable> {
    return delegate.loadForSigningExact(ref, expectedVersion)
  }

  public suspend fun loadForSigningFromIndex(
    credentialId: ByteArray
  ): Result<SensitivePasskeyCredential, Throwable> {
    ensureIndexLoaded()
    val key = credentialKey(credentialId)
    val entry =
      metadataIndex[key] ?: return Err(IllegalArgumentException("Credential not found in index"))

    return if (entry.fileRef != null) {
      delegate.loadForSigningExact(entry.fileRef, entry.sourceVersion)
    } else {
      delegate.loadForSigning(credentialId)
    }
  }

  override suspend fun saveCredential(credential: PasskeyCredential): Result<Unit, Throwable> {
    return delegate.saveCredential(credential).also { result ->
      if (result.isOk) {
        val metadata = PasskeyMetadata.fromPasskeyCredential(credential)
        val version = delegate.resolveSourceVersion(credential.credentialId).getOrElse { null }
        indexMetadata(metadata, version)
        if (generationProvider != null) {
          trackedGeneration = resolveCurrentGeneration()
        }
      }
    }
  }

  override suspend fun deleteCredential(credentialId: ByteArray): Result<Boolean, Throwable> {
    val key = credentialKey(credentialId)
    val entry = metadataIndex[key]

    val deleteResult =
      if (entry?.fileRef != null) {
        delegate.deleteCredentialExact(entry.fileRef)
      } else {
        delegate.deleteCredential(credentialId)
      }

    return deleteResult.fold(
      success = { deleted ->
        if (deleted && entry != null) {
          removeFromIndex(entry.metadata)
        }
        if (deleted && generationProvider != null) {
          trackedGeneration = resolveCurrentGeneration()
        }
        Ok(deleted)
      },
      failure = { Err(it) },
    )
  }

  override suspend fun deleteCredentialExact(ref: PasskeyFileRef): Result<Boolean, Throwable> {
    return delegate
      .deleteCredentialExact(ref)
      .fold(
        success = { deleted ->
          if (deleted) {
            val key = credentialKey(ref.credentialId)
            val entry = metadataIndex[key]
            if (entry != null) {
              removeFromIndex(entry.metadata)
            }
          }
          if (deleted && generationProvider != null) {
            trackedGeneration = resolveCurrentGeneration()
          }
          Ok(deleted)
        },
        failure = { Err(it) },
      )
  }

  override suspend fun updateSignCount(
    credentialId: ByteArray,
    newSignCount: ULong,
  ): Result<Unit, Throwable> {
    val key = credentialKey(credentialId)
    val existing = metadataIndex[key]

    return if (existing != null) {
      delegate.updateSignCount(credentialId, newSignCount).also { result ->
        if (result.isOk) {
          val updatedMetadata = existing.metadata.copy(signCount = newSignCount)
          metadataIndex[key] =
            IndexedEntry(updatedMetadata, existing.sourceVersion, existing.fileRef)
        }
      }
    } else {
      delegate.updateSignCount(credentialId, newSignCount)
    }
  }

  override suspend fun resolveSourceVersion(
    credentialId: ByteArray
  ): Result<CredentialSourceVersion?, Throwable> {
    val key = credentialKey(credentialId)
    val entry = metadataIndex[key]

    return if (entry?.fileRef != null) {
      delegate.resolveSourceVersionExact(entry.fileRef)
    } else {
      delegate.resolveSourceVersion(credentialId)
    }
  }

  override suspend fun resolveSourceVersionExact(
    ref: PasskeyFileRef
  ): Result<CredentialSourceVersion?, Throwable> {
    return delegate.resolveSourceVersionExact(ref)
  }

  public suspend fun getSourceVersion(credentialId: ByteArray): CredentialSourceVersion? {
    val key = credentialKey(credentialId)
    return metadataIndex[key]?.sourceVersion
  }

  public fun getFileRef(credentialId: ByteArray): PasskeyFileRef? {
    val key = credentialKey(credentialId)
    return metadataIndex[key]?.fileRef
  }

  override suspend fun invalidate(reason: InvalidationReason) {
    logcat { "Invalidating passkey index: $reason" }
    indexLoadMutex.withLock {
      metadataIndex.clear()
      rpIdIndex.clear()
      indexLoaded = false
      trackedGeneration = null
    }
  }

  override suspend fun currentGeneration(): RepositoryGeneration {
    return resolveCurrentGeneration()
      ?: RepositoryGeneration(
        repositoryIdentity = "unknown",
        gitHead = null,
        worktreeGeneration = 0L,
      )
  }

  override suspend fun onGitSyncCompleted(syncResult: GitSyncResult) {
    val passkeyConflicts =
      syncResult.conflicts.filter { it.startsWith("fido2/") || it == ".gpg-id" }
    if (passkeyConflicts.isNotEmpty()) {
      inMergeConflict = true
      resetBackupState()
      invalidate(InvalidationReason.MERGE_CONFLICT)
      return
    }
    if (syncResult.headChanged && syncResult.newHead != null && hasRemoteConfigured) {
      repositoryBackedUp = true
    }
    if (syncResult.affectsPasskeys()) {
      invalidate(InvalidationReason.GIT_SYNC_COMPLETED)
    }
  }

  override suspend fun onCredentialSaved() {
    resetBackupState()
    invalidate(InvalidationReason.LOCAL_SAVE)
  }

  override suspend fun onCredentialUpdated() {
    resetBackupState()
    invalidate(InvalidationReason.LOCAL_UPDATE)
  }

  override suspend fun onCredentialDeleted() {
    resetBackupState()
    invalidate(InvalidationReason.LOCAL_DELETE)
  }

  override suspend fun onRepositoryReinitialized() {
    resetBackupState()
    invalidate(InvalidationReason.REPOSITORY_REINITIALIZED)
  }

  override suspend fun onGpgIdChanged() {
    resetBackupState()
    invalidate(InvalidationReason.GPG_ID_CHANGED)
  }

  override fun isInMergeConflict(): Boolean = inMergeConflict

  override fun isRepositoryBackedUp(): Boolean = repositoryBackedUp && !inMergeConflict

  override fun hasRemote(): Boolean = hasRemoteConfigured

  override fun setHasRemote(hasRemote: Boolean) {
    hasRemoteConfigured = hasRemote
  }

  override fun effectiveBackupState(credentialBackupEligible: Boolean): Boolean {
    if (!credentialBackupEligible) return false
    if (inMergeConflict) return false
    return repositoryBackedUp
  }

  public fun clearIndex() {
    metadataIndex.clear()
    rpIdIndex.clear()
    indexLoaded = false
    trackedGeneration = null
    inMergeConflict = false
    repositoryBackedUp = false
  }

  public fun indexedCredentialCount(): Int = metadataIndex.size

  public fun indexedRpIds(): Set<String> = rpIdIndex.keys.toSet()

  public fun hasRpId(rpId: String): Boolean {
    return rpIdIndex.containsKey(rpId)
  }

  public fun credentialCountForRp(rpId: String): Int {
    return rpIdIndex[rpId]?.size ?: 0
  }
}
