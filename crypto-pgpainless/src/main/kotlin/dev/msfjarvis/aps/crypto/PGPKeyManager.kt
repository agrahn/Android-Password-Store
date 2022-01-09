/*
 * Copyright © 2014-2021 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("BlockingMethodInNonBlockingContext")

package dev.msfjarvis.aps.crypto

import androidx.annotation.VisibleForTesting
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.runCatching
import dev.msfjarvis.aps.crypto.KeyUtils.tryGetId
import dev.msfjarvis.aps.crypto.KeyUtils.tryParseKeyring
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import org.pgpainless.util.selection.userid.SelectUserId

public class PGPKeyManager
@Inject
constructor(
  filesDir: String,
  private val dispatcher: CoroutineDispatcher,
) : KeyManager {

  private val keyDir = File(filesDir, KEY_DIR_NAME)

  override suspend fun addKey(key: Key, replace: Boolean): Result<Key, Throwable> =
    withContext(dispatcher) {
      runCatching {
        if (!keyDirExists()) throw KeyManagerException.KeyDirectoryUnavailableException
        if (tryParseKeyring(key) == null) throw KeyManagerException.InvalidKeyException
        val keyFile = File(keyDir, "${tryGetId(key)}.$KEY_EXTENSION")
        if (keyFile.exists()) {
          // Check for replace flag first and if it is false, throw an error
          if (!replace)
            throw KeyManagerException.KeyAlreadyExistsException(
              tryGetId(key) ?: "Failed to retrieve key ID"
            )
          if (!keyFile.delete()) throw KeyManagerException.KeyDeletionFailedException
        }

        keyFile.writeBytes(key.contents)

        key
      }
    }

  override suspend fun removeKey(key: Key): Result<Key, Throwable> =
    withContext(dispatcher) {
      runCatching {
        if (!keyDirExists()) throw KeyManagerException.KeyDirectoryUnavailableException
        if (tryParseKeyring(key) == null) throw KeyManagerException.InvalidKeyException
        val keyFile = File(keyDir, "${tryGetId(key)}.$KEY_EXTENSION")
        if (keyFile.exists()) {
          if (!keyFile.delete()) throw KeyManagerException.KeyDeletionFailedException
        }

        key
      }
    }

  override suspend fun getKeyById(id: String): Result<Key, Throwable> =
    withContext(dispatcher) {
      runCatching {
        if (!keyDirExists()) throw KeyManagerException.KeyDirectoryUnavailableException
        val keyFiles = keyDir.listFiles()
        if (keyFiles.isNullOrEmpty()) throw KeyManagerException.NoKeysAvailableException

        val keys = keyFiles.map { file -> Key(file.readBytes()) }
        // Try to parse the key ID as an email
        val selector = SelectUserId.byEmail(id)
        val userIdMatch =
          keys.map { key -> key to tryParseKeyring(key) }.firstOrNull { (_, keyRing) ->
            selector.firstMatch(keyRing) != null
          }

        if (userIdMatch != null) {
          return@runCatching userIdMatch.first
        }

        val keyIdMatch =
          keys.map { key -> key to tryGetId(key) }.firstOrNull { (_, keyId) ->
            keyId == id || keyId == "0x$id"
          }

        if (keyIdMatch != null) {
          return@runCatching keyIdMatch.first
        }

        throw KeyManagerException.KeyNotFoundException(id)
      }
    }

  override suspend fun getAllKeys(): Result<List<Key>, Throwable> =
    withContext(dispatcher) {
      runCatching {
        if (!keyDirExists()) throw KeyManagerException.KeyDirectoryUnavailableException
        val keyFiles = keyDir.listFiles()
        if (keyFiles.isNullOrEmpty()) return@runCatching emptyList()
        keyFiles.map { keyFile -> Key(keyFile.readBytes()) }.toList()
      }
    }

  override suspend fun getKeyId(key: Key): String? = tryGetId(key)

  // TODO: This is a temp hack for now and in future it should check that the GPGKeyManager can
  // decrypt the file.
  override fun canHandle(fileName: String): Boolean {
    return fileName.endsWith(KEY_EXTENSION)
  }

  /** Checks if [keyDir] exists and attempts to create it if not. */
  private fun keyDirExists(): Boolean {
    return keyDir.exists() || keyDir.mkdirs()
  }

  public companion object {

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal const val KEY_DIR_NAME: String = "keys"
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    internal const val KEY_EXTENSION: String = "key"
  }
}
