/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.content.SharedPreferences
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPDecryptOptions
import app.passwordstore.crypto.PGPEncryptOptions
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.crypto.PGPainlessCryptoHandler
import app.passwordstore.injection.prefs.SettingsPreferences
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.filterValues
import com.github.michaelbull.result.map
import com.github.michaelbull.result.mapBoth
import com.github.michaelbull.result.unwrap
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.inject.Inject
import kotlinx.coroutines.withContext

inline fun <T, R> List<T>.mapUntil(predicate: (R) -> Boolean, transform: (T) -> R): List<R> {
  val result = ArrayList<R>()
  for (element in this) {
    val mapped = transform(element)
    result.add(mapped)
    if (predicate(mapped)) break
  }
  return result
}

class CryptoRepository
@Inject
constructor(
  private val pgpKeyManager: PGPKeyManager,
  private val pgpCryptoHandler: PGPainlessCryptoHandler,
  private val dispatcherProvider: DispatcherProvider,
  @SettingsPreferences private val settings: SharedPreferences,
) {

  suspend fun hasKeys(): Boolean {
    return withContext(dispatcherProvider.io()) {
      pgpKeyManager.getAllKeys().mapBoth(success = { it.isNotEmpty() }, failure = { false })
    }
  }

  suspend fun hasKey(id: PGPIdentifier): Boolean {
    return withContext(dispatcherProvider.io()) { pgpKeyManager.getKeyById(id).isOk }
  }

  suspend fun hasSecretKey(id: PGPIdentifier): Boolean {
    return withContext(dispatcherProvider.io()) {
      val result = pgpKeyManager.getKeyById(id)
      result.isOk && KeyUtils.isKeyUsableForDecryption(result.value)
    }
  }

  suspend fun isPasswordProtected(identifiers: List<PGPIdentifier>): Boolean {
    val keys = identifiers.map { pgpKeyManager.getKeyById(it) }.filterValues()
    return pgpCryptoHandler.isPassphraseProtected(keys)
  }

  suspend fun decrypt(
    passphrases: Map<String, CharArray>,
    identities: List<PGPIdentifier>,
    message: ByteArrayInputStream,
    out: ByteArrayOutputStream,
  ) =
    withContext(dispatcherProvider.io()) {
      if (passphrases.keys.first() == "") { // New passphrase from user input
        // Test it against the PGP identities of current entry
        identities
          .mapUntil({ it.second.isOk }) { id ->
            message.reset()
            out.reset()
            val key = pgpKeyManager.getKeyById(id).unwrap()
            val decryptionOptions = PGPDecryptOptions.Builder().build()
            val result =
              pgpCryptoHandler.decrypt(
                listOf(key),
                passphrases.values.first(),
                message,
                out,
                decryptionOptions,
              )
            Pair(listOf(id.toString()), result.map { out })
          }
          .last()
      } else { // Get the first working cached passphrase
        passphrases.keys
          .toList()
          .mapUntil({ it.second.isOk }) { id ->
            message.reset()
            out.reset()
            val pgpId = PGPIdentifier.fromString(id)
            val keys =
              pgpId?.let { listOf(pgpKeyManager.getKeyById(pgpId).unwrap()) } ?: listOf<PGPKey>()
            val decryptionOptions = PGPDecryptOptions.Builder().build()
            val result =
              pgpCryptoHandler.decrypt(keys, passphrases[id], message, out, decryptionOptions)
            Pair(listOf(id), result.map { out })
          }
          .last()
      }
    }

  suspend fun decryptSym(
    passphrase: CharArray,
    message: ByteArrayInputStream,
    out: ByteArrayOutputStream,
  ) =
    withContext(dispatcherProvider.io()) {
      val decryptionOptions = PGPDecryptOptions.Builder().build()
      pgpCryptoHandler.decrypt(listOf<PGPKey>(), passphrase, message, out, decryptionOptions).map {
        out
      }
    }

  suspend fun encrypt(
    identities: List<PGPIdentifier>,
    content: ByteArrayInputStream,
    out: ByteArrayOutputStream,
  ) =
    withContext(dispatcherProvider.io()) {
      val encryptionOptions =
        PGPEncryptOptions.Builder()
          .withAsciiArmor(settings.getBoolean(PreferenceKeys.ASCII_ARMOR, false))
          .build()
      val keys = identities.map { id -> pgpKeyManager.getKeyById(id) }.filterValues()
      pgpCryptoHandler.encrypt(keys, null, content, out, encryptionOptions).map { out }
    }

  suspend fun encryptSym(
    passphrase: CharArray,
    content: ByteArrayInputStream,
    out: ByteArrayOutputStream,
  ) =
    withContext(dispatcherProvider.io()) {
      val encryptionOptions =
        PGPEncryptOptions.Builder()
          .withAsciiArmor(settings.getBoolean(PreferenceKeys.ASCII_ARMOR, false))
          .build()
      pgpCryptoHandler.encrypt(listOf<PGPKey>(), passphrase, content, out, encryptionOptions).map {
        out
      }
    }
}
