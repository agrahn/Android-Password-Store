/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.crypto

import android.content.SharedPreferences
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

  suspend fun isPasswordProtected(identifiers: List<PGPIdentifier>): Boolean {
    val keys = identifiers.map { pgpKeyManager.getKeyById(it) }.filterValues()
    return pgpCryptoHandler.isPassphraseProtected(keys)
  }

  private suspend fun findFirstMatchingIdKeyPassphrase(
    passphrases: Map<String, CharArray>,
    identities: List<PGPIdentifier>,
  ): Triple<List<String>, List<PGPKey>, CharArray> {
    if (passphrases.keys.first() == "") { // New passphrase from user input
      // Test it against the PGP identities of current entry
      identities.forEach { id ->
        val key = pgpKeyManager.getKeyById(id).unwrap()
        if (pgpCryptoHandler.passphraseIsCorrect(key, passphrases.values.first()))
          return Triple(listOf(id.toString()), listOf(key), passphrases.values.first())
      }
      // Last resort: A key could be a "stripped" one
      identities.forEach { id ->
        val key = pgpKeyManager.getKeyById(id).unwrap()
        if (!pgpCryptoHandler.isPassphraseProtected(listOf(key))) {
          return Triple(listOf(id.toString()), listOf(key), passphrases.values.first())
        }
      }
    } else { // Get the first working cached passphrase
      passphrases.forEach { (id, pass) ->
        val pgpId = PGPIdentifier.fromString(id)
        pgpId?.let {
          val key = pgpKeyManager.getKeyById(pgpId).unwrap()
          if (pgpCryptoHandler.passphraseIsCorrect(key, pass))
            return Triple(listOf(id), listOf(key), pass)
        }
      }
      // One of the keys could be a "stripped" one
      passphrases.forEach { (id, pass) ->
        val pgpId = PGPIdentifier.fromString(id)
        pgpId?.let {
          val key = pgpKeyManager.getKeyById(pgpId).unwrap()
          if (!pgpCryptoHandler.isPassphraseProtected(listOf(key))) {
            return Triple(listOf(id), listOf(key), pass)
          }
        }
      }
    }
    // Nothing worked
    val keys = identities.map { pgpKeyManager.getKeyById(it) }.filterValues()
    return Triple(identities.map { it.toString() }, keys, charArrayOf())
  }

  suspend fun decrypt(
    passphrases: Map<String, CharArray>,
    identities: List<PGPIdentifier>,
    message: ByteArrayInputStream,
    out: ByteArrayOutputStream,
  ) =
    withContext(dispatcherProvider.io()) {
      val (matchingKeyId, matchingKey, matchingPassphrase) =
        findFirstMatchingIdKeyPassphrase(passphrases, identities)
      val decryptionOptions = PGPDecryptOptions.Builder().build()
      Pair(
        matchingKeyId,
        pgpCryptoHandler
          .decrypt(matchingKey, matchingPassphrase, message, out, decryptionOptions)
          .map { out },
      )
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
      pgpCryptoHandler.encrypt(keys, content, out, encryptionOptions).map { out }
    }
}
