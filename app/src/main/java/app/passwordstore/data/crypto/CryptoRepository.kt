/*
 * Copyright © 2014-2024 The Android Password Store Authors. All Rights Reserved.
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
import com.github.michaelbull.result.onSuccess
import com.github.michaelbull.result.runCatching
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
    identities: List<PGPIdentifier>,
    passphrases: List<CharArray?>,
  ): Triple<List<PGPIdentifier>, List<PGPKey>, CharArray?> {
    identities.forEach { id ->
      val key = pgpKeyManager.getKeyById(id).unwrap()
      passphrases.forEach { passphrase ->
        runCatching { pgpCryptoHandler.passphraseIsCorrect(key, passphrase) }
          .onSuccess {
            return Triple(listOf(id), listOf(key), passphrase)
          }
      }
    }
    // Last resort if one of the keys is a "stripped" one
    identities.forEach { id ->
      val key = pgpKeyManager.getKeyById(id).unwrap()
      if (!pgpCryptoHandler.isPassphraseProtected(listOf(key))) {
        return Triple(listOf(id), listOf(key), passphrases.first())
      }
    }
    val keys = identities.map { pgpKeyManager.getKeyById(it) }.filterValues()
    return Triple(identities, keys, null)
  }

  suspend fun decrypt(
    passphrases: List<CharArray?>,
    identities: List<PGPIdentifier>,
    message: ByteArrayInputStream,
    out: ByteArrayOutputStream,
  ) =
    withContext(dispatcherProvider.io()) {
      val (matchingKeyId, matchingKey, matchingPassphrase) =
        findFirstMatchingIdKeyPassphrase(identities, passphrases)
      val decryptionOptions = PGPDecryptOptions.Builder().build()
      Pair(
        matchingKeyId,
        pgpCryptoHandler
          .decrypt(matchingKey, matchingPassphrase, message, out, decryptionOptions)
          .map { out },
      )
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
