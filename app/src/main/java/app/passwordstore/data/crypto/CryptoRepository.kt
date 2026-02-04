/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
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
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getError
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.map
import com.github.michaelbull.result.mapBoth
import com.github.michaelbull.result.runCatching
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.inject.Inject
import logcat.asLog
import logcat.logcat

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

  fun hasKeys(): Boolean =
    pgpKeyManager.getAllKeys().mapBoth(success = { it.isNotEmpty() }, failure = { false })

  fun hasKey(id: PGPIdentifier): Boolean = pgpKeyManager.getKeyById(id).isOk

  fun isSecretKey(id: PGPIdentifier): Boolean {
    val key = pgpKeyManager.getKeyById(id).get()
    return key != null && KeyUtils.isSecretKey(key)
  }

  fun hasDecKey(id: PGPIdentifier): Boolean {
    val key = pgpKeyManager.getKeyById(id).get()
    return key != null && KeyUtils.hasDecKey(key)
  }

  fun hasAuthKey(id: PGPIdentifier): Boolean {
    val key = pgpKeyManager.getKeyById(id).get()
    return key != null && KeyUtils.hasAuthKey(key)
  }

  fun isPasswordProtected(identifiers: List<PGPIdentifier>, anySubkey: Boolean = false): Boolean {
    val keys = identifiers.map { pgpKeyManager.getKeyById(it) }.filterValues()
    return pgpCryptoHandler.isPassphraseProtected(keys, anySubkey)
  }

  fun isPasswordCorrect(
    identifier: PGPIdentifier,
    passphrase: CharArray?,
    anySubkey: Boolean = false,
  ): Boolean {
    val key = pgpKeyManager.getKeyById(identifier).get() ?: return false
    return pgpCryptoHandler.passphraseIsCorrect(key, passphrase, anySubkey = anySubkey)
  }

  fun getEmailFromKeyId(identifier: PGPIdentifier): String? {
    val key = pgpKeyManager.getKeyById(identifier).get() ?: return null
    val userId = KeyUtils.tryGetUserId(key) ?: return null
    return PGPIdentifier.splitUserId(userId.email)
  }

  fun getUserIdFromKeyId(identifier: PGPIdentifier): String? {
    val key = pgpKeyManager.getKeyById(identifier).get() ?: return null
    return KeyUtils.tryGetUserId(key).toString()
  }

  fun getLongKeyIdFromKeyId(identifier: PGPIdentifier): String? {
    val key = pgpKeyManager.getKeyById(identifier).get() ?: return null
    return KeyUtils.tryGetKeyId(key).toString()
  }

  fun unlockAuthKeyPair(passphrase: CharArray?, identifier: PGPIdentifier) = runCatching {
    val key = pgpKeyManager.getKeyById(identifier).getOrThrow()
    pgpCryptoHandler.unlockJcaAuthKeyPair(key, passphrase).getOrThrow()
  }

  fun decrypt(
    passphrases: Map<String, CharArray?>,
    identities: List<PGPIdentifier>,
    encryptedMessage: ByteArrayInputStream,
    message: ByteArrayOutputStream,
  ) = run {
    if (passphrases.keys.first() == "") { // New passphrase from user input
      // Test it against the PGP identities of current entry
      identities.mapUntil({ it.second.isOk }) { id ->
        encryptedMessage.reset()
        message.reset()
        val key = pgpKeyManager.getKeyById(id).get()
        val decryptionOptions = PGPDecryptOptions.Builder().build()
        val result =
          pgpCryptoHandler.decrypt(
            key,
            passphrases.values.first(),
            encryptedMessage,
            message,
            decryptionOptions,
          )
        result.getError()?.let { logcat { it.asLog() } }
        Pair(id.toString(), result.map { message })
      }
    } else { // Get the first working cached passphrase
      passphrases.keys.toList().mapUntil({ it.second.isOk }) { id ->
        encryptedMessage.reset()
        message.reset()
        val pgpId = PGPIdentifier.fromString(id)
        requireNotNull(pgpId) { "Error while parsing cached PGP identifier \"${id}\"" }
        val key = pgpKeyManager.getKeyById(pgpId).get()
        val decryptionOptions = PGPDecryptOptions.Builder().build()
        val result =
          pgpCryptoHandler.decrypt(
            key,
            passphrases[id],
            encryptedMessage,
            message,
            decryptionOptions,
          )
        result.getError()?.let { logcat { it.asLog() } }
        Pair(id, result.map { message })
      }
    }
  }

  fun decryptSym(
    passphrase: CharArray,
    encryptedMessage: ByteArrayInputStream,
    message: ByteArrayOutputStream,
  ) = run {
    val decryptionOptions = PGPDecryptOptions.Builder().build()
    pgpCryptoHandler.decrypt(null, passphrase, encryptedMessage, message, decryptionOptions).map {
      message
    }
  }

  fun encrypt(
    identities: List<PGPIdentifier>,
    message: ByteArrayInputStream,
    encryptedMessage: ByteArrayOutputStream,
  ) = run {
    // get primary key IDs in order to identify and avoid duplicate keys
    val primaryKeyIds =
      identities
        .mapNotNull { getLongKeyIdFromKeyId(it) }
        .distinct()
        .mapNotNull { PGPIdentifier.fromString(it) }
    val keys = primaryKeyIds.map { id -> pgpKeyManager.getKeyById(id) }.filterValues()
    val encryptionOptions =
      PGPEncryptOptions.Builder()
        .withAsciiArmor(settings.getBoolean(PreferenceKeys.ASCII_ARMOR, false))
        .build()
    val result = pgpCryptoHandler.encrypt(keys, null, message, encryptedMessage, encryptionOptions)
    result.getError()?.let { logcat { it.asLog() } }
    val succeededUserEmails =
      result.get()?.mapNotNull { key ->
        KeyUtils.tryGetUserId(key)?.toString()?.let { PGPIdentifier.splitUserId(it) }
      }
    Pair(succeededUserEmails, result.map { encryptedMessage })
  }

  fun encryptSym(
    passphrase: CharArray,
    message: ByteArrayInputStream,
    encryptedMessage: ByteArrayOutputStream,
    withArmor: Boolean = false,
  ) = run {
    val encryptionOptions = PGPEncryptOptions.Builder().withAsciiArmor(withArmor).build()
    pgpCryptoHandler
      .encrypt(listOf<PGPKey>(), passphrase, message, encryptedMessage, encryptionOptions)
      .map { encryptedMessage }
  }
}
