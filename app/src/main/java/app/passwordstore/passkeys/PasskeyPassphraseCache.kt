/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
open class PasskeyPassphraseCache @Inject constructor() {

  private val cache = ConcurrentHashMap<String, CharArray>()

  open fun put(keyId: String, passphrase: CharArray) {
    val encrypted = AESEncryption.encrypt(passphrase, KeyType.TEMPORARY) ?: return
    passphrase.fill('\u0000')
    cache[keyId] = encrypted
  }

  open fun get(keyId: String): CharArray? {
    val encrypted = cache[keyId] ?: return null
    return AESEncryption.decrypt(encrypted, KeyType.TEMPORARY)
  }

  open fun contains(keyId: String): Boolean = cache.containsKey(keyId)

  open fun clear() {
    cache.values.forEach { it.fill('\u0000') }
    cache.clear()
  }
}
