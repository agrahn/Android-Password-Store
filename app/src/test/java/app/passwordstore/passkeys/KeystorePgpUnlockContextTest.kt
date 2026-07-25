/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkeys

import kotlin.test.Test
import kotlin.test.assertNull
import kotlinx.coroutines.runBlocking

class KeystorePgpUnlockContextTest {

  @Test
  fun `unlockKey returns null when cache is empty`() = runBlocking {
    val cache = TestPassphraseCache()
    val context = KeystorePgpUnlockContext(cache)
    assertNull(context.unlockKey("some-key-id"))
  }

  @Test
  fun `unlockKey returns null for unknown key`() = runBlocking {
    val cache = TestPassphraseCache()
    cache.putDirect("known-key", "passphrase".toCharArray())
    val context = KeystorePgpUnlockContext(cache)
    assertNull(context.unlockKey("unknown-key"))
  }

  private class TestPassphraseCache : PasskeyPassphraseCache() {
    private val store = mutableMapOf<String, CharArray>()

    fun putDirect(keyId: String, passphrase: CharArray) {
      store[keyId] = passphrase
    }

    override fun get(keyId: String): CharArray? = store[keyId]?.copyOf()

    override fun contains(keyId: String): Boolean = store.containsKey(keyId)
  }
}
