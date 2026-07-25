/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.passkeys.crypto.PgpUnlockContext

class KeystorePgpUnlockContext(private val passphraseCache: PasskeyPassphraseCache) :
  PgpUnlockContext {

  override suspend fun unlockKey(keyId: String): CharArray? {
    return passphraseCache.get(keyId)
  }
}
