/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.KeyUtils.hasSecretKey
import app.passwordstore.crypto.KeyUtils.isKeyUsable
import app.passwordstore.crypto.KeyUtils.tryGetKeyId
import app.passwordstore.crypto.KeyUtils.tryParseCertificateOrKey
import app.passwordstore.crypto.TestUtils.AllKeys
import app.passwordstore.crypto.TestUtils.getArmoredSecretKeyWithMultipleIdentities
import app.passwordstore.crypto.TestUtils.getExpiredKey
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.bouncycastle.openpgp.api.OpenPGPKey

class KeyUtilsTest {
  @Test
  fun parseKeyWithMultipleIdentities() {
    val key = PGPKey(getArmoredSecretKeyWithMultipleIdentities())
    val openPgpKey = tryParseCertificateOrKey(key)
    assertNotNull(openPgpKey)
    assertIs<OpenPGPKey>(openPgpKey)
    assertTrue(openPgpKey.isSecretKey())
    val keyId = tryGetKeyId(key)
    assertNotNull(keyId)
    assertIs<PGPIdentifier.KeyId>(keyId)
    assertEquals("b950ae2813841585", keyId.toString())
  }

  @Test
  fun isKeyUsable() {
    val params = AllKeys.entries.map { it to true } // all test keys should be usable
    params.forEach { (allKeys, isUsable) ->
      val key = PGPKey(allKeys.keyMaterial)
      assertEquals(isUsable, isKeyUsable(key), "${allKeys.name} failed expectation:")
    }

    val expiredKey = PGPKey(getExpiredKey())
    assertTrue(hasSecretKey(expiredKey))
    assertFalse(isKeyUsable(expiredKey))
  }
}
