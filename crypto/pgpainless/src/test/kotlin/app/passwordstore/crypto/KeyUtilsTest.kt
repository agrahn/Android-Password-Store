/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.KeyUtils.isKeyUsable
import app.passwordstore.crypto.KeyUtils.isSecretKey
import app.passwordstore.crypto.KeyUtils.parseAllCertificatesOrKeys
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
  fun parseAllCertificatesOrKeysReturnsEveryBlockInMultiKeyArmor() {
    val aliceBytes =
      this::class.java.classLoader.getResource("alice_owner@example_com")!!.readBytes()
    val bobbyBytes =
      this::class.java.classLoader.getResource("bobby_owner@example_com")!!.readBytes()
    val combined = aliceBytes + "\n".toByteArray() + bobbyBytes

    val parsed = parseAllCertificatesOrKeys(PGPKey(combined))
    assertEquals(2, parsed.size)
    val ids = parsed.map { tryGetKeyId(it).toString() }.toSet()
    assertEquals(2, ids.size, "expected two distinct key IDs but got $ids")
  }

  @Test
  fun parseAllCertificatesOrKeysReturnsEmptyOnGarbage() {
    val garbage = PGPKey("not a pgp key".toByteArray())
    assertEquals(emptyList(), parseAllCertificatesOrKeys(garbage))
  }

  @Test
  fun isKeyUsable() {
    val params = AllKeys.entries.map { it to true } // all test keys should be usable
    params.forEach { (allKeys, isUsable) ->
      val key = PGPKey(allKeys.keyMaterial)
      assertEquals(isUsable, isKeyUsable(key), "${allKeys.name} failed expectation:")
    }

    val expiredKey = PGPKey(getExpiredKey())
    assertTrue(isSecretKey(expiredKey))
    assertFalse(isKeyUsable(expiredKey))
  }
}
