/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.security

import org.junit.Assert.assertEquals
import org.junit.Test

class PasskeyInputLimitsTest {

  @Test
  fun `default limits have expected values`() {
    val limits = PasskeyInputLimits.DEFAULT
    assertEquals(256 * 1024L, limits.maxCiphertextBytes)
    assertEquals(64 * 1024L, limits.maxPlaintextBytes)
    assertEquals(256 * 1024L, limits.maxAssetLinksBytes)
    assertEquals(256, limits.maxAssetLinkStatements)
    assertEquals(16, limits.maxRelationsPerStatement)
    assertEquals(16, limits.maxFingerprintsPerStatement)
    assertEquals(32, limits.maxCborDepth)
    assertEquals(4096, limits.maxCborCollectionItems)
    assertEquals(16 * 1024, limits.maxTextFieldBytes)
    assertEquals(16 * 1024, limits.maxBinaryFieldBytes)
  }

  @Test(expected = IllegalArgumentException::class)
  fun `zero ciphertext limit rejected`() {
    PasskeyInputLimits(maxCiphertextBytes = 0)
  }

  @Test(expected = IllegalArgumentException::class)
  fun `negative plaintext limit rejected`() {
    PasskeyInputLimits(maxPlaintextBytes = -1)
  }

  @Test(expected = IllegalArgumentException::class)
  fun `zero cbor depth rejected`() {
    PasskeyInputLimits(maxCborDepth = 0)
  }

  @Test
  fun `custom limits are accepted`() {
    val custom =
      PasskeyInputLimits(
        maxCiphertextBytes = 1024,
        maxPlaintextBytes = 512,
        maxCborDepth = 10,
        maxCborCollectionItems = 100,
      )
    assertEquals(1024L, custom.maxCiphertextBytes)
    assertEquals(512L, custom.maxPlaintextBytes)
    assertEquals(10, custom.maxCborDepth)
    assertEquals(100, custom.maxCborCollectionItems)
  }

  @Test
  fun `data class equality works`() {
    val a = PasskeyInputLimits()
    val b = PasskeyInputLimits()
    assertEquals(a, b)
  }
}
