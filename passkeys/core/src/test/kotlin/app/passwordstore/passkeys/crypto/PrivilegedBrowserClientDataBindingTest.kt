/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class PrivilegedBrowserClientDataBindingTest {

  @Test
  fun `privileged browser binding returns Credential Manager client data placeholder`() {
    val frameworkHash = ByteArray(32) { it.toByte() }
    val reconstructedBrowserJson =
      """{"type":"webauthn.create","challenge":"fake","origin":"https://example.com"}"""
        .toByteArray()

    val binding =
      ClientDataBinding.FrameworkHash(
        hash = frameworkHash,
        responseClientDataJson = reconstructedBrowserJson,
      )

    assertContentEquals("{}".toByteArray(), binding.responseClientDataJson)
  }

  @Test
  fun `privileged browser binding identity depends only on framework hash`() {
    val frameworkHash = ByteArray(32) { (it + 1).toByte() }
    val first =
      ClientDataBinding.FrameworkHash(
        hash = frameworkHash,
        responseClientDataJson = "first local reconstruction".toByteArray(),
      )
    val second =
      ClientDataBinding.FrameworkHash(
        hash = frameworkHash.copyOf(),
        responseClientDataJson = "different local reconstruction".toByteArray(),
      )
    val differentHash =
      ClientDataBinding.FrameworkHash(
        hash = frameworkHash.copyOf().also { it[0] = 0x7F },
        responseClientDataJson = "first local reconstruction".toByteArray(),
      )

    assertEquals(first, second)
    assertEquals(first.hashCode(), second.hashCode())
    assertNotEquals(first, differentHash)
  }

  @Test
  fun `placeholder getter does not expose shared mutable state`() {
    val binding =
      ClientDataBinding.FrameworkHash(
        hash = ByteArray(32),
        responseClientDataJson = "ignored".toByteArray(),
      )

    val first = binding.responseClientDataJson
    first[0] = '!'.code.toByte()

    assertContentEquals("{}".toByteArray(), binding.responseClientDataJson)
  }
}
