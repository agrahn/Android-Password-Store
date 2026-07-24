/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Clock

class PasskeyCredentialTest {

  @Test
  fun `PasskeyCredential equals works correctly`() {
    val now = Clock.System.now()
    val credential1 =
      PasskeyCredential(
        credentialId = "cred123".toByteArray(),
        publicKey = "public".toByteArray(),
        rpId = "example.com",
        user = FidoUser("user123".toByteArray(), "testuser", "Test User"),
        signCount = 0u,
        createdAt = now,
      )

    val credential2 =
      PasskeyCredential(
        credentialId = "cred123".toByteArray(),
        publicKey = "public".toByteArray(),
        rpId = "example.com",
        user = FidoUser("user123".toByteArray(), "testuser", "Test User"),
        signCount = 0u,
        createdAt = now,
      )

    val credential3 =
      PasskeyCredential(
        credentialId = "cred456".toByteArray(),
        publicKey = "public".toByteArray(),
        rpId = "example.com",
        user = FidoUser("user123".toByteArray(), "testuser", "Test User"),
        signCount = 0u,
        createdAt = now,
      )

    assertEquals(credential1, credential2, "Credentials with same values should be equal")
    assertNotEquals(credential1, credential3, "Credentials with different IDs should not be equal")
  }

  @Test
  fun `incrementSignCount increases sign count by 1`() {
    val credential =
      PasskeyCredential(
        credentialId = "cred123".toByteArray(),
        publicKey = "public".toByteArray(),
        rpId = "example.com",
        user = FidoUser("user123".toByteArray(), "testuser", "Test User"),
        signCount = 5u,
        createdAt = Clock.System.now(),
      )

    val incremented = credential.incrementSignCount()

    assertEquals(6u, incremented.signCount, "Sign count should be incremented by 1")
    assertEquals(5u, credential.signCount, "Original credential should not be modified")
  }

  @Test
  fun `PasskeyCredential default values are correct`() {
    val credential =
      PasskeyCredential(
        credentialId = "cred123".toByteArray(),
        publicKey = "public".toByteArray(),
        rpId = "example.com",
        user = FidoUser("user123".toByteArray(), "testuser", "Test User"),
        createdAt = Clock.System.now(),
      )

    assertEquals(0u, credential.signCount, "Default sign count should be 0")
    assertEquals(listOf("internal"), credential.transports, "Default transports should be internal")
    assertTrue(credential.uvInitialized, "Default uvInitialized should be true")
  }
}
