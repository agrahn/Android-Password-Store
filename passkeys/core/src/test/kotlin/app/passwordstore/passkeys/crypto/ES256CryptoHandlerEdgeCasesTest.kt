/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.crypto

import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import com.github.michaelbull.result.getOrElse
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ES256CryptoHandlerEdgeCasesTest {

  private val cryptoHandler = ES256CryptoHandler()

  @Test
  fun `sign rejects empty inputs`() {
    val (privateKey, _) = cryptoHandler.generateKeyPair()

    val emptyKeyResult =
      cryptoHandler.sign(
        privateKey = ByteArray(0),
        authenticatorData = ByteArray(37) { it.toByte() },
        clientDataHash = ByteArray(32) { it.toByte() },
      )
    assertTrue(emptyKeyResult.isErr, "Should reject empty private key")

    val emptyAuthDataResult =
      cryptoHandler.sign(
        privateKey = privateKey,
        authenticatorData = ByteArray(0),
        clientDataHash = ByteArray(32) { it.toByte() },
      )
    assertTrue(emptyAuthDataResult.isErr, "Should reject empty authenticator data")

    val emptyHashResult =
      cryptoHandler.sign(
        privateKey = privateKey,
        authenticatorData = ByteArray(37) { it.toByte() },
        clientDataHash = ByteArray(0),
      )
    assertTrue(emptyHashResult.isErr, "Should reject empty client data hash")
  }

  @Test
  fun `verify rejects empty signature`() {
    val (_, publicKey) = cryptoHandler.generateKeyPair()
    val authData = ByteArray(37) { it.toByte() }
    val clientDataHash = ByteArray(32) { it.toByte() }

    val emptySig = ByteArray(0)
    val result = cryptoHandler.verify(publicKey, emptySig, authData, clientDataHash)

    assertTrue(result.isErr, "Should reject empty signature")
  }

  @Test
  fun `verify rejects empty inputs`() {
    val (_, publicKey) = cryptoHandler.generateKeyPair()
    val signature = ByteArray(70) { it.toByte() }

    val emptyKeyResult =
      cryptoHandler.verify(
        publicKey = ByteArray(0),
        signature = signature,
        authenticatorData = ByteArray(37) { it.toByte() },
        clientDataHash = ByteArray(32) { it.toByte() },
      )
    assertTrue(emptyKeyResult.isErr, "Should reject empty public key")

    val emptyAuthDataResult =
      cryptoHandler.verify(
        publicKey = publicKey,
        signature = signature,
        authenticatorData = ByteArray(0),
        clientDataHash = ByteArray(32) { it.toByte() },
      )
    assertTrue(emptyAuthDataResult.isErr, "Should reject empty authenticator data")

    val emptyHashResult =
      cryptoHandler.verify(
        publicKey = publicKey,
        signature = signature,
        authenticatorData = ByteArray(37) { it.toByte() },
        clientDataHash = ByteArray(0),
      )
    assertTrue(emptyHashResult.isErr, "Should reject empty client data hash")
  }

  @Test
  fun `createCredential rejects blank rpId`() {
    val result =
      cryptoHandler.createCredential(
        rpId = "",
        userId = "user".toByteArray(),
        userName = "test",
        userDisplayName = "Test",
        challenge = ByteArray(32) { it.toByte() },
      )
    assertTrue(result.isErr, "Should reject blank RP ID")

    val whitespaceResult =
      cryptoHandler.createCredential(
        rpId = "   ",
        userId = "user".toByteArray(),
        userName = "test",
        userDisplayName = "Test",
        challenge = ByteArray(32) { it.toByte() },
      )
    assertTrue(whitespaceResult.isErr, "Should reject whitespace RP ID")
  }

  @Test
  fun `createCredential rejects empty userId`() {
    val result =
      cryptoHandler.createCredential(
        rpId = "example.com",
        userId = ByteArray(0),
        userName = "test",
        userDisplayName = "Test",
        challenge = ByteArray(32) { it.toByte() },
      )
    assertTrue(result.isErr, "Should reject empty user ID")
  }

  @Test
  fun `getAssertion rejects blank rpId`() {
    val (credential, privateKey) = createValidCredential()

    val result =
      cryptoHandler.getAssertion(
        credential = credential,
        privateKey = privateKey,
        rpId = "",
        challenge = ByteArray(32) { it.toByte() },
        origin = "https://example.com",
      )
    assertTrue(result.isErr, "Should reject blank RP ID")
  }

  @Test
  fun `getAssertion rejects empty challenge`() {
    val (credential, privateKey) = createValidCredential()

    val result =
      cryptoHandler.getAssertion(
        credential = credential,
        privateKey = privateKey,
        rpId = credential.rpId,
        challenge = ByteArray(0),
        origin = "https://example.com",
      )
    assertTrue(result.isErr, "Should reject empty challenge")
  }

  @Test
  fun `getAssertion rejects blank origin`() {
    val (credential, privateKey) = createValidCredential()

    val result =
      cryptoHandler.getAssertion(
        credential = credential,
        privateKey = privateKey,
        rpId = credential.rpId,
        challenge = ByteArray(32) { it.toByte() },
        origin = "",
      )
    assertTrue(result.isErr, "Should reject blank origin")
  }

  @Test
  fun `signature verification fails with different data`() {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    val authData = ByteArray(37) { it.toByte() }
    val clientDataHash = ByteArray(32) { it.toByte() }

    val signature =
      cryptoHandler.sign(privateKey, authData, clientDataHash).getOrElse {
        throw AssertionError("Sign failed")
      }

    val differentAuthData = ByteArray(37) { (it + 1).toByte() }
    val result = cryptoHandler.verify(publicKey, signature, differentAuthData, clientDataHash)

    assertTrue(result.isOk, "Verify should complete")
    assertFalse(result.getOrElse { true }, "Signature should not verify with different data")
  }

  @Test
  fun `signature verification fails with different key`() {
    val (privateKey1, _) = cryptoHandler.generateKeyPair()
    val (_, publicKey2) = cryptoHandler.generateKeyPair()
    val authData = ByteArray(37) { it.toByte() }
    val clientDataHash = ByteArray(32) { it.toByte() }

    val signature =
      cryptoHandler.sign(privateKey1, authData, clientDataHash).getOrElse {
        throw AssertionError("Sign failed")
      }

    val result = cryptoHandler.verify(publicKey2, signature, authData, clientDataHash)

    assertTrue(result.isOk, "Verify should complete")
    assertFalse(result.getOrElse { true }, "Signature should not verify with different key")
  }

  @Test
  fun `handles maximum sign count value`() {
    val (baseCredential, privateKey) = createValidCredential()
    val credential = baseCredential.copy(signCount = ULong.MAX_VALUE - 1u)

    val result =
      cryptoHandler.getAssertion(
        credential = credential,
        privateKey = privateKey,
        rpId = credential.rpId,
        challenge = ByteArray(32) { it.toByte() },
        origin = "https://example.com",
      )

    assertTrue(result.isOk, "Should handle large sign count")
  }

  @Test
  fun `handles large challenge`() {
    val (credential, privateKey) = createValidCredential()

    val result =
      cryptoHandler.getAssertion(
        credential = credential,
        privateKey = privateKey,
        rpId = credential.rpId,
        challenge = ByteArray(1000) { it.toByte() },
        origin = "https://example.com",
      )

    assertTrue(result.isOk, "Should handle large challenge")
  }

  @Test
  fun `handles unicode in user names`() {
    val result =
      cryptoHandler.createCredential(
        rpId = "example.com",
        userId = "user".toByteArray(),
        userName = "用户名",
        userDisplayName = "显示名称 🎉",
        challenge = ByteArray(32) { it.toByte() },
      )

    assertTrue(result.isOk, "Should handle unicode in names")
    val created = result.getOrElse { throw AssertionError("Failed") }
    assertTrue(created.credential.user.name.contains("用户名"))
    assertTrue(created.credential.user.displayName.contains("🎉"))
  }

  @Test
  fun `handles long rpId`() {
    val longRpId = "a".repeat(253) + ".com"

    val result =
      cryptoHandler.createCredential(
        rpId = longRpId,
        userId = "user".toByteArray(),
        userName = "test",
        userDisplayName = "Test",
        challenge = ByteArray(32) { it.toByte() },
      )

    assertTrue(result.isOk, "Should handle long RP ID")
  }

  private fun createValidCredential(): Pair<PasskeyCredential, ByteArray> {
    val (privateKey, publicKey) = cryptoHandler.generateKeyPair()
    val credential =
      PasskeyCredential(
        credentialId = ByteArray(32) { it.toByte() },
        publicKey = publicKey,
        rpId = "example.com",
        user =
          FidoUser(
            id = "user-id".toByteArray(),
            name = "testuser",
            displayName = "Test User",
          ),
        signCount = 0u,
        createdAt = kotlin.time.Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
      )
    return Pair(credential, privateKey)
  }
}
