/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.passkeys.provider

import app.passwordstore.passkeys.crypto.CallerType
import app.passwordstore.passkeys.crypto.ClientDataBinding
import app.passwordstore.passkeys.crypto.ES256CryptoHandler
import app.passwordstore.passkeys.crypto.VerifiedWebAuthnContext
import app.passwordstore.passkeys.model.FidoUser
import app.passwordstore.passkeys.model.PasskeyCredential
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Clock

class PrivilegedBrowserResponseTest {

  @Test
  fun `privileged browser registration returns Credential Manager client data placeholder`() {
    val crypto = ES256CryptoHandler()
    val (_, publicKey) = crypto.generateKeyPair()
    val credential =
      PasskeyCredential(
        credentialId = ByteArray(32) { it.toByte() },
        publicKey = publicKey,
        rpId = "example.com",
        user = FidoUser(id = "user-id".toByteArray(), name = "test", displayName = "Test User"),
        signCount = 0u,
        createdAt = Clock.System.now(),
        transports = listOf("internal"),
        uvInitialized = true,
      )
    val context =
      VerifiedWebAuthnContext(
        callingPackage = "com.android.chrome",
        origin = "https://example.com",
        callerType = CallerType.PRIVILEGED_BROWSER,
        signingCertificateDigests = setOf("chrome"),
        clientDataBinding =
          ClientDataBinding.FrameworkHash(
            hash = ByteArray(32) { (it + 1).toByte() },
            responseClientDataJson =
              """{"type":"webauthn.create","challenge":"locally-rebuilt","origin":"https://example.com"}"""
                .toByteArray(),
          ),
      )
    val requestJson =
      """
      {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": "dXNlci1pZA", "name": "test", "displayName": "Test User"},
        "challenge": "Y2hhbGxlbmdl",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
      }
      """
        .trimIndent()

    val responseJson =
      PasskeyProviderUtils.buildAttestationResponse(credential, requestJson, context)
    val response =
      PasskeyProviderUtils.json.decodeFromString(AttestationResponseJson.serializer(), responseJson)

    assertEquals(
      "{}",
      PasskeyProviderUtils.decodeBase64Url(response.response.clientDataJSON).decodeToString(),
    )
  }
}
