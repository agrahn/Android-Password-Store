/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("DEPRECATION")

package app.passwordstore.util.passkey

import app.passwordstore.util.passkey.PasskeyCredential.Algorithm
import app.passwordstore.util.passkey.PasskeyCredential.FidoUser
import com.github.michaelbull.result.get
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.ZoneId
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.bouncycastle.jce.provider.BouncyCastleProvider

class PasskeyCredentialTest {

  private lateinit var keyPairEC: KeyPair
  private lateinit var keyPairEdDSA: KeyPair
  private lateinit var credentialId: ByteArray
  private lateinit var userId: ByteArray
  private lateinit var createdAt: Instant
  private lateinit var zoneId: ZoneId

  @BeforeTest
  fun setup() {
    var keyPairGenerator =
      KeyPairGenerator.getInstance("EC", BouncyCastleProvider()).also {
        it.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
      }
    keyPairEC = keyPairGenerator.generateKeyPair()

    keyPairGenerator =
      KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider()).also {
        it.initialize(ECGenParameterSpec("Ed25519"), SecureRandom())
      }
    keyPairEdDSA = keyPairGenerator.generateKeyPair()

    credentialId = ByteArray(32)
    SecureRandom().nextBytes(credentialId)

    userId = ByteArray(32)
    SecureRandom().nextBytes(userId)
    createdAt = Instant.now()
    zoneId = ZoneId.systemDefault()
  }

  @Test
  fun createPasskeyCredential() {
    val passkeyCredential =
      PasskeyCredential(
        credentialId = credentialId,
        keyPair = keyPairEC,
        algorithm = Algorithm.ES256,
        rpId = "example.org",
        user =
          FidoUser(
            id = userId,
            name = "j.roe@apsusers.org",
            displayName = "Jane Roe",
          ),
        createdAt = createdAt,
        zoneId = zoneId,
      )

    val passkeyCredentialSame =
      PasskeyCredential(
        credentialId = credentialId,
        keyPair = keyPairEC,
        algorithm = Algorithm.ES256,
        rpId = "example.org",
        user =
          FidoUser(
            id = userId,
            name = "j.roe@apsusers.org",
            displayName = "Jane Roe",
          ),
        createdAt = createdAt,
        zoneId = zoneId,
      )

    assertTrue(passkeyCredential == passkeyCredentialSame)
    assertTrue(passkeyCredential.hashCode() == passkeyCredentialSame.hashCode())

    val passkeyCredentialOther =
      PasskeyCredential(
        credentialId = credentialId,
        keyPair = keyPairEdDSA,
        algorithm = Algorithm.EDDSA,
        rpId = "example.org",
        user =
          FidoUser(
            id = userId,
            name = "j.roe@apsusers.org",
            displayName = "Jane Roe",
          ),
        createdAt = createdAt,
        zoneId = zoneId,
      )

    assertFalse(passkeyCredential == passkeyCredentialOther)
    assertFalse(passkeyCredential.hashCode() == passkeyCredentialOther.hashCode())
  }

  @Test
  fun createStoredCredentialAndConvertToAndFromCbor() {
    val passkeyCredential =
      PasskeyCredential(
        credentialId = credentialId,
        keyPair = keyPairEC,
        algorithm = Algorithm.ES256,
        rpId = "example.org",
        user =
          FidoUser(
            id = userId,
            name = "j.roe@apsusers.org",
            displayName = "Jane Roe",
          ),
        createdAt = createdAt,
        zoneId = zoneId,
      )

    val storedCredential = StoredCredential.fromPasskeyCredential(passkeyCredential).get()
    assertNotNull(storedCredential)
    assertTrue(storedCredential.alg == Algorithm.ES256.id) // EC (-7)

    val storedCredentialCbor = storedCredential.toCborResult().get()
    assertNotNull(storedCredentialCbor)

    val storedCredentialSame = StoredCredential.fromCbor(storedCredentialCbor).get()
    assertNotNull(storedCredentialSame)
    assertTrue(storedCredential == storedCredentialSame)
    assertTrue(storedCredential.hashCode() == storedCredentialSame.hashCode())

    assertNull(
      StoredCredential.fromCbor("lot of garbage garbage garbage".toByteArray()).get()
    ) // test on garbage bytes
    assertNull(StoredCredential.fromCbor(byteArrayOf()).get()) // test on empty ByteArray

    val passkeyCredentialOther =
      PasskeyCredential(
        credentialId = credentialId,
        keyPair = keyPairEdDSA,
        algorithm = Algorithm.EDDSA,
        rpId = "example.org",
        user =
          FidoUser(
            id = userId,
            name = "j.roe@apsusers.org",
            displayName = "Jane Roe",
          ),
        createdAt = createdAt,
        zoneId = zoneId,
      )
    val storedCredentialOther = StoredCredential.fromPasskeyCredential(passkeyCredentialOther).get()
    assertNotNull(storedCredentialOther)
    assertTrue(storedCredentialOther.alg == Algorithm.EDDSA.id) // EdDSA (-8)

    assertTrue(storedCredential.user.revealName == false)
    storedCredential.user.revealName = true
    val storedCredentialModifCbor = storedCredential.toCbor()
    assertTrue(StoredCredential.fromCbor(storedCredentialModifCbor).get()?.user?.revealName == true)
  }
}
