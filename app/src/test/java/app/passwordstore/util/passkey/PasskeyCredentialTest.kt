/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("DEPRECATION")

package app.passwordstore.util.passkey

import app.passwordstore.util.passkey.PasskeyCredential.Algorithm
import app.passwordstore.util.passkey.PasskeyCredential.FidoUser
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getOrThrow
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
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
  private lateinit var keyPairRSA: KeyPair
  private lateinit var credentialId: ByteArray
  private lateinit var userId: ByteArray
  private lateinit var createdAt: Instant
  private lateinit var zoneId: ZoneId

  private lateinit var sigVerifierEC: Signature
  private lateinit var sigVerifierEdDSA: Signature
  private lateinit var sigVerifierRSA: Signature
  private lateinit var dataToSign: ByteArray

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

    keyPairGenerator =
      KeyPairGenerator.getInstance("RSA", BouncyCastleProvider()).also {
        it.initialize(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4), SecureRandom())
      }
    keyPairRSA = keyPairGenerator.generateKeyPair()

    credentialId = ByteArray(32)
    SecureRandom().nextBytes(credentialId)

    userId = ByteArray(32)
    SecureRandom().nextBytes(userId)
    createdAt = Instant.now()
    zoneId = ZoneId.systemDefault()

    dataToSign = "Thou shalt sign this challenge!".toByteArray()

    sigVerifierEC = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider())
    sigVerifierEC.initVerify(keyPairEC.public)
    sigVerifierEC.update(dataToSign)

    sigVerifierEdDSA = Signature.getInstance("Ed25519", BouncyCastleProvider())
    sigVerifierEdDSA.initVerify(keyPairEdDSA.public)
    sigVerifierEdDSA.update(dataToSign)

    sigVerifierRSA = Signature.getInstance("SHA256withRSA", BouncyCastleProvider())
    sigVerifierRSA.initVerify(keyPairRSA.public)
    sigVerifierRSA.update(dataToSign)
  }

  @Test
  fun createPasskeyCredential() {
    val passkeyCredential =
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
    assertNotNull(passkeyCredential)

    val passkeyCredentialSame =
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

    assertTrue(passkeyCredential == passkeyCredentialSame)
    assertTrue(passkeyCredential.hashCode() == passkeyCredentialSame.hashCode())

    val passkeyCredentialEC =
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

    assertFalse(passkeyCredential == passkeyCredentialEC)
    assertFalse(passkeyCredential.hashCode() == passkeyCredentialEC.hashCode())
  }

  @Test
  fun createStoredCredentialAndConvertToAndFromCbor() {
    val passkeyCredentialEC =
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

    val storedCredentialEC =
      StoredCredential.fromPasskeyCredential(passkeyCredentialEC).getOrThrow()
    assertTrue(storedCredentialEC.alg == Algorithm.ES256.id) // EC (-7)

    val storedCredentialECCbor = storedCredentialEC.toCborResult().getOrThrow()

    val storedCredentialECSame = StoredCredential.fromCbor(storedCredentialECCbor).getOrThrow()
    assertTrue(storedCredentialEC == storedCredentialECSame)
    assertTrue(storedCredentialEC.hashCode() == storedCredentialECSame.hashCode())

    assertNull(
      StoredCredential.fromCbor("lot of garbage garbage garbage".toByteArray()).get()
    ) // test on garbage bytes
    assertNull(StoredCredential.fromCbor(byteArrayOf()).get()) // test on empty ByteArray

    val passkeyCredentialEdDSA =
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
    val storedCredentialEdDSA =
      StoredCredential.fromPasskeyCredential(passkeyCredentialEdDSA).getOrThrow()
    assertTrue(storedCredentialEdDSA.alg == Algorithm.EDDSA.id) // EdDSA (-8)

    assertTrue(storedCredentialEC.user.revealName == false)
    storedCredentialEC.user.revealName = true
    val storedCredentialModifCbor = storedCredentialEC.toCbor()
    assertTrue(StoredCredential.fromCbor(storedCredentialModifCbor).get()?.user?.revealName == true)

    val passkeyCredentialRSA =
      PasskeyCredential(
        credentialId = credentialId,
        keyPair = keyPairRSA,
        algorithm = Algorithm.RS256,
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

    val storedCredentialRSA =
      StoredCredential.fromPasskeyCredential(passkeyCredentialRSA).getOrThrow()
    assertTrue(storedCredentialRSA.alg == Algorithm.RS256.id) // RSA (-257)

    val storedCredentialRSACbor = storedCredentialRSA.toCborResult().getOrThrow()

    val storedCredentialRSASame = StoredCredential.fromCbor(storedCredentialRSACbor).getOrThrow()
    assertTrue(storedCredentialRSA == storedCredentialRSASame)
    assertTrue(storedCredentialRSA.hashCode() == storedCredentialRSASame.hashCode())
  }

  @Test
  fun signDataAndVerifySignature() {
    val passkeyCredentialEC =
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

    val storedCredentialEC =
      StoredCredential.fromPasskeyCredential(passkeyCredentialEC).getOrThrow()
    val signatureBytesEC = storedCredentialEC.signData(dataToSign).getOrThrow()
    assertTrue(sigVerifierEC.verify(signatureBytesEC))

    val passkeyCredentialEdDSA =
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

    val storedCredentialEdDSA =
      StoredCredential.fromPasskeyCredential(passkeyCredentialEdDSA).getOrThrow()
    val signatureBytesEdDSA = storedCredentialEdDSA.signData(dataToSign).getOrThrow()
    assertTrue(sigVerifierEdDSA.verify(signatureBytesEdDSA))

    val passkeyCredentialRSA =
      PasskeyCredential(
        credentialId = credentialId,
        keyPair = keyPairRSA,
        algorithm = Algorithm.RS256,
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

    val storedCredentialRSA =
      StoredCredential.fromPasskeyCredential(passkeyCredentialRSA).getOrThrow()
    val signatureBytesRSA = storedCredentialRSA.signData(dataToSign).getOrThrow()
    assertTrue(sigVerifierRSA.verify(signatureBytesRSA))
  }
}
