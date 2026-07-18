/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("DEPRECATION")

package app.passwordstore.util.passkey

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
  fun createPasskeyCredentialAndConvertToAndFromCborSignDataAndVerifySignature() {
    // testing passkey creation for supported algorithms
    val passkeyCredentialEC =
      PasskeyCredential.createNew(
        credentialId = credentialId,
        rpId = "example.org",
        userId = userId,
        userName = "j.roe@apsusers.org",
        userDisplayName = "Jane Roe",
        algorithm = Algorithm.ES256,
        keyPair = keyPairEC,
      )

    val passkeyCredentialECCbor = passkeyCredentialEC.toCborResult().getOrThrow()
    val passkeyCredentialECSame = PasskeyCredential.fromCbor(passkeyCredentialECCbor).getOrThrow()
    assertTrue(passkeyCredentialEC == passkeyCredentialECSame)
    assertTrue(passkeyCredentialEC.hashCode() == passkeyCredentialECSame.hashCode())

    assertTrue(passkeyCredentialEC.user.revealName == false)
    passkeyCredentialEC.user.revealName = true
    val passkeyCredentialModifCbor = passkeyCredentialEC.toCborResult().getOrThrow()
    assertTrue(
      PasskeyCredential.fromCbor(passkeyCredentialModifCbor).get()?.user?.revealName == true
    )

    val passkeyCredentialEdDSA =
      PasskeyCredential.createNew(
        credentialId = credentialId,
        rpId = "example.org",
        userId = userId,
        userName = "j.roe@apsusers.org",
        userDisplayName = "Jane Roe",
        algorithm = Algorithm.EDDSA,
        keyPair = keyPairEdDSA,
      )

    val passkeyCredentialRSA =
      PasskeyCredential.createNew(
        credentialId = credentialId,
        rpId = "example.org",
        userId = userId,
        userName = "j.roe@apsusers.org",
        userDisplayName = "Jane Roe",
        algorithm = Algorithm.RS256,
        keyPair = keyPairRSA,
      )

    // signing and verification
    val signatureBytesEC = passkeyCredentialEC.signData(dataToSign).getOrThrow()
    assertTrue(sigVerifierEC.verify(signatureBytesEC))

    val signatureBytesEdDSA = passkeyCredentialEdDSA.signData(dataToSign).getOrThrow()
    assertTrue(sigVerifierEdDSA.verify(signatureBytesEdDSA))

    val signatureBytesRSA = passkeyCredentialRSA.signData(dataToSign).getOrThrow()
    assertTrue(sigVerifierRSA.verify(signatureBytesRSA))

    // try restoring passkey from garbage bytes/empty data
    assertNull(PasskeyCredential.fromCbor("lot of garbage garbage garbage".toByteArray()).get())
    assertNull(PasskeyCredential.fromCbor(byteArrayOf()).get())
  }
}
