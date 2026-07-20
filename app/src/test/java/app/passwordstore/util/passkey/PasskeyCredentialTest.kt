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
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.bouncycastle.jce.provider.BouncyCastleProvider

@OptIn(kotlin.ExperimentalUnsignedTypes::class)
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
  fun parsePasslessPasskeyFromCbor() {
    val cborIn =
      ("a9626964982013188118811865183018c2186718f00f18b718d818a81844" +
          "18b6185f1876185c18bb18c0185918d818d718c6189518a40b187a181d18" +
          "ea184818f11839627270a26269646b776562617574686e2e696f646e616d" +
          "65f66475736572a3626964931877186518621861187518741868186e1869" +
          "186f182d1870186118731873186c186518731873646e616d656870617373" +
          "6c6573736c646973706c61795f6e616d65f66a7369676e5f636f756e7400" +
          "63616c67276b707269766174655f6b65799820185e186718a01892186f18" +
          "451818184e1835183b183218f8187b18b71863181f184d18e318c018aa18" +
          "4618fb185a189b184b187a1850189f18d718c41849186467637265617465" +
          "641a69b6a1d06c646973636f76657261626c65f56a657874656e73696f6e" +
          "73a26c637265645f70726f74656374036b686d61635f736563726574f6")
        .hexToByteArray()

    val passlessKey = PasskeyCredential.fromCbor(cborIn).getOrThrow()

    val id = passlessKey.id
    assertEquals(32, id.size)
    assertEquals(0x13, id[0].toInt())
    assertEquals(0x81, id[1].toInt())

    val rp = passlessKey.rp
    assertEquals("webauthn.io", rp.id)
    assertNull(rp.name)

    assertEquals("passless", passlessKey.user.name)

    assertEquals(-8, passlessKey.alg)

    assertEquals(32, passlessKey.privateKey.size)

    assertNotNull(passlessKey.created)
    assertEquals("UTC", passlessKey.zone)
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
