/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.RelyingParty
import app.passwordstore.passkeys.model.StoredCredential
import app.passwordstore.passkeys.model.User
import com.github.michaelbull.result.fold
import kotlin.test.Test
import kotlin.test.assertTrue

class PayloadBindingValidatorTest {

  private val validPrivateKey = ByteArray(32) { (it + 1).toByte() }
  private val validPublicKey = StoredCredential.deriveP256PublicKey(validPrivateKey)
  private val validCredentialId = byteArrayOf(0xaa.toByte(), 0xbb.toByte(), 0xcc.toByte())

  private fun makeStoredCredential(
    rpId: String = "example.com",
    credentialId: ByteArray = validCredentialId,
    privateKey: ByteArray = validPrivateKey,
    publicKey: ByteArray? = validPublicKey,
    alg: Int = StoredCredential.ALG_ES256,
  ): StoredCredential {
    return StoredCredential(
      id = credentialId,
      rp = RelyingParty(id = rpId),
      user = User(id = "user-id".toByteArray(), name = "test", displayName = "Test"),
      signCount = 0u,
      alg = alg,
      privateKey = privateKey,
      publicKey = publicKey,
      created = 1000L,
    )
  }

  private fun makeRef(
    rpId: String = "example.com",
    credentialId: ByteArray = validCredentialId,
  ): PasskeyFileRef {
    return PasskeyFileRef(
      canonicalRpId = rpId,
      credentialId = credentialId,
      relativePath = "$rpId/${credentialId.joinToString("") { "%02x".format(it) }}.gpg",
    )
  }

  @Test
  fun `valid credential passes all binding checks`() {
    val ref = makeRef()
    val stored = makeStoredCredential()

    val result =
      PayloadBindingValidator.validate(
        requestRpId = "example.com",
        requestCredentialId = validCredentialId,
        fileRef = ref,
        stored = stored,
      )

    result.fold(
      success = { /* expected */ },
      failure = { throw AssertionError("Valid credential should pass: ${it.message}") },
    )
  }

  @Test
  fun `request RP ID differs from metadata RP ID is rejected`() {
    val ref = makeRef(rpId = "example.com")
    val stored = makeStoredCredential(rpId = "example.com")

    val result =
      PayloadBindingValidator.validate(
        requestRpId = "evil.com",
        requestCredentialId = validCredentialId,
        fileRef = ref,
        stored = stored,
      )

    result.fold(
      success = { throw AssertionError("Mismatched RP ID should be rejected") },
      failure = {
        assertTrue(it is FileStoreError.PayloadBindingMismatch)
      },
    )
  }

  @Test
  fun `directory RP differs from decrypted CBOR RP is rejected`() {
    val ref = makeRef(rpId = "evil.com")
    val stored = makeStoredCredential(rpId = "example.com")

    val result =
      PayloadBindingValidator.validate(
        requestRpId = "evil.com",
        requestCredentialId = validCredentialId,
        fileRef = ref,
        stored = stored,
      )

    result.fold(
      success = { throw AssertionError("Directory/decrypted RP mismatch should be rejected") },
      failure = {
        assertTrue(it is FileStoreError.PayloadBindingMismatch)
      },
    )
  }

  @Test
  fun `filename ID differs from decrypted CBOR ID is rejected`() {
    val ref =
      PasskeyFileRef(
        canonicalRpId = "example.com",
        credentialId = byteArrayOf(0x11, 0x22),
        relativePath = "example.com/1122.gpg",
      )
    val stored = makeStoredCredential(credentialId = byteArrayOf(0x33, 0x44))

    val result =
      PayloadBindingValidator.validate(
        requestRpId = "example.com",
        requestCredentialId = byteArrayOf(0x11, 0x22),
        fileRef = ref,
        stored = stored,
      )

    result.fold(
      success = { throw AssertionError("Filename/decrypted ID mismatch should be rejected") },
      failure = {
        assertTrue(it is FileStoreError.PayloadBindingMismatch)
      },
    )
  }

  @Test
  fun `unsupported algorithm is rejected`() {
    val ref = makeRef()
    val stored = makeStoredCredential(alg = -257)

    val result =
      PayloadBindingValidator.validate(
        requestRpId = "example.com",
        requestCredentialId = validCredentialId,
        fileRef = ref,
        stored = stored,
      )

    result.fold(
      success = { throw AssertionError("Unsupported algorithm should be rejected") },
      failure = {
        assertTrue(it is FileStoreError.PayloadBindingMismatch)
        assertTrue(it.message.contains("algorithm"))
      },
    )
  }

  @Test
  fun `invalid private scalar size is rejected`() {
    val ref = makeRef()
    val stored = makeStoredCredential(privateKey = ByteArray(16) { it.toByte() })

    val result =
      PayloadBindingValidator.validate(
        requestRpId = "example.com",
        requestCredentialId = validCredentialId,
        fileRef = ref,
        stored = stored,
      )

    result.fold(
      success = { throw AssertionError("Invalid scalar size should be rejected") },
      failure = {
        assertTrue(it is FileStoreError.PayloadBindingMismatch)
        assertTrue(it.message.contains("scalar"))
      },
    )
  }

  @Test
  fun `public key not matching private scalar is rejected`() {
    val ref = makeRef()
    val wrongPublicKey = ByteArray(65) { 0x04 }
    val stored = makeStoredCredential(publicKey = wrongPublicKey)

    val result =
      PayloadBindingValidator.validate(
        requestRpId = "example.com",
        requestCredentialId = validCredentialId,
        fileRef = ref,
        stored = stored,
      )

    result.fold(
      success = { throw AssertionError("Mismatched public key should be rejected") },
      failure = {
        assertTrue(it is FileStoreError.PayloadBindingMismatch)
        assertTrue(it.message.contains("public key"))
      },
    )
  }

  @Test
  fun `private scalar out of P-256 range is rejected`() {
    val ref = makeRef()
    val zeroScalar = ByteArray(32)
    val stored = makeStoredCredential(privateKey = zeroScalar)

    val result =
      PayloadBindingValidator.validate(
        requestRpId = "example.com",
        requestCredentialId = validCredentialId,
        fileRef = ref,
        stored = stored,
      )

    result.fold(
      success = { throw AssertionError("Zero scalar should be rejected") },
      failure = {
        assertTrue(it is FileStoreError.PayloadBindingMismatch)
        assertTrue(it.message.contains("range"))
      },
    )
  }

  @Test
  fun `empty credential ID in stored credential is rejected`() {
    val ref = makeRef(credentialId = byteArrayOf(0x01))
    val stored =
      StoredCredential(
        id = ByteArray(0),
        rp = RelyingParty(id = "example.com"),
        user = User(id = "uid".toByteArray()),
        signCount = 0u,
        alg = StoredCredential.ALG_ES256,
        privateKey = validPrivateKey,
        publicKey = validPublicKey,
        created = 1000L,
      )

    val result =
      PayloadBindingValidator.validate(
        requestRpId = "example.com",
        requestCredentialId = byteArrayOf(0x01),
        fileRef = ref,
        stored = stored,
      )

    result.fold(
      success = {
        throw AssertionError("Empty credential ID in stored credential should be rejected")
      },
      failure = {
        assertTrue(it is FileStoreError.PayloadBindingMismatch)
      },
    )
  }
}
