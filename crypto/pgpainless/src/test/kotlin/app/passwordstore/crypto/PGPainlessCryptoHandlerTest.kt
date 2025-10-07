/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("JUnitMalformedDeclaration") // The test runner takes care of it

package app.passwordstore.crypto

import app.passwordstore.crypto.CryptoConstants.AEAD_ENCRYPTED_TEXT
import app.passwordstore.crypto.CryptoConstants.AEAD_KEY_PASSPHRASE
import app.passwordstore.crypto.CryptoConstants.HELLO_CLEAR_TEXT
import app.passwordstore.crypto.CryptoConstants.HELLO_ENCRYPTED_TEXT
import app.passwordstore.crypto.CryptoConstants.HELLO_SESSIONKEY_DATA
import app.passwordstore.crypto.CryptoConstants.KEY_PASSPHRASE
import app.passwordstore.crypto.CryptoConstants.KEY_PASSPHRASE_ALICE
import app.passwordstore.crypto.CryptoConstants.KEY_PASSPHRASE_BOBBY
import app.passwordstore.crypto.CryptoConstants.PLAIN_TEXT
import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import com.github.michaelbull.result.getError
import com.google.testing.junit.testparameterinjector.TestParameter
import com.google.testing.junit.testparameterinjector.TestParameterInjector
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.runner.RunWith
import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.MessageInspector

@Suppress("Unused") // Test runner handles it internally
enum class EncryptionKey(val keySet: List<PGPKey>) {
  PUBLIC(listOf(PGPKey(TestUtils.getArmoredPublicKey()))),
  SECRET(listOf(PGPKey(TestUtils.getArmoredSecretKey()))),
  ALL(listOf(PGPKey(TestUtils.getArmoredPublicKey()), PGPKey(TestUtils.getArmoredSecretKey()))),
}

@RunWith(TestParameterInjector::class)
class PGPainlessCryptoHandlerTest {

  private val cryptoHandler = PGPainlessCryptoHandler()
  private val secretKey = PGPKey(TestUtils.getArmoredSecretKey())

  @Test
  fun encryptAndDecrypt(@TestParameter encryptionKey: EncryptionKey) {
    val ciphertextStream = ByteArrayOutputStream()
    val encryptRes =
      cryptoHandler.encrypt(
        encryptionKey.keySet,
        null,
        PLAIN_TEXT.byteInputStream(Charsets.UTF_8),
        ciphertextStream,
        PGPEncryptOptions.Builder().build(),
      )
    assertTrue(encryptRes.isOk)
    val plaintextStream = ByteArrayOutputStream()
    val decryptRes =
      cryptoHandler.decrypt(
        secretKey,
        KEY_PASSPHRASE.toCharArray(),
        ciphertextStream.toByteArray().inputStream(),
        plaintextStream,
        PGPDecryptOptions.Builder().build(),
      )
    assertTrue(decryptRes.isOk)
    assertEquals(PLAIN_TEXT, plaintextStream.toString(Charsets.UTF_8))
  }

  @Test
  fun encryptAndDecryptSymmetrically() {
    val ciphertextStream = ByteArrayOutputStream()
    val encryptRes =
      cryptoHandler.encrypt(
        listOf<PGPKey>(),
        KEY_PASSPHRASE.toCharArray(),
        PLAIN_TEXT.byteInputStream(Charsets.UTF_8),
        ciphertextStream,
        PGPEncryptOptions.Builder().build(),
      )
    assertTrue(encryptRes.isOk)
    val plaintextStream = ByteArrayOutputStream()
    val decryptRes =
      cryptoHandler.decrypt(
        null,
        KEY_PASSPHRASE.toCharArray(),
        ciphertextStream.toByteArray().inputStream(),
        plaintextStream,
        PGPDecryptOptions.Builder().build(),
      )
    assertTrue(decryptRes.isOk)
    assertEquals(PLAIN_TEXT, plaintextStream.toString(Charsets.UTF_8))
  }

  @Test
  fun decryptSymmtericallyWithWrongPassphrase() {
    val ciphertextStream = ByteArrayOutputStream()
    val encryptRes =
      cryptoHandler.encrypt(
        listOf<PGPKey>(),
        KEY_PASSPHRASE.toCharArray(),
        PLAIN_TEXT.byteInputStream(Charsets.UTF_8),
        ciphertextStream,
        PGPEncryptOptions.Builder().build(),
      )
    assertTrue(encryptRes.isOk)
    val plaintextStream = ByteArrayOutputStream()
    val decryptRes =
      cryptoHandler.decrypt(
        null,
        "wrong passphrase".toCharArray(),
        ciphertextStream.toByteArray().inputStream(),
        plaintextStream,
        PGPDecryptOptions.Builder().build(),
      )
    assertTrue(decryptRes.isErr)
    assertIs<IncorrectPassphraseException>(decryptRes.getError())
  }

  @Test
  fun decryptWithWrongPassphrase(@TestParameter encryptionKey: EncryptionKey) {
    val ciphertextStream = ByteArrayOutputStream()
    val encryptRes =
      cryptoHandler.encrypt(
        encryptionKey.keySet,
        null,
        PLAIN_TEXT.byteInputStream(Charsets.UTF_8),
        ciphertextStream,
        PGPEncryptOptions.Builder().build(),
      )
    assertTrue(encryptRes.isOk)
    val plaintextStream = ByteArrayOutputStream()
    val result =
      cryptoHandler.decrypt(
        secretKey,
        "very incorrect passphrase".toCharArray(),
        ciphertextStream.toByteArray().inputStream(),
        plaintextStream,
        PGPDecryptOptions.Builder().build(),
      )
    assertTrue(result.isErr)
    assertIs<IncorrectPassphraseException>(result.getError())
  }

  @Test
  fun decryptWithSessionKey() {
    val plaintextStream = ByteArrayOutputStream()
    val result =
      cryptoHandler.decrypt(
        PGPKey(HELLO_SESSIONKEY_DATA.hexToByteArray()),
        null,
        HELLO_ENCRYPTED_TEXT.byteInputStream(Charsets.UTF_8),
        plaintextStream,
        PGPDecryptOptions.Builder().withSessionKey(true).build(),
      )
    val plaintext = plaintextStream.toString(Charsets.UTF_8)
    assertTrue(result.isOk)
    assertEquals(plaintext, HELLO_CLEAR_TEXT)
  }

  @Test
  fun encryptAsciiArmored(@TestParameter encryptionKey: EncryptionKey) {
    val ciphertextStream = ByteArrayOutputStream()
    val encryptRes =
      cryptoHandler.encrypt(
        encryptionKey.keySet,
        null,
        PLAIN_TEXT.byteInputStream(Charsets.UTF_8),
        ciphertextStream,
        PGPEncryptOptions.Builder().withAsciiArmor(true).build(),
      )
    assertTrue(encryptRes.isOk)
    val ciphertext = ciphertextStream.toString(Charsets.UTF_8)
    assertContains(ciphertext, "Version: PGPainless")
    assertContains(ciphertext, "-----BEGIN PGP MESSAGE-----")
    assertContains(ciphertext, "-----END PGP MESSAGE-----")
  }

  @Test
  fun encryptMultiple() {
    val alice =
      PGPainless.getInstance()
        .generateKey()
        .modernKeyRing("Alice <owner@example.com>", KEY_PASSPHRASE_ALICE)
    val bob =
      PGPainless.getInstance()
        .generateKey()
        .modernKeyRing("Bob <owner@example.com>", KEY_PASSPHRASE_BOBBY)
    val aliceKey = PGPKey(PGPainless.getInstance().toAsciiArmor(alice).encodeToByteArray())
    val bobKey = PGPKey(PGPainless.getInstance().toAsciiArmor(bob).encodeToByteArray())
    val ciphertextStream = ByteArrayOutputStream()
    val encryptRes =
      cryptoHandler.encrypt(
        listOf(aliceKey, bobKey),
        null,
        PLAIN_TEXT.byteInputStream(Charsets.UTF_8),
        ciphertextStream,
        PGPEncryptOptions.Builder().withAsciiArmor(true).build(),
      )
    assertTrue(encryptRes.isOk)
    val message = ciphertextStream.toByteArray().decodeToString()
    val info = MessageInspector().determineEncryptionInfoForMessage(message)
    assertTrue(info.isEncrypted)
    assertEquals(2, info.keyIds.size)
    assertFalse(info.isSignedOnly)

    mapOf(aliceKey to KEY_PASSPHRASE_ALICE, bobKey to KEY_PASSPHRASE_BOBBY).forEach { (k, p) ->
      val plaintextStream = ByteArrayOutputStream()
      val res =
        cryptoHandler.decrypt(
          k,
          p.toCharArray(),
          message.byteInputStream(),
          plaintextStream,
          PGPDecryptOptions.Builder().build(),
        )
      assertTrue(res.isOk)
      assertEquals(PLAIN_TEXT, plaintextStream.toString(Charsets.UTF_8))
    }
  }

  @Test
  fun aeadDecryptEncryptReDecrypt() {
    val secKey = PGPKey(TestUtils.getAEADSecretKey())
    val plaintextStream = ByteArrayOutputStream()
    var decryptRes =
      cryptoHandler.decrypt(
        secKey,
        AEAD_KEY_PASSPHRASE.toCharArray(),
        AEAD_ENCRYPTED_TEXT.byteInputStream(Charsets.UTF_8),
        plaintextStream,
        PGPDecryptOptions.Builder().build(),
      )
    assertTrue(decryptRes.isOk)
    val decryptedText = plaintextStream.toString(Charsets.UTF_8)
    val ciphertextStream = ByteArrayOutputStream()
    val encryptRes =
      cryptoHandler.encrypt(
        listOf(secKey),
        null,
        decryptedText.byteInputStream(Charsets.UTF_8),
        ciphertextStream,
        PGPEncryptOptions.Builder().withAsciiArmor(true).build(),
      )
    assertTrue(encryptRes.isOk)
    val plaintextStream2 = ByteArrayOutputStream()
    decryptRes =
      cryptoHandler.decrypt(
        secKey,
        AEAD_KEY_PASSPHRASE.toCharArray(),
        ciphertextStream.toByteArray().inputStream(),
        plaintextStream2,
        PGPDecryptOptions.Builder().build(),
      )
    assertTrue(decryptRes.isOk)
    assertEquals(decryptedText, plaintextStream2.toString(Charsets.UTF_8))
  }

  @Test
  fun detectsKeysWithPassphrase() {
    assertTrue(cryptoHandler.isPassphraseProtected(listOf(PGPKey(TestUtils.getArmoredSecretKey()))))
    assertTrue(
      cryptoHandler.isPassphraseProtected(
        listOf(PGPKey(TestUtils.getArmoredSecretKeyWithMultipleIdentities()))
      )
    )
  }

  @Test
  fun detectsKeysWithoutPassphrase() {
    val unprotectedKey =
      PGPKey(
        PGPainless.getInstance()
          .toAsciiArmor(PGPainless.getInstance().generateKey().modernKeyRing("John Doe"))
          .encodeToByteArray()
      )
    assertFalse(cryptoHandler.isPassphraseProtected(listOf(unprotectedKey)))
    assertTrue(cryptoHandler.passphraseIsCorrect(unprotectedKey, null))
    assertFalse(
      cryptoHandler.passphraseIsCorrect(unprotectedKey, "obviously wrong passphrase".toCharArray())
    )
  }

  @Test
  fun canHandleFiltersFormats() {
    assertFalse { cryptoHandler.canHandle("example.com") }
    assertTrue { cryptoHandler.canHandle("example.com.gpg") }
    assertFalse { cryptoHandler.canHandle("example.com.asc") }
  }

  @Test
  fun decryptWithPublicKeys() {
    val alice =
      PGPainless.getInstance()
        .generateKey()
        .modernKeyRing("Alice <owner@example.com>", KEY_PASSPHRASE_ALICE)
    val bob =
      PGPainless.getInstance()
        .generateKey()
        .modernKeyRing("Bob <owner@example.com>", KEY_PASSPHRASE_BOBBY)
    val bobCertificate = bob.toCertificate()
    val aliceKey = PGPKey(PGPainless.getInstance().toAsciiArmor(alice).encodeToByteArray())
    val bobKey = PGPKey(PGPainless.getInstance().toAsciiArmor(bobCertificate).encodeToByteArray())
    val ciphertextStream = ByteArrayOutputStream()
    val encryptRes =
      cryptoHandler.encrypt(
        listOf(aliceKey, bobKey),
        null,
        PLAIN_TEXT.byteInputStream(Charsets.UTF_8),
        ciphertextStream,
        PGPEncryptOptions.Builder().withAsciiArmor(true).build(),
      )
    assertTrue(encryptRes.isOk)
    val message = ciphertextStream.toByteArray().decodeToString()
    val info = MessageInspector().determineEncryptionInfoForMessage(message)
    assertTrue(info.isEncrypted)
    assertEquals(2, info.keyIds.size)
    assertFalse(info.isSignedOnly)

    var plaintextStream = ByteArrayOutputStream()
    var res =
      cryptoHandler.decrypt(
        aliceKey,
        KEY_PASSPHRASE_ALICE.toCharArray(),
        message.byteInputStream(),
        plaintextStream,
        PGPDecryptOptions.Builder().build(),
      )
    assertTrue(res.isOk)
    assertEquals(PLAIN_TEXT, plaintextStream.toString(Charsets.UTF_8))
    plaintextStream = ByteArrayOutputStream()
    res =
      cryptoHandler.decrypt(
        bobKey,
        KEY_PASSPHRASE_ALICE.toCharArray(),
        message.byteInputStream(),
        plaintextStream,
        PGPDecryptOptions.Builder().build(),
      )
    assertTrue(res.isErr)
    assertIs<NoDecryptionKeyAvailableException>(res.getError())
  }
}
