/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import org.bouncycastle.openpgp.PGPSessionKey
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPIdentifier.UserId
import com.github.michaelbull.result.get
import com.github.michaelbull.result.runCatching
import java.io.ByteArrayInputStream
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.pgpainless.PGPainless
import org.pgpainless.key.parsing.KeyRingReader
import org.pgpainless.util.ArmorUtils

/** Utility methods to deal with [PGPKey]s. */
public object KeyUtils {
  /**
   * Attempts to parse a [PGPKeyRing] from a given [key]. The key is first tried as a secret key and
   * then as a public one before the method gives up and returns null.
   */
  public fun tryParseKeyring(key: PGPKey): PGPKeyRing? {
    return runCatching { KeyRingReader.readKeyRing(key.contents.inputStream()) }.get()
  }

  /** Parses a [PGPKeyRing] from the given [key] and calculates its long key ID */
  public fun tryGetId(key: PGPKey): KeyId? {
    val keyRing = tryParseKeyring(key) ?: return null
    return KeyId(keyRing.publicKey.keyID)
  }

  /** Parses a [PGPKeyRing] from the given [key] and calculates the encryption subkey's long key ID */
  public fun tryGetEncryptionId(key: PGPKey): KeyId? {
    val keyRing = tryParseKeyring(key) ?: return null
    val encryptionKey = keyRing.getPublicKeys().asSequence().toList().firstOrNull{ it.isEncryptionKey() } ?: return null
    return KeyId(encryptionKey.keyID)
  }

  /**
   * Parses a [PGPKeyRing] from the given [key] and tries to determine its public key encryption algorithm;
   * returned integer code is one of https://www.rfc-editor.org/rfc/rfc4880.html#section-9.1 or zero if no
   * encryption key was found
   */
  public fun tryGetEncryptionAlgorithm(key: PGPKey): Int {
    val keyRing = tryParseKeyring(key) ?: return 0
    val encryptionKey = keyRing.getPublicKeys().asSequence().toList().firstOrNull{ it.isEncryptionKey() } ?: return 0
    return encryptionKey.getAlgorithm()
  }

  /**
   * Attempts to parse the given [PGPKey] into a [PGPKeyRing] and obtains the [UserId] of the
   * corresponding public key.
   */
  public fun tryGetEmail(key: PGPKey): UserId? {
    val keyRing = tryParseKeyring(key) ?: return null
    return UserId(keyRing.publicKey.userIDs.next())
  }

  /**
   * Tests if the given [key] can be used for encryption, which is a bare minimum necessity for the
   * app.
   */
  public fun isKeyUsable(key: PGPKey): Boolean {
    return runCatching {
        val keyRing = tryParseKeyring(key) ?: return false
        PGPainless.inspectKeyRing(keyRing).isUsableForEncryption
      }
      .get() != null
  }

  /** Tests if the given [key] provides a secret key */
  public fun hasSecretKey(key: PGPKey): Boolean {
    return runCatching { PGPainless.readKeyRing().secretKeyRing(key.contents) }.get() != null
  }

  public fun extractPublicKey(key: PGPKey): PGPKey? {
    val keyRing = tryParseKeyring(key) ?: return null
    val publicKeyRing = PGPPublicKeyRing(keyRing.getPublicKeys().asSequence().toList())
    return PGPKey(publicKeyRing.getEncoded())
  }

  public fun extractPublicKeyData(key: PGPKey): ByteArray? {
    val keyRing = tryParseKeyring(key) ?: return null
    val publicKeyRing = PGPPublicKeyRing(keyRing.getPublicKeys().asSequence().toList())
    return PGPainless.asciiArmor(publicKeyRing).toByteArray()
  }

  public fun getEncryptedSessionKeys(
    message: ByteArray
  ): MutableList<Triple<Int, ByteArray, PGPIdentifier?>> {
    val decoderStream = ArmorUtils.getDecoderStream(ByteArrayInputStream(message))
    val bcpgStream = BCPGInputStream(decoderStream)

    val encSessionKeys: MutableList<Triple<Int, ByteArray, PGPIdentifier?>> = mutableListOf()

    var packet = bcpgStream.readPacket()
    while (packet != null) {
      if (packet is PublicKeyEncSessionPacket) {
        val algorithm = packet.getAlgorithm()
        val encSessionKeyBC = packet.getEncSessionKey()
        /* BouncyCastle exports encrypted session keys in a special format where
         * the first two bytes denote the length. We need to strip them.
         */
        val encSessionKey = encSessionKeyBC[0].copyOfRange(2, encSessionKeyBC[0].count())
        val keyID = packet.getKeyID()
        encSessionKeys.add(Triple(algorithm, encSessionKey, KeyId(keyID)))
      }
      packet = bcpgStream.readPacket()
    }

    return encSessionKeys
  }

  /**
   * Creates BC PGPSessionKey from decrypted session key data; session key data format acc. to
   * https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-fields-f
   */
  public fun createPGPSessionKey(bytes: ByteArray) : PGPSessionKey? {
      val algorithm = bytes[0].toUByte().toInt() // symmetric key algorithm
      val keyData = when(algorithm) {
        7 ->  // AES-128
          bytes.copyOfRange(1, 1+128/8)
        8 ->  // AES-192
          bytes.copyOfRange(1, 1+192/8)
        9 ->  // AES-256
          bytes.copyOfRange(1, 1+256/8)
        else -> return null
      }
      return PGPSessionKey(algorithm, keyData)
  }
}
