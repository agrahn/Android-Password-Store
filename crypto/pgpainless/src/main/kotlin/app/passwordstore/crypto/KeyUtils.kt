/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import java.io.InputStream
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPIdentifier.UserId
import com.github.michaelbull.result.get
import com.github.michaelbull.result.runCatching
import java.io.ByteArrayInputStream
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKeyReader
import org.pgpainless.key.info.KeyRingInfo
import org.pgpainless.util.ArmorUtils
import org.pgpainless.util.SessionKey
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags

/** Utility methods to deal with [PGPKey]s. */
public object KeyUtils {
  /**
   * Attempts to parse an [OpenPGPCertificate] from a given [PGPKey]. The key is first tried as a
   * secret key and then as a public one before the method gives up and returns null.
   */
  public fun tryParseCertificateOrKey(key: PGPKey): OpenPGPCertificate? =
    runCatching {
        val incoming = OpenPGPKeyReader().parseKeysOrCertificates(key.contents.inputStream())
        // get first secret key and if there is none, get first certificate (public key)
        incoming.filter { it.isSecretKey() }?.firstOrNull() ?: incoming.firstOrNull()
      }
      .get()

  /** Parses an [OpenPGPPrimaryKey] from the given [PGPKey] and calculates its long key ID */
  public fun tryGetKeyId(key: PGPKey): KeyId? =
    tryParseCertificateOrKey(key)?.getPrimaryKey()?.getKeyIdentifier()?.getKeyId()?.let {
      KeyId(it)
    }

  /**
   * Parses an [OpenPGPPrimaryKey] from the given [OpenPGPCertificate] and calculates its long key
   * ID
   */
  public fun tryGetKeyId(cert: OpenPGPCertificate): KeyId =
    cert.getPrimaryKey().getKeyIdentifier().getKeyId().let { KeyId(it) }

  /** Parses an [OpenPGPPrimaryKey] from the given [PGPKey] and attempts to obtain the [UserId] */
  public fun tryGetUserId(key: PGPKey): UserId? =
    tryParseCertificateOrKey(key)?.let { tryGetUserId(it) }

  /** Parses the [UserId] from the given [OpenPGPCertificate] */
  public fun tryGetUserId(cert: OpenPGPCertificate): UserId? =
    cert.getPrimaryKey().getUserIDs().firstOrNull()?.let { UserId(it.getUserId()) }

  /** Tests if the given [PGPKey] content is a PGP certificate or key at all */
  public fun isCertificateOrKey(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { true } ?: false

  /**
   * Tests if the given [PGPKey] can be used for encryption, which is a bare minimum necessity for
   * the app.
   */
  public fun isKeyUsable(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { isKeyUsable(it) } ?: false

  /**
   * Tests if the given [OpenPGPCertificate] can be used for encryption, which is a bare minimum
   * necessity for the app.
   */
  public fun isKeyUsable(cert: OpenPGPCertificate): Boolean =
    KeyRingInfo(cert).isUsableForEncryption

  /** Tests if the given [PGPKey] is an OpenPGPKey */
  public fun hasSecretKey(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { hasSecretKey(it) } ?: false

  /** Tests if the given [OpenPGPCertificate] is an OpenPGPKey */
  public fun hasSecretKey(cert: OpenPGPCertificate): Boolean = cert.isSecretKey

  public fun extractPublicKeyData(key: PGPKey): ByteArray? =
    tryParseCertificateOrKey(key)?.let {
      OpenPGPCertificate(it.getPGPPublicKeyRing() as PGPKeyRing)
        .toAsciiArmoredString()
        .toByteArray()
    }

  public fun extractPublicKey(key: PGPKey): PGPKey? =
    extractPublicKeyData(key)?.let { PGPKey(it) }

  /**
   * Creates PGPainless SessionKey from decrypted session key data
   */
  public fun getSessionKey(bytes: ByteArray): SessionKey? {
    val algorithm = bytes[0].toUByte().toInt() // symmetric key algorithm
    val keyData =
      when (algorithm) {
        2 -> // 3DES
        bytes.copyOfRange(1, 1 + 192 / 8)
        7 -> // AES-128
        bytes.copyOfRange(1, 1 + 128 / 8)
        8 -> // AES-192
        bytes.copyOfRange(1, 1 + 192 / 8)
        9 -> // AES-256
        bytes.copyOfRange(1, 1 + 256 / 8)
        else -> return null
      }
    return SessionKey(PGPSessionKey(algorithm, keyData))
  }
}
