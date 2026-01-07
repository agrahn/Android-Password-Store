/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPIdentifier.UserId
import com.github.michaelbull.result.get
import com.github.michaelbull.result.runCatching
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKeyReader
import org.pgpainless.key.info.KeyRingInfo

/** Utility methods to deal with [PGPKey]s. */
public object KeyUtils {
  /**
   * Attempts to parse an [OpenPGPCertificate] from a given [PGPKey]. The key is first tried as a
   * secret keyring and then as a public one before the method gives up and returns null.
   */
  public fun tryParseCertificateOrKey(key: PGPKey): OpenPGPCertificate? =
    runCatching {
        val incoming = OpenPGPKeyReader().parseKeysOrCertificates(key.contents.inputStream())
        // get first secret key and if there is none, get first certificate (public keyring)
        incoming.filter { it.isSecretKey() }?.firstOrNull() ?: incoming.firstOrNull()
      }
      .get()

  /**
   * Parses an [OpenPGPPrimaryKey] from the given [PGPKey] and calculates its long primary key ID
   */
  public fun tryGetKeyId(key: PGPKey): KeyId? =
    tryParseCertificateOrKey(key)?.let { tryGetKeyId(it) }

  /**
   * Parses an [OpenPGPPrimaryKey] from the given [OpenPGPCertificate] and calculates its long
   * primary key ID
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

  /** Tests if the given [PGPKey] provides a decryption subkey */
  public fun hasSecretKey(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { hasSecretKey(it) } ?: false

  /** Tests if the given [OpenPGPCertificate] provides a decryption subkey */
  public fun hasSecretKey(cert: OpenPGPCertificate): Boolean =
    cert is OpenPGPKey &&
      cert.getSecretKeys().values.any {
        it.isEncryptionKey() && !it.getPGPSecretKey().isPrivateKeyEmpty()
      }

  public fun extractPublicKeyData(key: PGPKey): ByteArray? =
    tryParseCertificateOrKey(key)?.let {
      OpenPGPCertificate(it.getPGPPublicKeyRing() as PGPKeyRing)
        .toAsciiArmoredString()
        .toByteArray()
    }
}
