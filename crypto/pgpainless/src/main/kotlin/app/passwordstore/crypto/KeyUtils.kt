/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPIdentifier.UserId
import com.github.michaelbull.result.get
import com.github.michaelbull.result.runCatching
import java.util.Date
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKeyReader

/** Utility methods to deal with [PGPKey]s. */
public object KeyUtils {
  /**
   * Attempts to parse an [OpenPGPCertificate] from a given [PGPKey]. The key is first tried as a
   * secret key and then as a public one before the method gives up and returns null.
   */
  public fun tryParseCertificateOrKey(key: PGPKey): OpenPGPCertificate? {
    return runCatching {
        val incoming = OpenPGPKeyReader().parseKeysOrCertificates(key.contents.inputStream())
        // get first secret key and if there is none, get first certificate (public key)
        incoming.filter { it.isSecretKey() }?.firstOrNull() ?: incoming.firstOrNull()
      }
      .get()
  }

  /** Parses an [OpenPGPPrimaryKey] from the given [PGPKey] and calculates its long key ID */
  public fun tryGetId(key: PGPKey): KeyId? {
    return tryParseCertificateOrKey(key)?.getPrimaryKey()?.getKeyIdentifier()?.getKeyId()?.let {
      KeyId(it)
    }
  }

  /**
   * Parses an [OpenPGPPrimaryKey] from the given [OpenPGPCertificate] and calculates its long key
   * ID
   */
  public fun tryGetId(cert: OpenPGPCertificate): KeyId {
    return cert.getPrimaryKey().getKeyIdentifier().getKeyId().let { KeyId(it) }
  }

  /** Parses an [OpenPGPPrimaryKey] from the given [PGPKey] and attempts to obtain the [UserId] */
  public fun tryGetEmail(key: PGPKey): UserId? {
    return tryParseCertificateOrKey(key)?.getPrimaryKey()?.getValidUserIds()?.first()?.let {
      UserId(it.getUserId())
    }
  }

  /** Parses the [UserId] from the given [OpenPGPCertificate] */
  public fun tryGetEmail(cert: OpenPGPCertificate): UserId? {
    return cert.getPrimaryKey().getValidUserIds().firstOrNull()?.let { UserId(it.getUserId()) }
  }

  /**
   * Tests if the given [PGPKey] can be used for encryption (as of today), which is a bare minimum
   * necessity for the app.
   */
  public fun isKeyUsable(key: PGPKey): Boolean {
    val certificate = tryParseCertificateOrKey(key) ?: return false
    return certificate.getEncryptionKeys(Date()).isNotEmpty()
  }

  /** Tests if the given [PGPKey] provides a secret key */
  public fun hasSecretKey(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.isSecretKey() ?: false

  /** Tests if the given [OpenPGPCertificate] provides a secret key */
  public fun hasSecretKey(cert: OpenPGPCertificate): Boolean = cert.isSecretKey()

  public fun extractPublicKeyData(key: PGPKey): ByteArray? {
    return tryParseCertificateOrKey(key)?.let {
      OpenPGPCertificate(it.getPGPPublicKeyRing() as PGPKeyRing)
        .toAsciiArmoredString()
        .toByteArray()
    }
  }
}
