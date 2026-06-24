/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPIdentifier.UserId
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getOr
import com.github.michaelbull.result.runCatching
import java.security.PublicKey
import java.util.Date
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.api.OpenPGPCertificate
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.openpgp.api.OpenPGPKeyReader
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter
import org.pgpainless.key.info.KeyRingInfo

/** Utility methods to deal with [PGPKey]s. */
public object KeyUtils {

  /**
   * Attempts to parse an [OpenPGPCertificate] from a given [PGPKey]. The key is first tried as a
   * secret keyring and then as a public one before the method gives up and returns null.
   */
  public fun tryParseCertificateOrKey(key: PGPKey): OpenPGPCertificate? = runCatching {
    val incoming = OpenPGPKeyReader().parseKeysOrCertificates(key.contents.inputStream())
    // get first secret key and if there is none, get first certificate (public keyring)
    incoming.filter { it.isSecretKey() }?.firstOrNull() ?: incoming.firstOrNull()
  }
    .get()

  /**
   * Parses every PGP certificate or key block contained in [key]'s payload. A typical multi-key
   * file (e.g. produced by `gpg --export A B C`) holds several concatenated blocks; this helper
   * yields one [OpenPGPCertificate] per block, with any secret keys ordered before public
   * certificates to match the preference used by [tryParseCertificateOrKey]. The elements in the
   * sorted list need to be visited once more to strip those public certificates whose secret
   * counterpart with the same key ID has already been included.
   *
   * Returns an empty list if parsing fails or no key is found.
   */
  public fun parseAllCertificatesOrKeys(key: PGPKey): List<OpenPGPCertificate> = runCatching {
    var primaryKeyIds = mutableListOf<Long>()
    OpenPGPKeyReader()
      .parseKeysOrCertificates(key.contents.inputStream())
      .sortedByDescending { cert ->
        cert.isSecretKey()
      }
      .filterNot { cert ->
        val primaryKeyId = cert.getKeyIdentifier().getKeyId()
        primaryKeyIds.contains(primaryKeyId).also { primaryKeyIds.add(primaryKeyId) }
      }
  }
    .getOr(emptyList())

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

  /**
   * Queries all secret subkey IDs of a given [OpenPGPCertificate] along with their usages (C,E,S,A)
   * and whether the private key was stripped
   */
  public fun tryGetSecretSubkeyIdsUsagesIsStripped(
    key: PGPKey
  ): List<Triple<KeyId, String, Boolean>>? =
    tryParseCertificateOrKey(key)?.let { tryGetSecretSubkeyIdsUsagesIsStripped(it) }

  /**
   * Queries all secret subkey IDs of a given [PGPKey] along with their usages (C,E,S,A) and whether
   * the private key was stripped
   */
  public fun tryGetSecretSubkeyIdsUsagesIsStripped(
    cert: OpenPGPCertificate
  ): List<Triple<KeyId, String, Boolean>>? {
    if (cert !is OpenPGPKey) return null
    return cert.getSecretKeys().entries.map {
      val keyId = KeyId(it.key.getKeyId())
      val usages =
        "[" +
          (if (it.value.isSigningKey(Date())) "S" else "") +
          (if (it.value.isCertificationKey(Date())) "C" else "") +
          (if (it.value.isEncryptionKey(Date())) "E" else "") +
          (if (it.value.hasKeyFlags(Date(), KeyFlags.AUTHENTICATION)) "A" else "") +
          "]"
      val isStripped = it.value.getPGPSecretKey().isPrivateKeyEmpty()
      Triple(keyId, usages, isStripped)
    }
  }

  /** Parses an [OpenPGPPrimaryKey] from the given [PGPKey] and attempts to obtain the [UserId] */
  public fun tryGetUserId(key: PGPKey): UserId? =
    tryParseCertificateOrKey(key)?.let { tryGetUserId(it) }

  /** Parses the [UserId] from the given [OpenPGPCertificate] */
  public fun tryGetUserId(cert: OpenPGPCertificate): UserId? =
    cert.getPrimaryKey().getUserIDs().firstOrNull()?.let { UserId(it.getUserId()) }

  /** Tests if the given [PGPKey] content is a PGP certificate or key at all */
  public fun isCertificateOrKey(key: PGPKey): Boolean = tryParseCertificateOrKey(key) != null

  /** Tests if the given [PGPKey] provides any secret non-stripped subkey */
  public fun isSecretKey(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { isSecretKey(it) } ?: false

  /** Tests if the given [OpenPGPCertificate] provides any secret non-stripped subkey */
  public fun isSecretKey(cert: OpenPGPCertificate): Boolean =
    cert is OpenPGPKey &&
      cert.getSecretKeys().values.any { !it.getPGPSecretKey().isPrivateKeyEmpty() }

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

  /** Tests if the given [PGPKey] provides a decryption-capable secret subkey */
  public fun hasDecKey(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { hasDecKey(it) } ?: false

  /** Tests if the given [OpenPGPCertificate] provides a decryption-capable secret subkey */
  public fun hasDecKey(cert: OpenPGPCertificate): Boolean =
    cert is OpenPGPKey &&
      cert.getSecretKeys().values.any {
        it.isEncryptionKey() && !it.getPGPSecretKey().isPrivateKeyEmpty()
      }

  /** Tests if the given [PGPKey] provides an authentication-capable secret subkey */
  public fun hasAuthKey(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { hasAuthKey(it) } ?: false

  /** Tests if the given [OpenPGPCertificate] provides an authentication-capable secret subkey */
  public fun hasAuthKey(cert: OpenPGPCertificate): Boolean {
    if (cert !is OpenPGPKey) return false
    val authFlags = listOf(KeyFlags.AUTHENTICATION, KeyFlags.SIGN_DATA, KeyFlags.CERTIFY_OTHER)
    val subkeys = cert.getSecretKeys().values
    val authKeys =
      authFlags
        .map { flag ->
          subkeys
            .filter { it.hasKeyFlags(Date(), flag) && !it.getPGPSecretKey().isPrivateKeyEmpty() }
            .firstOrNull()
        }
        .filterNotNull()
    return authKeys.isNotEmpty()
  }

  /**
   * Parse the public part of the first authentication-capable subkey from [OpenPGPCertificate] or
   * null if none was found
   */
  public fun extractPublicAuthKey(key: PGPKey): PublicKey? =
    tryParseCertificateOrKey(key)?.let { extractPublicAuthKey(it) } ?: null

  /**
   * Parse the public part of the first authentication-capable subkey from [OpenPGPCertificate] or
   * null if none was found, the returned key format is java.security.PublicKey, as used by sshj
   */
  public fun extractPublicAuthKey(cert: OpenPGPCertificate): PublicKey? {
    if (cert !is OpenPGPKey) return null

    /* A and S subkeys as well as the primary C key are equally suitable for authentication;
     * we pick the first subkey matching one of the capabilities in the given ranking order: */
    val authFlags = listOf(KeyFlags.AUTHENTICATION, KeyFlags.SIGN_DATA, KeyFlags.CERTIFY_OTHER)
    val subkeys =
      cert.getSecretKeys().values.sortedByDescending { it.getCreationTime() } // newest first
    val authKeys =
      authFlags
        .map { flag ->
          subkeys
            .filter { it.hasKeyFlags(Date(), flag) && !it.getPGPSecretKey().isPrivateKeyEmpty() }
            .firstOrNull()
        }
        .filterNotNull()

    return if (authKeys.isEmpty()) null
    else
      JcaPGPKeyConverter()
        .setProvider(BouncyCastleProvider())
        .getPublicKey(authKeys.first().getPGPSecretKey().getPublicKey())
  }

  public fun extractPublicKeyData(key: PGPKey): ByteArray? =
    tryParseCertificateOrKey(key)?.let {
      OpenPGPCertificate(it.getPGPPublicKeyRing() as PGPKeyRing)
        .toAsciiArmoredString()
        .toByteArray()
    }
}
