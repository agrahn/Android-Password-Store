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
   * Key-usage flags that make a (sub)key usable for authentication, in preference order: a
   * dedicated Authentication subkey first, then a Signing subkey, then the primary Certification
   * key.
   */
  private val AUTH_CAPABILITY_RANKING =
    listOf(KeyFlags.AUTHENTICATION, KeyFlags.SIGN_DATA, KeyFlags.CERTIFY_OTHER)

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

  /** Returns all fingerprints present in [key], including subkeys. */
  public fun tryGetFingerprints(key: PGPKey): List<ByteArray> =
    tryParseCertificateOrKey(key)?.getAllKeyIdentifiers()?.mapNotNull { it.getFingerprint() }
      ?: emptyList()

  /** Returns true if [key] contains any of [fingerprints]. */
  public fun containsAnyFingerprint(key: PGPKey, fingerprints: List<ByteArray>): Boolean {
    val keyFingerprints = tryGetFingerprints(key)
    return keyFingerprints.any { keyFingerprint ->
      fingerprints.any { fingerprint -> keyFingerprint.contentEquals(fingerprint) }
    }
  }

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

  /** Tests if the given [PGPKey] provides any secret subkey, including smartcard stubs. */
  public fun isSecretKey(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { isSecretKey(it) } ?: false

  /**
   * Tests if the given [OpenPGPCertificate] provides any secret subkey, including smartcard stubs.
   */
  public fun isSecretKey(cert: OpenPGPCertificate): Boolean =
    cert is OpenPGPKey && cert.getSecretKeys().values.any()

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

  /** Tests if the given [PGPKey] provides a decryption-capable secret subkey. */
  public fun hasDecKey(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { hasDecKey(it) } ?: false

  /** Tests if the given [OpenPGPCertificate] provides a decryption-capable secret subkey. */
  public fun hasDecKey(cert: OpenPGPCertificate): Boolean =
    cert is OpenPGPKey && cert.getSecretKeys().values.any { it.isEncryptionKey() }

  /** Tests if the given [PGPKey] provides only card-backed decryption stubs. */
  public fun hasOnlyStubDecKeys(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { hasOnlyStubDecKeys(it) } ?: false

  /** Tests if the given [OpenPGPCertificate] provides only card-backed decryption stubs. */
  public fun hasOnlyStubDecKeys(cert: OpenPGPCertificate): Boolean =
    cert is OpenPGPKey &&
      cert.getSecretKeys().values.any { it.isEncryptionKey() } &&
      cert
        .getSecretKeys()
        .values
        .filter { it.isEncryptionKey() }
        .all { it.getPGPSecretKey().isPrivateKeyEmpty() }

  /** Tests if the given [PGPKey] provides an authentication-capable (sub)key. */
  public fun hasAuthKey(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { hasAuthKey(it) } ?: false

  /**
   * Tests if the given [OpenPGPCertificate] provides an authentication-capable (sub)key.
   *
   * This inspects the certificate's *public* component keys, so it works for a public-only
   * certificate and for a smartcard-backed key whose private half lives on the card (a stub with
   * empty private material) — in both cases the key is still authentication-capable (the card, or a
   * private key held elsewhere, does the actual signing).
   */
  public fun hasAuthKey(cert: OpenPGPCertificate): Boolean = AUTH_CAPABILITY_RANKING.any { flag ->
    cert.getComponentKeysWithFlag(Date(), flag).isNotEmpty()
  }

  /**
   * Tests if the given [PGPKey] provides an authentication-capable secret subkey whose private key
   * is present locally (i.e. can sign without a smartcard). Used to decide whether a key can be
   * used for SSH authentication on its own.
   */
  public fun hasPrivateAuthKey(key: PGPKey): Boolean =
    tryParseCertificateOrKey(key)?.let { hasPrivateAuthKey(it) } ?: false

  /** @see hasPrivateAuthKey */
  public fun hasPrivateAuthKey(cert: OpenPGPCertificate): Boolean {
    if (cert !is OpenPGPKey) return false
    val subkeys = cert.getSecretKeys().values
    return AUTH_CAPABILITY_RANKING.any { flag ->
      subkeys.any { it.hasKeyFlags(Date(), flag) && !it.getPGPSecretKey().isPrivateKeyEmpty() }
    }
  }

  /**
   * Parse the public part of the first authentication-capable (sub)key from [OpenPGPCertificate] or
   * null if none was found
   */
  public fun extractPublicAuthKey(key: PGPKey): PublicKey? =
    tryParseCertificateOrKey(key)?.let { extractPublicAuthKey(it) } ?: null

  /**
   * Parse the public part of the first authentication-capable (sub)key from [OpenPGPCertificate] or
   * null if none was found, the returned key format is java.security.PublicKey, as used by sshj.
   *
   * Only the public half is needed here (it becomes the SSH public key), so this reads the
   * certificate's *public* component keys. That makes it work for public-only certificates and for
   * smartcard-backed stubs (empty private material) alike — the private authentication operation
   * happens later, on the card.
   */
  public fun extractPublicAuthKey(cert: OpenPGPCertificate): PublicKey? {
    // A and S subkeys as well as the primary C key are equally suitable for authentication; pick
    // the
    // newest key matching one of the capabilities in the given ranking order.
    val authKey =
      AUTH_CAPABILITY_RANKING.firstNotNullOfOrNull { flag ->
        cert.getComponentKeysWithFlag(Date(), flag).maxByOrNull {
          it.getCreationTime()
        } // newest first
      } ?: return null

    return JcaPGPKeyConverter()
      .setProvider(BouncyCastleProvider())
      .getPublicKey(authKey.getPGPPublicKey())
  }

  public fun extractPublicKeyData(key: PGPKey): ByteArray? =
    tryParseCertificateOrKey(key)?.let {
      OpenPGPCertificate(it.getPGPPublicKeyRing() as PGPKeyRing)
        .toAsciiArmoredString()
        .toByteArray()
    }
}
