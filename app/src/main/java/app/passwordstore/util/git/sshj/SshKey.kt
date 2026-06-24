/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git.sshj

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.content.edit
import app.passwordstore.Application
import app.passwordstore.R
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKey
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.gitSecrets
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.git.operation.CredentialFinder
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.runCatching
import java.io.File
import java.io.IOException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import logcat.asLog
import logcat.logcat
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.common.SSHRuntimeException
import net.schmizz.sshj.common.SecurityUtils
import net.schmizz.sshj.userauth.keyprovider.KeyProvider
import net.schmizz.sshj.userauth.password.PasswordFinder
import org.bouncycastle.jce.provider.BouncyCastleProvider

private const val PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore"
private const val KEYSTORE_ALIAS = "sshkey"

private val androidKeystore: KeyStore by unsafeLazy {
  KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE).apply { load(null) }
}

private val KeyStore.sshPrivateKey
  get() = getKey(KEYSTORE_ALIAS, null) as? PrivateKey

private val KeyStore.sshPublicKey
  get() = getCertificate(KEYSTORE_ALIAS)?.publicKey

fun parseSshPublicKey(sshPublicKey: String): PublicKey? {
  val sshKeyParts = sshPublicKey.split("""\s+""".toRegex())
  if (sshKeyParts.size < 2) return null
  return normalizeForSshj(
    Buffer.PlainBuffer(Base64.decode(sshKeyParts[1], Base64.NO_WRAP)).readPublicKey()
  )
}

internal fun normalizeForSshj(key: PublicKey): PublicKey {
  if (KeyType.fromKey(key) != KeyType.UNKNOWN) return key

  val encoded =
    key.encoded
      ?: throw SSHRuntimeException(
        "Cannot normalize key: encoded form is null (${key.javaClass.name})"
      )

  val bcAlgorithm =
    when (key.algorithm) {
      "EdDSA",
      "Ed25519",
      "1.3.101.112" -> "Ed25519"
      else -> key.algorithm
    }

  return runCatching {
    KeyFactory.getInstance(bcAlgorithm, BouncyCastleProvider.PROVIDER_NAME)
      .generatePublic(X509EncodedKeySpec(encoded))
  }
    .getOrElse { error ->
      logcat("normalizeForSshj") { error.asLog() }
      throw SSHRuntimeException(
        "Cannot normalize ${key.javaClass.name} (algorithm=${key.algorithm}) for SSHJ",
        error,
      )
    }
}

fun toSshPublicKey(publicKey: PublicKey): String {
  val normalizedKey = normalizeForSshj(publicKey)
  val rawPublicKey = Buffer.PlainBuffer().putPublicKey(normalizedKey).compactData
  val keyType = KeyType.fromKey(normalizedKey)
  return "$keyType ${Base64.encodeToString(rawPublicKey, Base64.NO_WRAP)}"
}

object SshKey {
  val sshPublicKey
    get() = if (publicKeyFile.exists()) publicKeyFile.readText() else null

  val canShowSshPublicKey
    get() = type in listOf(Type.KeystoreNative, Type.KeystoreWrappedEd25519, Type.ImportedPGP)

  val exists
    get() = type != null

  val pgpLongKeyId
    get() = context.sharedPrefs.getLong(PreferenceKeys.SSH_PGP_KEY_ID, 0L)

  val mustAuthenticate: Boolean
    get() {
      return runCatching {
        when (type) {
          Type.KeystoreNative ->
            when (val key = androidKeystore.getKey(KEYSTORE_ALIAS, null)) {
              is PrivateKey -> {
                val factory = KeyFactory.getInstance(key.algorithm, PROVIDER_ANDROID_KEY_STORE)
                return@runCatching factory
                  .getKeySpec(key, KeyInfo::class.java)
                  .isUserAuthenticationRequired
              }
              is SecretKey -> {
                val factory =
                  SecretKeyFactory.getInstance(key.algorithm, PROVIDER_ANDROID_KEY_STORE)
                return@runCatching (factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo)
                  .isUserAuthenticationRequired
              }
              else -> throw IllegalStateException("SSH key does not exist in Keystore")
            }
          Type.KeystoreWrappedEd25519 -> {
            context.gitSecrets
              .getString(KEYSTORE_ALIAS, "false:")
              ?.split(":", limit = 2)
              ?.getOrNull(0) == "true"
          }
          else -> return@runCatching false
        }
      }
        .getOrElse { error ->
          // It is fine to swallow the exception here since it will reappear when the key
          // is used for SSH authentication and can then be shown in the UI.
          logcat { error.asLog() }
          false
        }
    }

  private val context: Context
    get() = Application.instance.applicationContext

  private val privateKeyFile
    get() = File(context.filesDir, ".ssh_key")

  private val publicKeyFile
    get() = File(context.filesDir, ".ssh_key.pub")

  var type: Type?
    get() = Type.fromValue(context.sharedPrefs.getString(PreferenceKeys.GIT_REMOTE_KEY_TYPE))
    private set(value) =
      context.sharedPrefs.edit { putString(PreferenceKeys.GIT_REMOTE_KEY_TYPE, value?.value) }

  private val isStrongBoxSupported by unsafeLazy {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
      context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    else false
  }

  public enum class Type(val value: String) {
    Imported("imported"),
    KeystoreNative("keystore_native"),
    KeystoreWrappedEd25519("keystore_wrapped_eddsa"),
    ImportedPGP("imported_pgp");

    companion object {

      fun fromValue(value: String?): Type? = entries.associateBy { it.value }[value]
    }
  }

  enum class Algorithm(
    val algorithm: String,
    val applyToSpec: KeyGenParameterSpec.Builder.() -> Unit,
  ) {
    Rsa(
      KeyProperties.KEY_ALGORITHM_RSA,
      {
        setKeySize(3072)
        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        setDigests(
          KeyProperties.DIGEST_SHA1,
          KeyProperties.DIGEST_SHA256,
          KeyProperties.DIGEST_SHA512,
        )
      },
    ),
    Ecdsa(
      KeyProperties.KEY_ALGORITHM_EC,
      {
        setKeySize(256)
        setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        setDigests(KeyProperties.DIGEST_SHA256)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          setIsStrongBoxBacked(isStrongBoxSupported)
        }
      },
    ),
  }

  fun delete() {
    androidKeystore.deleteEntry(KEYSTORE_ALIAS)
    context.gitSecrets.edit { remove(KEYSTORE_ALIAS) } // encrypted EdDsa
    context.sharedPrefs.edit { remove(PreferenceKeys.SSH_PGP_KEY_ID) }
    context.gitSecrets.edit { remove(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE) }

    if (privateKeyFile.isFile) {
      privateKeyFile.delete()
    }
    if (publicKeyFile.isFile) {
      publicKeyFile.delete()
    }

    type = null
  }

  fun import(uri: Uri) {
    // First check whether the content at uri is likely an SSH private key.
    val fileSize =
      context.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use {
        cursor ->
        // Cursor returns only a single row.
        cursor.moveToFirst()
        cursor.getInt(0)
      } ?: throw IOException(context.getString(R.string.ssh_key_does_not_exist))

    // We assume that an SSH key's ideal size is > 0 bytes && < 100 kilobytes.
    if (fileSize > 100_000 || fileSize == 0)
      throw IllegalArgumentException(
        context.getString(R.string.ssh_key_import_error_not_an_ssh_key_message)
      )

    val sshKeyInputStream =
      context.contentResolver.openInputStream(uri)
        ?: throw IOException(context.getString(R.string.ssh_key_does_not_exist))
    val lines = sshKeyInputStream.use { `is` -> `is`.bufferedReader().readLines() }

    // The file must have more than 2 lines, and the first and last line must have private key
    // markers.
    if (
      lines.size < 2 ||
        !Regex("BEGIN .* PRIVATE KEY").containsMatchIn(lines.first()) ||
        !Regex("END .* PRIVATE KEY").containsMatchIn(lines.last())
    )
      throw IllegalArgumentException(
        context.getString(R.string.ssh_key_import_error_not_an_ssh_key_message)
      )

    val userId = context.sharedPrefs.getString(PreferenceKeys.GIT_CONFIG_AUTHOR_EMAIL) ?: "nn@aps"

    // At this point, we are reasonably confident that we have actually been provided a private
    // key and delete the old key.
    delete()

    // Canonicalize line endings to '\n'.
    privateKeyFile.writeText(lines.joinToString("\n"))

    type = Type.Imported
  }

  fun generateKeystoreNativeKey(algorithm: Algorithm, requireAuthentication: Boolean) {
    delete()

    val parameterSpec =
      KeyGenParameterSpec.Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_SIGN).run {
        apply(algorithm.applyToSpec)
        if (requireAuthentication) {
          setUserAuthenticationRequired(true)
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(
              30,
              KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            )
          } else {
            @Suppress("DEPRECATION") setUserAuthenticationValidityDurationSeconds(30)
          }
        }
        build()
      }
    val keyPair =
      KeyPairGenerator.getInstance(algorithm.algorithm, PROVIDER_ANDROID_KEY_STORE).run {
        initialize(parameterSpec, SecureRandom())
        generateKeyPair()
      }

    val userId = context.sharedPrefs.getString(PreferenceKeys.GIT_CONFIG_AUTHOR_EMAIL) ?: "nn@aps"

    // Write public key in SSH format to .ssh_key.pub.
    publicKeyFile.writeText(toSshPublicKey(keyPair.public) + " " + userId)

    type = Type.KeystoreNative
  }

  fun generateKeystoreWrappedEd25519Key(requireAuthentication: Boolean) {
    delete()

    // Generate the Ed25519 key pair, encrypt the private key and store it away
    val keyPair =
      KeyPairGenerator.getInstance("EdDSA", BouncyCastleProvider()).run {
        initialize(ECGenParameterSpec("ed25519"), SecureRandom())
        generateKeyPair()
      }

    val privateEncodedEncrypted =
      AESEncryption.encrypt(
          keyPair.private.encoded,
          if (requireAuthentication) AESEncryption.KeyType.PERSISTENT_WITH_PIN
          else AESEncryption.KeyType.PERSISTENT,
        )
        ?.concatToString()

    context.gitSecrets.edit {
      putString(
        KEYSTORE_ALIAS,
        "${requireAuthentication}:" + privateEncodedEncrypted,
      )
    }

    val userId = context.sharedPrefs.getString(PreferenceKeys.GIT_CONFIG_AUTHOR_EMAIL) ?: "nn@aps"
    publicKeyFile.writeText(toSshPublicKey(keyPair.public) + " " + userId)

    type = Type.KeystoreWrappedEd25519
  }

  fun usePgpAuthKey(key: PGPKey) {
    val publicAuthKey =
      KeyUtils.extractPublicAuthKey(key)
        ?: throw IllegalArgumentException(
          context.getString(R.string.ssh_use_pgp_key_error_no_authkey_message)
        )

    val authKeyId =
      KeyUtils.tryGetKeyId(key)
        ?: throw NullPointerException("Could not retrieve key ID from PGP certificate")
    val userId =
      KeyUtils.tryGetUserId(key)?.let { PGPIdentifier.splitUserId(it.email) }
        ?: authKeyId.toString()

    delete()

    publicKeyFile.writeText(toSshPublicKey(publicAuthKey) + " " + userId)
    context.sharedPrefs.edit { putLong(PreferenceKeys.SSH_PGP_KEY_ID, authKeyId.id) }

    type = Type.ImportedPGP
  }

  fun provide(client: SSHClient, passphraseFinder: PasswordFinder): KeyProvider? =
    when (type) {
      Type.Imported -> client.loadKeys(privateKeyFile.absolutePath, passphraseFinder)
      Type.KeystoreNative -> provideKeystoreNativeKey(client)
      Type.KeystoreWrappedEd25519 -> provideKeystoreWrappedEd25519Key(client)
      Type.ImportedPGP -> providePgpAuthenticationKey(client, passphraseFinder)
      null -> null
    }

  private fun provideKeystoreNativeKey(client: SSHClient): KeyProvider = runCatching {
    val publicKey = androidKeystore.sshPublicKey ?: throw NullPointerException()
    val privateKey = androidKeystore.sshPrivateKey ?: throw NullPointerException()

    // let Keystore do cryptographic operations
    SecurityUtils.setRegisterBouncyCastle(false)
    SecurityUtils.setSecurityProvider(null)

    client.loadKeys(KeyPair(publicKey, privateKey))
  }
    .getOrElse { error ->
      logcat { error.asLog() }
      throw IOException(
        context.getString(R.string.ssh_use_pgp_key_error_unlocking_from_keystore_message),
        error,
      )
    }

  private fun provideKeystoreWrappedEd25519Key(client: SSHClient): KeyProvider = runCatching {
    val publicKey = sshPublicKey?.let { parseSshPublicKey(it) } ?: throw NullPointerException()

    val mustAuthenticateAndPrivateKeyEncrypted =
      context.gitSecrets.getString(KEYSTORE_ALIAS, "false:")?.split(":", limit = 2)

    val privateKeyEncoded =
      AESEncryption.decryptToByteArray(
        mustAuthenticateAndPrivateKeyEncrypted?.getOrNull(1)?.toCharArray(),
        if (mustAuthenticateAndPrivateKeyEncrypted?.getOrNull(0) == "true")
          AESEncryption.KeyType.PERSISTENT_WITH_PIN
        else AESEncryption.KeyType.PERSISTENT,
      )

    val keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider())
    val keySpec = PKCS8EncodedKeySpec(privateKeyEncoded)
    val privateKey = keyFactory.generatePrivate(keySpec)

    // ensure that BC carries out cryptographic operations
    SecurityUtils.setRegisterBouncyCastle(true)
    SecurityUtils.setSecurityProvider(BouncyCastleProvider.PROVIDER_NAME)

    client.loadKeys(KeyPair(publicKey, privateKey))
  }
    .getOrElse { error ->
      logcat { error.asLog() }
      throw IOException(
        context.getString(R.string.ssh_use_pgp_key_error_unlocking_wrapped_ed25519_message),
        error,
      )
    }

  private fun providePgpAuthenticationKey(
    client: SSHClient,
    passphraseFinder: PasswordFinder,
  ): KeyProvider = runCatching {
    (passphraseFinder as CredentialFinder).unlockAuthKeyPair()?.let { client.loadKeys(it) }
      ?: throw NullPointerException()
  }
    .getOrElse { error ->
      logcat { error.asLog() }
      throw IOException(
        context.getString(R.string.ssh_use_pgp_key_error_unlocking_pgp_auth_subkey_message),
        error,
      )
    }
}
