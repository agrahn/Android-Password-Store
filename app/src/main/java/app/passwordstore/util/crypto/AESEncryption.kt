/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import app.passwordstore.Application
import app.passwordstore.util.extensions.decodeFromBase64ToByteArray
import app.passwordstore.util.extensions.encodeToBase64CharArray
import app.passwordstore.util.extensions.toByteArray
import app.passwordstore.util.extensions.toCharArray
import app.passwordstore.util.extensions.unsafeLazy
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.runCatching
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import logcat.asLog
import logcat.logcat

object AESEncryption {

  enum class KeyType {
    TEMPORARY,
    PERSISTENT,
    PERSISTENT_WITH_AUTHENTICATION,
  }

  private const val KEYSTORE_ALIAS = "AESKey" // valid during the lifetime of the app process
  // persistent, but without authentication (used for sensitive preferences and PIN caching)
  private const val KEYSTORE_ALIAS_NO_AUTHENTICATION = "AESKeyNoAuth"
  // persistent, with authentication (used for persistent passphrase caching)
  private const val KEYSTORE_ALIAS_WITH_AUTHENTICATION = "AESKeyWithAuth"
  private const val PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore"
  private const val TRANSFORMATION = "AES/GCM/NoPadding"
  private const val IV_SIZE = 12 // 12 bytes (96 bits) length of initialisation vector for GCM mode

  private val androidKeystore: KeyStore by unsafeLazy {
    KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE).apply { load(null) }
  }

  private val context: Context by unsafeLazy { Application.instance.applicationContext }

  private val isStrongBoxSupported by unsafeLazy {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
      context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    else false
  }

  // Initialize the KeyStore and generate an AES key if it doesn't exist
  private fun initKeyStore(keyType: KeyType) {
    val keyStoreAlias =
      when (keyType) {
        KeyType.TEMPORARY -> KEYSTORE_ALIAS
        KeyType.PERSISTENT -> KEYSTORE_ALIAS_NO_AUTHENTICATION
        KeyType.PERSISTENT_WITH_AUTHENTICATION -> KEYSTORE_ALIAS_WITH_AUTHENTICATION
      }

    if (!androidKeystore.containsAlias(keyStoreAlias)) {
      val keyGenerator =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER_ANDROID_KEY_STORE)
      val keyGenParameterSpec =
        KeyGenParameterSpec.Builder(
            keyStoreAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
          )
          .run {
            setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            setKeySize(256)
            if (keyType == KeyType.PERSISTENT_WITH_AUTHENTICATION) {
              setUserAuthenticationRequired(true)
            }
            /* disabled due to platform or firmware bug;
             * see https://github.com/agrahn/Android-Password-Store/issues/206#issuecomment-2783212156
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
              setIsStrongBoxBacked(isStrongBoxSupported)
            }
            */
            build()
          }
      keyGenerator.init(keyGenParameterSpec)
      keyGenerator.generateKey()
    }
  }

  // Retrieve the AES key from the KeyStore
  private fun getSecretKey(keyType: KeyType): SecretKey {
    val keyStoreAlias =
      when (keyType) {
        KeyType.TEMPORARY -> KEYSTORE_ALIAS
        KeyType.PERSISTENT -> KEYSTORE_ALIAS_NO_AUTHENTICATION
        KeyType.PERSISTENT_WITH_AUTHENTICATION -> KEYSTORE_ALIAS_WITH_AUTHENTICATION
      }
    return androidKeystore.getKey(keyStoreAlias, null) as SecretKey
  }

  /* Public methods */

  /* Get a Cipher instance for encryption, decryption and biometric authentication.
   * If encryptedBase64Data is null, it will be used for encryption. Otherwise, it will
   * be used for decryption. */
  fun getCipher(
    keyType: KeyType = KeyType.TEMPORARY,
    encryptedBase64Data: CharArray? = null,
  ): Cipher? {
    runCatching { initKeyStore(keyType) }
      .onFailure {
        return null
      }
    val cipher = Cipher.getInstance(TRANSFORMATION)
    return runCatching {
        if (encryptedBase64Data == null) {
          cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(keyType))
        } else {
          val iv = encryptedBase64Data.decodeFromBase64ToByteArray().copyOfRange(0, IV_SIZE)
          val spec = GCMParameterSpec(128, iv)
          cipher.init(Cipher.DECRYPT_MODE, getSecretKey(keyType), spec)
        }
        cipher
      }
      .getOrElse { e ->
        logcat { e.asLog() }
        null
      }
  }

  /* Encrypt a CharArray using the AES key from the KeyStore and Base64-encode the result;
   * prepend the cipher's init vector to the result */
  fun encrypt(
    data: CharArray?,
    keyType: KeyType = KeyType.TEMPORARY,
    cipher: Cipher? = null,
  ): CharArray? {
    if (data == null || !isHardwareBacked(keyType)) return null
    val c = cipher ?: getCipher(keyType)
    if (c == null) return null
    return runCatching { (c.iv + c.doFinal(data.toByteArray())).encodeToBase64CharArray() }
      .getOrElse { e ->
        logcat { e.asLog() }
        null
      }
  }

  // Decrypt Base64 encoded AES-encrypted data to CharArray
  fun decrypt(
    encryptedBase64Data: CharArray?,
    keyType: KeyType = KeyType.TEMPORARY,
    cipher: Cipher? = null,
  ): CharArray? {
    if (encryptedBase64Data == null || !isHardwareBacked(keyType)) return null
    val ivAndEncryptedData = encryptedBase64Data.decodeFromBase64ToByteArray()
    val encryptedBytes = ivAndEncryptedData.copyOfRange(IV_SIZE, ivAndEncryptedData.size)
    val c = cipher ?: getCipher(keyType, encryptedBase64Data)
    if (c == null) return null
    return runCatching { c.doFinal(encryptedBytes).toCharArray() }
      .getOrElse { e ->
        logcat { e.asLog() }
        null
      }
  }

  fun deleteKey(keyType: KeyType = KeyType.TEMPORARY) {
    val keyStoreAlias =
      when (keyType) {
        KeyType.TEMPORARY -> KEYSTORE_ALIAS
        KeyType.PERSISTENT -> KEYSTORE_ALIAS_NO_AUTHENTICATION
        KeyType.PERSISTENT_WITH_AUTHENTICATION -> KEYSTORE_ALIAS_WITH_AUTHENTICATION
      }
    if (androidKeystore.containsAlias(keyStoreAlias)) androidKeystore.deleteEntry(keyStoreAlias)
  }

  // Check if the AES key is hardware-backed
  fun isHardwareBacked(keyType: KeyType = KeyType.TEMPORARY): Boolean {
    runCatching { initKeyStore(keyType) }
      .onFailure {
        return false
      }
    val key = getSecretKey(keyType)
    val factory = SecretKeyFactory.getInstance(key.algorithm, PROVIDER_ANDROID_KEY_STORE)
    val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      val securityLevel = keyInfo.getSecurityLevel()
      securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
        securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
    } else {
      @Suppress("DEPRECATION") keyInfo.isInsideSecureHardware()
    }
  }
}
