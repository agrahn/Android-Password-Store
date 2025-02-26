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
import android.util.Base64
import app.passwordstore.Application
import app.passwordstore.util.extensions.unsafeLazy
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

private const val KEYSTORE_ALIAS = "AESKey"
private const val KEYSTORE_ALIAS_WITH_AUTHENTICATION = "AESKeyWithAuth"
private const val PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore"
private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val IV_SIZE = 12 // 12 bytes (96 bits) length of initialisation vector for GCM mode

private val androidKeystore: KeyStore by unsafeLazy {
  KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE).apply { load(null) }
}

object AESEncryption {

  fun isHardwareBacked(withAuthentication: Boolean = false): Boolean {
    initKeyStore(withAuthentication)
    val key = getSecretKey(withAuthentication)
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

  private val context: Context
    get() = Application.instance.applicationContext

  private val isStrongBoxSupported by unsafeLazy {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
      context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    else false
  }

  // Initialize the KeyStore and generate an AES key if it doesn't exist
  private fun initKeyStore(requireAuthentication: Boolean) {
    val keyStoreAlias =
      if (requireAuthentication) KEYSTORE_ALIAS_WITH_AUTHENTICATION else KEYSTORE_ALIAS
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
            if (requireAuthentication) {
              setUserAuthenticationRequired(true)
              if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                setUserAuthenticationParameters(30, KeyProperties.AUTH_DEVICE_CREDENTIAL)
              } else {
                @Suppress("DEPRECATION") setUserAuthenticationValidityDurationSeconds(30)
              }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
              setIsStrongBoxBacked(isStrongBoxSupported)
            }
            build()
          }
      keyGenerator.init(keyGenParameterSpec)
      keyGenerator.generateKey()
    }
  }

  // Retrieve the AES key from the KeyStore
  private fun getSecretKey(requireAuthentication: Boolean): SecretKey {
    val keyStoreAlias =
      if (requireAuthentication) KEYSTORE_ALIAS_WITH_AUTHENTICATION else KEYSTORE_ALIAS
    return androidKeystore.getKey(keyStoreAlias, null) as SecretKey
  }

  private fun CharArray.toByteArray(): ByteArray {
    val byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(this))
    val byteArray = ByteArray(byteBuffer.remaining())
    byteBuffer.get(byteArray)
    return byteArray
  }

  private fun ByteArray.toCharArray(): CharArray {
    val charBuffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(this))
    val charArray = CharArray(charBuffer.remaining())
    charBuffer.get(charArray)
    return charArray
  }

  private fun ByteArray.encodeToBase64CharArray(): CharArray {
    val encodedBytes = Base64.encode(this, Base64.NO_WRAP)
    return CharArray(encodedBytes.size) { i -> Char(encodedBytes[i].toUShort()) }
  }

  private fun CharArray.decodeFromBase64ToByteArray(): ByteArray {
    val byteArray = ByteArray(this.size) { i -> this[i].code.toByte() }
    return Base64.decode(byteArray, Base64.NO_WRAP)
  }

  // Encrypt a CharArray using the AES key from the KeyStore and Base64-encode the result
  fun encrypt(data: CharArray, requireAuthentication: Boolean = false): CharArray? {
    if (!isHardwareBacked(requireAuthentication)) return null
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(requireAuthentication))
    return (cipher.iv + cipher.doFinal(data.toByteArray())).encodeToBase64CharArray()
  }

  // Decrypt a CharArray with Base64 encoded AES-encrypted data
  fun decrypt(encryptedBase64Data: CharArray?, requireAuthentication: Boolean = false): CharArray? {
    if (encryptedBase64Data == null) return null
    if (!isHardwareBacked(requireAuthentication)) return null
    val ivAndEncryptedData = encryptedBase64Data.decodeFromBase64ToByteArray()
    val iv = ivAndEncryptedData.copyOfRange(0, IV_SIZE)
    val encryptedBytes = ivAndEncryptedData.copyOfRange(IV_SIZE, ivAndEncryptedData.size)
    val cipher = Cipher.getInstance(TRANSFORMATION)
    val spec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.DECRYPT_MODE, getSecretKey(requireAuthentication), spec)
    val decryptedBytes = cipher.doFinal(encryptedBytes)
    return decryptedBytes.toCharArray()
  }

  fun deleteKey(withAuthentication: Boolean = false) {
    val keyStoreAlias =
      if (withAuthentication) KEYSTORE_ALIAS_WITH_AUTHENTICATION else KEYSTORE_ALIAS
    if (androidKeystore.containsAlias(keyStoreAlias)) androidKeystore.deleteEntry(keyStoreAlias)
  }
}
