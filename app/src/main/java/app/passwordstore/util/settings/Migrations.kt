/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
@file:Suppress("DEPRECATION")

package app.passwordstore.util.settings

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import app.passwordstore.Application
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.unsafeLazy
import com.github.michaelbull.result.get
import com.github.michaelbull.result.runCatching
import java.io.File
import java.net.URI
import java.security.KeyStore
import logcat.LogPriority.ERROR
import logcat.LogPriority.INFO
import logcat.logcat

private const val TAG = "Migrations"

fun runMigrations(
  filesDirPath: String,
  sharedPrefs: SharedPreferences,
  gitSettings: GitSettings,
  context: Context = Application.instance.applicationContext,
  runTest: Boolean = false,
) {
  migrateToGitUrlBasedConfig(sharedPrefs, gitSettings)
  migrateToHideAll(sharedPrefs)
  migrateToClipboardHistory(sharedPrefs)
  migrateToDiceware(sharedPrefs)
  removeExternalStorageProperties(sharedPrefs)
  removeCurrentBranchValue(sharedPrefs)
  removePersistentCredentialCache(sharedPrefs, gitSettings, context, runTest)
  if (!runTest) moveToPasswordGeneratorPrefs(sharedPrefs, context)
  deleteKeystoreWrappedEd25519Key(sharedPrefs, context)
  migrateToFastUnlockOptions(sharedPrefs)
}

private fun deleteKeystoreWrappedEd25519Key(sharedPrefs: SharedPreferences, context: Context) {
  val gitRemoteKeyType = sharedPrefs.getString(PreferenceKeys.GIT_REMOTE_KEY_TYPE)
  if (gitRemoteKeyType == "keystore_wrapped_ed25519") {
    logcat(TAG, INFO) {
      "Deleting APS-generated Ed25519 SSH key pair. Please, generate a new RSA or ECDSA key pair and transfer the public key to the Git server."
    }

    val PROVIDER_ANDROID_KEY_STORE = "AndroidKeyStore"
    val KEYSTORE_ALIAS = "sshkey"
    val androidKeystore: KeyStore by unsafeLazy {
      KeyStore.getInstance(PROVIDER_ANDROID_KEY_STORE).apply { load(null) }
    }
    androidKeystore.deleteEntry(KEYSTORE_ALIAS)

    val ANDROIDX_SECURITY_KEYSET_PREF_NAME = "androidx_sshkey_keyset_prefs"
    context.getSharedPreferences(ANDROIDX_SECURITY_KEYSET_PREF_NAME, Context.MODE_PRIVATE).edit {
      clear()
    }

    val privateKeyFile = File(context.filesDir, ".ssh_key")
    if (privateKeyFile.isFile) {
      privateKeyFile.delete()
    }
    val publicKeyFile = File(context.filesDir, ".ssh_key.pub")
    if (publicKeyFile.isFile) {
      publicKeyFile.delete()
    }

    sharedPrefs.edit { remove(PreferenceKeys.GIT_REMOTE_KEY_TYPE) }
  }
}

private fun removePersistentCredentialCache(
  sharedPrefs: SharedPreferences,
  gitSettings: GitSettings,
  context: Context,
  runTest: Boolean,
) {
  val gitPrefs = if (runTest) sharedPrefs else createEncryptedPreferences(context, "git_operation")
  val proxyPrefs = if (runTest) sharedPrefs else createEncryptedPreferences(context, "http_proxy")

  if (sharedPrefs.contains(PreferenceKeys.CLEAR_PASSPHRASE_CACHE)) {
    logcat(TAG, INFO) { "Deleting now unused persistent PGP passphrase cache preference" }
    sharedPrefs.edit { remove(PreferenceKeys.CLEAR_PASSPHRASE_CACHE) }
  }
  if (gitPrefs.contains(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE)) {
    logcat(TAG, INFO) { "Wiping cached credential" }
    gitPrefs.edit { remove(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE) }
  }
  if (gitPrefs.contains(PreferenceKeys.HTTPS_PASSWORD)) {
    logcat(TAG, INFO) { "Wiping cached credential" }
    gitPrefs.edit { remove(PreferenceKeys.HTTPS_PASSWORD) }
  }
  var value = proxyPrefs.getString(PreferenceKeys.PROXY_HOST, null)
  value?.let {
    logcat(TAG, INFO) { "Moving PreferenceKeys.PROXY_HOST to SharedPreferences" }
    proxyPrefs.edit { remove(PreferenceKeys.PROXY_HOST) }
    sharedPrefs.edit { putString(PreferenceKeys.PROXY_HOST, it) }
  }
  value = proxyPrefs.getString(PreferenceKeys.PROXY_PORT, null)
  value?.let {
    logcat(TAG, INFO) { "Moving PreferenceKeys.PROXY_PORT to SharedPreferences" }
    proxyPrefs.edit { remove(PreferenceKeys.PROXY_PORT) }
    sharedPrefs.edit { putString(PreferenceKeys.PROXY_PORT, it) }
  }
  value = proxyPrefs.getString(PreferenceKeys.PROXY_USERNAME, null)
  value?.let {
    logcat(TAG, INFO) { "Moving PreferenceKeys.PROXY_USERNAME to SharedPreferences" }
    proxyPrefs.edit { remove(PreferenceKeys.PROXY_USERNAME) }
    sharedPrefs.edit { putString(PreferenceKeys.PROXY_USERNAME, it) }
  }
  val password =
    proxyPrefs.getString(PreferenceKeys.PROXY_PASSWORD, null)?.toCharArray()
      ?: sharedPrefs.getString(PreferenceKeys.PROXY_PASSWORD, null)?.toCharArray()
  password?.let {
    logcat(TAG, INFO) { "Moving PreferenceKeys.PROXY_PASSWORD to GitSecrets" }
    proxyPrefs.edit { remove(PreferenceKeys.PROXY_PASSWORD) }
    sharedPrefs.edit { remove(PreferenceKeys.PROXY_PASSWORD) }
    gitSettings.proxyPassword = it
  }
}

private fun moveToPasswordGeneratorPrefs(sharedPrefs: SharedPreferences, context: Context) {
  // Old, encrypted preferences
  val pwgenPrefs = createEncryptedPreferences(context, "pwgen_preferences")
  // New destination
  val passwordGeneratorPrefs =
    context.getSharedPreferences("PasswordGenerator", Context.MODE_PRIVATE)

  val separator =
    pwgenPrefs.getString(PreferenceKeys.DICEWARE_SEPARATOR, null)
      ?: sharedPrefs.getString(PreferenceKeys.DICEWARE_SEPARATOR, null)
  separator?.let { v ->
    logcat(TAG, INFO) {
      "Moving PreferenceKeys.DICEWARE_SEPARATOR to  PasswordGenerator preferences"
    }
    pwgenPrefs.edit { remove(PreferenceKeys.DICEWARE_SEPARATOR) }
    sharedPrefs.edit { remove(PreferenceKeys.DICEWARE_SEPARATOR) }

    passwordGeneratorPrefs.edit {
      putString(
        PreferenceKeys.DICEWARE_SEPARATOR,
        AESEncryption.encrypt(v.toCharArray(), keyType = KeyType.PERSISTENT)?.let { String(it) },
      )
    }
  }

  var dwLength = pwgenPrefs.getInt(PreferenceKeys.DICEWARE_LENGTH, -1000)
  if (dwLength < 0) dwLength = sharedPrefs.getInt(PreferenceKeys.DICEWARE_LENGTH, -1000)
  if (dwLength >= 0) {
    pwgenPrefs.edit { remove(PreferenceKeys.DICEWARE_LENGTH) }
    sharedPrefs.edit { remove(PreferenceKeys.DICEWARE_LENGTH) }
    logcat(TAG, INFO) { "Moving PreferenceKeys.DICEWARE_LENGTH to PasswordGenerator preferences" }
    passwordGeneratorPrefs.edit {
      putString(
        PreferenceKeys.DICEWARE_LENGTH,
        AESEncryption.encrypt(dwLength.toString().toCharArray(), keyType = KeyType.PERSISTENT)
          ?.let { String(it) },
      )
    }
  }
}

private fun removeCurrentBranchValue(sharedPrefs: SharedPreferences) {
  if (!sharedPrefs.contains(PreferenceKeys.GIT_BRANCH_NAME)) {
    return
  }
  logcat(TAG, INFO) { "Deleting now unused branch name preference" }
  sharedPrefs.edit { remove(PreferenceKeys.GIT_BRANCH_NAME) }
}

private fun migrateToGitUrlBasedConfig(sharedPrefs: SharedPreferences, gitSettings: GitSettings) {
  val serverHostname = sharedPrefs.getString(PreferenceKeys.GIT_REMOTE_SERVER) ?: return
  logcat(TAG, INFO) { "Migrating to URL-based Git config" }
  val serverPort = sharedPrefs.getString(PreferenceKeys.GIT_REMOTE_PORT) ?: ""
  val serverUser = sharedPrefs.getString(PreferenceKeys.GIT_REMOTE_USERNAME) ?: ""
  val serverPath = sharedPrefs.getString(PreferenceKeys.GIT_REMOTE_LOCATION) ?: ""
  val protocol = Protocol.fromString(sharedPrefs.getString(PreferenceKeys.GIT_REMOTE_PROTOCOL))
  // Whether we need the leading ssh:// depends on the use of a custom port.
  val hostnamePart = serverHostname.removePrefix("ssh://")
  val url =
    when (protocol) {
      Protocol.Ssh -> {
        val userPart = if (serverUser.isEmpty()) "" else "${serverUser.trimEnd('@')}@"
        val portPart = if (serverPort == "22" || serverPort.isEmpty()) "" else ":$serverPort"
        if (portPart.isEmpty()) {
          "$userPart$hostnamePart:$serverPath"
        } else {
          // Only absolute paths are supported with custom ports.
          if (!serverPath.startsWith('/')) {
            null
          } else {
            // We have to specify the ssh scheme as this is the only way to pass a custom
            // port.
            "ssh://$userPart$hostnamePart$portPart$serverPath"
          }
        }
      }
      Protocol.Https -> {
        val portPart = if (serverPort == "443" || serverPort.isEmpty()) "" else ":$serverPort"
        val pathPart = serverPath.trimStart('/', ':')
        val urlWithFreeEntryScheme = "$hostnamePart$portPart/$pathPart"
        val url =
          when {
            urlWithFreeEntryScheme.startsWith("https://") -> urlWithFreeEntryScheme
            urlWithFreeEntryScheme.startsWith("http://") ->
              urlWithFreeEntryScheme.replaceFirst("http", "https")
            else -> "https://$urlWithFreeEntryScheme"
          }
        runCatching { if (URI(url).rawAuthority != null) url else null }.get()
      }
    }

  sharedPrefs.edit {
    remove(PreferenceKeys.GIT_REMOTE_LOCATION)
    remove(PreferenceKeys.GIT_REMOTE_PORT)
    remove(PreferenceKeys.GIT_REMOTE_SERVER)
    remove(PreferenceKeys.GIT_REMOTE_USERNAME)
    remove(PreferenceKeys.GIT_REMOTE_PROTOCOL)
  }
  if (
    url == null ||
      gitSettings.updateConnectionSettingsIfValid(
        newAuthMode = gitSettings.authMode,
        newUrl = url,
      ) != GitSettings.UpdateConnectionSettingsResult.Valid
  ) {
    logcat(TAG, ERROR) { "Failed to migrate to URL-based Git config, generated URL is invalid." }
  }
}

private fun migrateToHideAll(sharedPrefs: SharedPreferences) {
  sharedPrefs.all[PreferenceKeys.SHOW_HIDDEN_FOLDERS] ?: return
  val isHidden = sharedPrefs.getBoolean(PreferenceKeys.SHOW_HIDDEN_FOLDERS, false)
  sharedPrefs.edit {
    remove(PreferenceKeys.SHOW_HIDDEN_FOLDERS)
    putBoolean(PreferenceKeys.SHOW_HIDDEN_CONTENTS, isHidden)
  }
}

private fun migrateToClipboardHistory(sharedPrefs: SharedPreferences) {
  if (sharedPrefs.contains(PreferenceKeys.CLEAR_CLIPBOARD_20X)) {
    sharedPrefs.edit {
      putBoolean(
        PreferenceKeys.CLEAR_CLIPBOARD_HISTORY,
        sharedPrefs.getBoolean(PreferenceKeys.CLEAR_CLIPBOARD_20X, false),
      )
      remove(PreferenceKeys.CLEAR_CLIPBOARD_20X)
    }
  }
}

private fun migrateToDiceware(sharedPrefs: SharedPreferences) {
  if (sharedPrefs.contains(PreferenceKeys.PREF_KEY_PWGEN_TYPE)) {
    sharedPrefs.edit {
      if (sharedPrefs.getString(PreferenceKeys.PREF_KEY_PWGEN_TYPE) == "xkpasswd") {
        putString(PreferenceKeys.PREF_KEY_PWGEN_TYPE, "diceware")
      }
    }
  }
}

private fun removeExternalStorageProperties(prefs: SharedPreferences) {
  prefs.edit {
    if (prefs.contains(PreferenceKeys.GIT_EXTERNAL)) {
      if (prefs.getBoolean(PreferenceKeys.GIT_EXTERNAL, false)) {
        putBoolean(PreferenceKeys.GIT_EXTERNAL_MIGRATED, true)
      }
      remove(PreferenceKeys.GIT_EXTERNAL)
    }
    if (prefs.contains(PreferenceKeys.GIT_EXTERNAL_REPO)) {
      remove(PreferenceKeys.GIT_EXTERNAL_REPO)
    }
  }
}

private fun createEncryptedPreferences(context: Context, fileName: String): SharedPreferences {
  val masterKeyAlias =
    MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
  return EncryptedSharedPreferences.create(
    context,
    fileName,
    masterKeyAlias,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
  )
}

private fun migrateToFastUnlockOptions(sharedPrefs: SharedPreferences) {
  sharedPrefs.edit {
    if (sharedPrefs.getBoolean(PreferenceKeys.UNLOCK_PASSWORDS_WITH_PIN, false))
      putString(PreferenceKeys.PREF_FAST_UNLOCK_OPTION, "fingerprint")
    remove(PreferenceKeys.UNLOCK_PASSWORDS_WITH_PIN)
  }
}
