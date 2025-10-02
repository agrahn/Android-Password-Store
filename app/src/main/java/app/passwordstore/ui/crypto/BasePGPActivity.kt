/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.crypto

import android.content.ClipData
import android.content.ClipDescription
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.view.WindowManager
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.annotation.CallSuper
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import androidx.fragment.app.setFragmentResultListener
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.data.crypto.CryptoRepository
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.injection.prefs.PGPPassphrases
import app.passwordstore.injection.prefs.SettingsPreferences
import app.passwordstore.ui.dialogs.PasswordDialog
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.util.auth.BiometricAuthenticator
import app.passwordstore.util.auth.BiometricAuthenticator.Result as BiometricResult
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import app.passwordstore.util.extensions.clipboard
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.isInsideRepository
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.settings.Constants
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import java.io.File
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.asLog
import logcat.logcat

@Suppress("Registered")
@AndroidEntryPoint
open class BasePGPActivity : AppCompatActivity() {

  /** Full path to the repository */
  val repoPath by unsafeLazy {
    requireNotNull(intent.getStringExtra("REPO_PATH")) { "REPO_PATH is missing" }
  }

  /** Full path to the password file being worked on */
  val fullPath by unsafeLazy {
    requireNotNull(intent.getStringExtra("FILE_PATH")) { "FILE_PATH is missing" }
  }

  /**
   * Name of the password file
   *
   * Converts personal/auth.foo.org/john_doe@example.org.gpg to john_doe.example.org
   */
  val name: String by unsafeLazy { File(fullPath).nameWithoutExtension }

  /* Counter for the user's decryption (with passphrase) attempts */
  private var retries = 0

  var secondsOnPause = 0L // seconds since Epoch upon pause
  var timeout = 0L

  @Inject lateinit var pgpKeyManager: PGPKeyManager

  /** Action to invoke if [keyImportAction] succeeds. */
  private var onKeyImport: (() -> Unit)? = null
  private val keyImportAction =
    registerForActivityResult(StartActivityForResult()) {
      if (it.resultCode == RESULT_OK) {
        onKeyImport?.invoke()
        onKeyImport = null
      } else {
        finish()
      }
    }

  /** [SharedPreferences] instance used by subclasses to persist settings */
  @SettingsPreferences @Inject lateinit var settings: SharedPreferences

  /**
   * [SharedPreferences] instance used by subclasses for persistent caching of encrypted passphrases
   */
  @PGPPassphrases @Inject lateinit var persistentPassphrases: SharedPreferences

  @Inject lateinit var repository: CryptoRepository
  @Inject lateinit var dispatcherProvider: DispatcherProvider

  /**
   * [onCreate] sets the window up with the right flags to prevent auth leaks through screenshots or
   * recent apps screen.
   */
  @CallSuper
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
  }

  override fun onResume() {
    val secondsNow = Instant.now().getEpochSecond()
    if (timeout > 0 && (secondsNow - secondsOnPause) > timeout) finish()
    super.onResume()
  }

  override fun onPause() {
    timeout =
      settings.getString(PreferenceKeys.GENERAL_SHOW_TIME)?.toLongOrNull()
        ?: Constants.DEFAULT_DECRYPTION_TIMEOUT.toLong()

    if (timeout > 0) secondsOnPause = Instant.now().getEpochSecond()
    super.onPause()
  }

  /* Function to execute [onKeysExist] only if there are PGP keys imported in the app's key manager.
   */
  protected fun requireKeysExist(onKeysExist: () -> Unit) {
    lifecycleScope.launch {
      val hasKeys = repository.hasKeys()
      if (!hasKeys) {
        withContext(dispatcherProvider.main()) {
          MaterialAlertDialogBuilder(this@BasePGPActivity)
            .setTitle(resources.getString(R.string.no_keys_imported_dialog_title))
            .setMessage(resources.getString(R.string.no_keys_imported_dialog_message))
            .setPositiveButton(
              resources.getString(R.string.no_keys_imported_dialog_open_key_manager)
            ) { _, _ ->
              onKeyImport = onKeysExist
              keyImportAction.launch(Intent(this@BasePGPActivity, PGPKeyListActivity::class.java))
            }
            .show()
        }
      } else {
        onKeysExist()
      }
    }
  }

  /**
   * Copies a provided [password] string to the clipboard. This wraps [copyTextToClipboard] to
   * optionally hide the default [Snackbar] and starts off a timer to clear the clipboard.
   */
  protected fun copyPasswordToClipboard(
    password: CharArray?,
    isSensitive: Boolean = true,
    showSnackbar: Boolean = true,
  ): ScheduledExecutorService? {
    copyTextToClipboard(password, isSensitive = isSensitive, showSnackbar)
    password?.wipe()

    val clearAfter = settings.getString(PreferenceKeys.GENERAL_SHOW_TIME)?.toIntOrNull() ?: 45
    val deepClear = settings.getBoolean(PreferenceKeys.CLEAR_CLIPBOARD_HISTORY, false)
    val clipboard = clipboard

    if (isSensitive && clearAfter != 0 && clipboard != null) {
      val timer = Executors.newSingleThreadScheduledExecutor()
      timer.schedule(
        {
          logcat { "Clearing the clipboard" }
          var randomNum = (100000000000000000..999999999999999999).random().toString().toCharArray()
          copyTextToClipboard(randomNum, isSensitive = false, showSnackbar = false)
          if (deepClear) {
            repeat(CLIPBOARD_CLEAR_COUNT) {
              randomNum = (100000000000000000..999999999999999999).random().toString().toCharArray()
              copyTextToClipboard(randomNum, isSensitive = false, showSnackbar = false)
            }
          }
        },
        clearAfter.toLong(),
        TimeUnit.SECONDS,
      )
      return timer
    }

    return null
  }

  /**
   * Copies provided [text] to the clipboard. Shows a [Snackbar] which can be disabled by passing
   * [showSnackbar] as false.
   */
  protected fun copyTextToClipboard(
    text: CharArray?,
    isSensitive: Boolean = true,
    showSnackbar: Boolean = true,
    @StringRes snackbarTextRes: Int = R.string.clipboard_copied_text,
  ) {
    val clipboard = clipboard ?: return
    val clip = ClipData.newPlainText((100000..999999).random().toString(), text?.let { String(it) })
    clip.description.extras =
      PersistableBundle().apply {
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.S_V2)
          putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, isSensitive)
        else putBoolean("android.content.extra.IS_SENSITIVE", isSensitive)
      }
    clipboard.setPrimaryClip(clip)
    if (showSnackbar && Build.VERSION.SDK_INT < Build.VERSION_CODES.S_V2) {
      snackbar(message = resources.getString(snackbarTextRes))
    }
  }

  /**
   * Get a list of available [PGPIdentifier]s for the current password repository. This method
   * throws when no identifiers were able to be parsed. If this method returns null, it means that
   * an invalid identifier was encountered and further execution must stop to let the user correct
   * the problem.
   */
  protected fun getPGPIdentifiers(subDir: String): List<PGPIdentifier>? {
    PasswordRepository.gpgidChecked = false
    var shortIdCount = 0
    var invalidIdCount = 0
    val repoRoot = PasswordRepository.getRepositoryDirectory()
    val gpgIdentifierFile = File(repoRoot, subDir).findTillRoot(".gpg-id", repoRoot)
    if (gpgIdentifierFile == null) { // no file found
      snackbar(message = resources.getString(R.string.missing_gpg_id))
      return null
    }
    val gpgIdentifiers =
      gpgIdentifierFile
        .readLines()
        .filter { it.isNotBlank() }
        .map { line ->
          if (line == "gpg-id") {
            null
          } else if (line.removePrefix("0x").matches("[a-fA-F0-9]{8}".toRegex())) {
            // Short key IDs are not accepted
            shortIdCount++
            null
          } else {
            val id = PGPIdentifier.fromString(line)
            if (id == null || !repository.hasKey(id)) {
              invalidIdCount++
              persistentPassphrases.edit { remove(id.toString()) }
              null
            } else id
          }
        }
        .filterIsInstance<PGPIdentifier>()
    if (gpgIdentifiers.isNullOrEmpty()) {
      if (shortIdCount == 0 && invalidIdCount == 0) {
        snackbar(message = resources.getString(R.string.empty_gpg_id))
      } else if (shortIdCount > 0 && invalidIdCount == 0) {
        snackbar(message = resources.getString(R.string.short_gpg_id))
      } else {
        snackbar(message = resources.getString(R.string.invalid_gpg_id))
      }
      return null
    }
    PasswordRepository.gpgidChecked = true
    return gpgIdentifiers
  }

  private fun getEmailsFromIdentifiers(identifiers: List<PGPIdentifier>): String? {
    val emails = identifiers.map { repository.getEmailFromKeyId(it) }.filter { it != null }
    if (emails.isEmpty()) return null
    val label = if (emails.size > 1) R.string.pgp_id_label_plural else R.string.pgp_id_label
    return "${resources.getString(label)} ${emails.joinToString(", ")}"
  }

  @Suppress("ReturnCount")
  private fun File.findTillRoot(fileName: String, rootPath: File): File? {
    val gpgFile = File(this, fileName)
    require(gpgFile.isInsideRepository()) { "Trying to access target outside the repository" }
    if (gpgFile.exists()) return gpgFile

    if (this.absolutePath == rootPath.absolutePath) {
      return null
    }
    val parent = parentFile
    parent?.let {
      require(it.isInsideRepository()) { "Trying to access target outside the repository" }
    }
    return if (parent != null && parent.exists()) {
      parent.findTillRoot(fileName, rootPath)
    } else {
      null
    }
  }

  /** Opens the dialog for passphrase input and then forwards it to the decryption method. */
  private suspend fun askPassphrase(isError: Boolean, identifiers: List<PGPIdentifier>) {
    if (++retries > MAX_RETRIES) finish()

    val dialog =
      PasswordDialog.newInstance(getEmailsFromIdentifiers(identifiers), cacheOptionVisible = true)
    if (isError) dialog.setError()
    dialog.show(supportFragmentManager, "PASSWORD_DIALOG")
    dialog.setFragmentResultListener(PasswordDialog.PASSWORD_RESULT_KEY) { key, bundle ->
      if (key == PasswordDialog.PASSWORD_RESULT_KEY) {
        val passphrase =
          requireNotNull(bundle.getCharArray(PasswordDialog.PASSWORD_PHRASE_KEY)) {
            "returned passphrase is null"
          }
        var cacheEnabled = bundle.getBoolean(PasswordDialog.PASSWORD_CACHE_KEY)
        lifecycleScope.launch(dispatcherProvider.main()) {
          decryptWithPassphrase(mapOf("" to passphrase), identifiers) { id -> // onSuccess
            runCatching {
                // update temporary passphrase cache
                val isHardwareBacked = AESEncryption.isHardwareBacked()
                val encryptedPassphrase = AESEncryption.encrypt(passphrase)
                if (isHardwareBacked && cacheEnabled && encryptedPassphrase != null)
                  cachedPassphrases.put(id, encryptedPassphrase)
                settings.edit {
                  putBoolean(
                    PreferenceKeys.CACHE_PASSPHRASE,
                    isHardwareBacked && cacheEnabled && encryptedPassphrase != null,
                  )
                }

                // update persistent passphrase cache
                var cipher = // cipher for encrypting the passphrase with biometrics
                  if (
                    AESEncryption.isHardwareBacked(KeyType.PERSISTENT_WITH_AUTHENTICATION) &&
                      BiometricAuthenticator.canAuthenticate(this@BasePGPActivity)
                  ) {
                    AESEncryption.getCipher(KeyType.PERSISTENT_WITH_AUTHENTICATION)
                      ?: run {
                        if (
                          settings.getString(PreferenceKeys.PREF_FAST_UNLOCK_OPTION, "disabled") ==
                            "fingerprint"
                        )
                          persistentPassphrases.edit { clear() }
                        // recover from invalidated AES key
                        AESEncryption.deleteKey(KeyType.PERSISTENT_WITH_AUTHENTICATION)
                        AESEncryption.getCipher(KeyType.PERSISTENT_WITH_AUTHENTICATION)
                      }
                  } else null

                if (
                  settings.getString(PreferenceKeys.PREF_FAST_UNLOCK_OPTION, "disabled") ==
                    "fingerprint" && cipher != null
                ) {
                  BiometricAuthenticator.authenticate(
                    this@BasePGPActivity,
                    dialogDescriptionRes =
                      R.string.biometric_prompt_description_persistently_cache_password,
                    cipher = cipher,
                  ) { result ->
                    if (result is BiometricResult.Success) {
                      persistentPassphrases.edit {
                        putString(
                          id,
                          AESEncryption.encrypt(
                              passphrase,
                              keyType = KeyType.PERSISTENT_WITH_AUTHENTICATION,
                              cipher = result.cryptoObject?.cipher,
                            )
                            ?.concatToString(),
                        )
                      }
                    }
                  }
                } else if (
                  settings.getString(PreferenceKeys.PREF_FAST_UNLOCK_OPTION, "disabled") == "PIN" &&
                    AESEncryption.isHardwareBacked(KeyType.PERSISTENT)
                ) {
                  /* Ask user for setting a PIN if not yet existing, encrypt and store it on the
                   * device, then update passphrase in cache */
                  if (persistentPassphrases.getString("unlock_pin", null) == null) {
                    val pinDialog =
                      PinDialog.newInstance(
                        title = resources.getString(R.string.pin_new_entry_title),
                        description = resources.getString(R.string.pin_new_entry_description),
                      )
                    pinDialog.show(supportFragmentManager, "PIN_DIALOG")
                    pinDialog.setFragmentResultListener(PinDialog.PIN_RESULT_KEY) { key, bundle ->
                      if (key == PinDialog.PIN_RESULT_KEY) {
                        val pin =
                          requireNotNull(bundle.getCharArray(PinDialog.PIN_KEY)) {
                            "returned PIN is null"
                          }
                        if (pin.size >= 4) {
                          persistentPassphrases.edit {
                            putString(
                              "unlock_pin", // reset and prepend PIN attempt counter
                              AESEncryption.encrypt(
                                  charArrayOf('0', ':') + pin,
                                  keyType = KeyType.PERSISTENT,
                                )
                                ?.concatToString(),
                            )
                            putString(
                              id,
                              AESEncryption.encrypt(passphrase, keyType = KeyType.PERSISTENT)
                                ?.concatToString(),
                            )
                          }
                        }
                      }
                    }
                  } else {
                    persistentPassphrases.edit {
                      putString(
                        id,
                        AESEncryption.encrypt(passphrase, keyType = KeyType.PERSISTENT)
                          ?.concatToString(),
                      )
                    }
                  }
                }
              }
              .onFailure { e -> logcat { e.asLog() } }
          }
        }
      }
    }
  }

  /* Find persistent PGP passphrases with matching key ID, unlock the first one
   * with biometrics or after PIN verification */
  protected fun getPersistentAndDecrypt(identifiers: List<PGPIdentifier>) {
    // Detect AES key invalidation due to enrollment of a new fingerprint and emit warning
    if (
      BiometricAuthenticator.canAuthenticate(this@BasePGPActivity) &&
        AESEncryption.getCipher(KeyType.PERSISTENT_WITH_AUTHENTICATION) == null
    ) {
      MaterialAlertDialogBuilder(this@BasePGPActivity)
        .setTitle(resources.getString(R.string.aes_key_invalidated_dialog_title))
        .setMessage(resources.getString(R.string.aes_key_invalidated_dialog_message))
        .setIcon(R.drawable.ic_warning_red_24dp)
        .setPositiveButton(getString(R.string.dialog_ok)) { _, _ -> decrypt(identifiers) }
        .setCancelable(false)
        .show()
      return
    }
    val persistentIds =
      identifiers.map { it.toString() }.filter { persistentPassphrases.contains(it) }
    val pinEncrypted = persistentPassphrases.getString("unlock_pin", null)?.toCharArray()
    if (
      !persistentIds.none() &&
        identifiers.map { it.toString() }.filter { cachedPassphrases.containsKey(it) }.none() &&
        AESEncryption.isHardwareBacked(KeyType.PERSISTENT_WITH_AUTHENTICATION) &&
        settings.getString(PreferenceKeys.PREF_FAST_UNLOCK_OPTION, "disabled") == "fingerprint" &&
        BiometricAuthenticator.canAuthenticate(this@BasePGPActivity)
    ) {
      val id = persistentIds[0]
      val passEncrypted = persistentPassphrases.getString(id, null)?.toCharArray()
      val cipher = AESEncryption.getCipher(KeyType.PERSISTENT_WITH_AUTHENTICATION, passEncrypted)
      BiometricAuthenticator.authenticate(
        this@BasePGPActivity,
        dialogDescriptionRes = R.string.biometric_prompt_description_unlock_entry,
        cipher = cipher,
      ) { result ->
        if (result is BiometricResult.Success) {
          val pass =
            // re-encrypt passphrase without biometrics for use until screen-off
            AESEncryption.encrypt(
              // decrypt persistently cached passphrase with biometrics
              AESEncryption.decrypt(
                passEncrypted,
                keyType = KeyType.PERSISTENT_WITH_AUTHENTICATION,
                cipher = result.cryptoObject?.cipher,
              )
            )
          if (pass != null) cachedPassphrases.put(id, pass)
        }
        if (result !is BiometricResult.Retry) decrypt(identifiers)
      }
    } else if (
      !persistentIds.none() &&
        identifiers.map { it.toString() }.filter { cachedPassphrases.containsKey(it) }.none() &&
        AESEncryption.isHardwareBacked(KeyType.PERSISTENT) &&
        settings.getString(PreferenceKeys.PREF_FAST_UNLOCK_OPTION, "disabled") == "PIN" &&
        pinEncrypted != null
    ) {
      verifyPin(pinEncrypted, persistentIds, identifiers)
    } else decrypt(identifiers)
  }

  /* Asks for and verifies the user PIN for unlocking a store entry. */
  private fun verifyPin(
    pinEncrypted: CharArray,
    ids: List<String>,
    identifiers: List<PGPIdentifier>,
    isError: Boolean = false,
  ) {
    val pinDialog =
      PinDialog.newInstance(
        title = resources.getString(R.string.pin_entry_title),
        description = resources.getString(R.string.pin_entry_description),
      )
    if (isError) pinDialog.setError()
    pinDialog.show(supportFragmentManager, "PIN_DIALOG")
    pinDialog.setFragmentResultListener(PinDialog.PIN_RESULT_KEY) { key, bundle ->
      if (key == PinDialog.PIN_RESULT_KEY) {
        val pin = requireNotNull(bundle.getCharArray(PinDialog.PIN_KEY)) { "returned PIN is null" }
        var (pinRetries, cachedPin) =
          AESEncryption.decrypt(pinEncrypted, keyType = KeyType.PERSISTENT)?.let { cached ->
            if (cached[1] == ':') {
              Pair(cached[0].digitToInt(), cached.filterIndexed { i, _ -> i > 1 }.toCharArray())
            } else {
              // fix PIN cache that does not have an attempt count prepended (old app version)
              persistentPassphrases.edit {
                putString(
                  "unlock_pin",
                  AESEncryption.encrypt(
                      charArrayOf('0', ':') + cached,
                      keyType = KeyType.PERSISTENT,
                    )
                    ?.concatToString(),
                )
              }
              Pair(0, cached)
            }
          } ?: Pair(MAX_RETRIES, null)
        if (cachedPin?.let { it.contentEquals(pin) } ?: false) { // PIN verifies successfully
          persistentPassphrases.edit {
            putString(
              "unlock_pin", // reset to zero and prepend attempt counter
              AESEncryption.encrypt(charArrayOf('0', ':') + pin, keyType = KeyType.PERSISTENT)
                ?.concatToString(),
            )
          }
          ids.forEach { id ->
            val passEncrypted = persistentPassphrases.getString(id, null)?.toCharArray()
            val pass =
              // re-encrypt passphrase for use until screen-off
              AESEncryption.encrypt(
                // decrypt persistently cached passphrase
                AESEncryption.decrypt(passEncrypted, keyType = KeyType.PERSISTENT)
              )
            pass?.let { cachedPassphrases.put(id, it) }
          }
          decrypt(identifiers)
        } else if (
          cachedPin != null && ++pinRetries < MAX_RETRIES
        ) { // PIN verification failed, try again
          val pinEncryptedUpdate =
            AESEncryption.encrypt(
              charArrayOf(pinRetries.digitToChar(), ':') + cachedPin,
              keyType = KeyType.PERSISTENT,
            )
          pinEncryptedUpdate?.let { // update PIN cache with incremented attempt counter
            persistentPassphrases.edit {
              putString("unlock_pin", pinEncryptedUpdate.concatToString())
            }
            verifyPin(pinEncryptedUpdate, ids, identifiers, isError = true)
          } ?: throw NullPointerException()
        } else { // PIN verification failed, do not try again
          persistentPassphrases.edit { clear() } // reset PIN to prevent bruteforcing
          decrypt(identifiers) // decrypt with passphrase verification
        }
      }
    }
  }

  protected fun decrypt(identifiers: List<PGPIdentifier>, isError: Boolean = false) {
    val passphrases =
      cachedPassphrases.filterKeys { identifiers.map { it.toString() }.contains(it) }
    lifecycleScope.launch(dispatcherProvider.main()) {
      val identifiersWithSecretKey = identifiers.filter { repository.hasSecretKey(it) }
      if (!repository.isPasswordProtected(identifiersWithSecretKey) && !isError) {
        // try passphraseless decryption first
        decryptWithPassphrase(mapOf("" to charArrayOf()), identifiersWithSecretKey)
      } else if (!isError && !passphrases.isEmpty()) {
        // try cached passphrases
        decryptWithPassphrase(
          passphrases.mapValues { AESEncryption.decrypt(it.value) ?: charArrayOf() },
          identifiers,
        )
      } else {
        askPassphrase(isError, identifiers)
      }
    }
  }

  /** Subclass-specific implementations */
  open suspend fun decryptWithPassphrase(
    passphrases: Map<String, CharArray>,
    identifiers: List<PGPIdentifier>,
    onSuccess: suspend (String) -> Unit = {},
  ) {}

  companion object {

    const val MAX_RETRIES = 3
    const val EXTRA_FILE_PATH = "FILE_PATH"
    const val EXTRA_REPO_PATH = "REPO_PATH"

    /**
     * Temporary cache for PGP key passphrases, unconditionally nulled and cleared when the screen
     * is switched off. Passphrases stored here are AES encrypted with a key that is renewed when
     * the app is restarted.
     */
    val cachedPassphrases = mutableMapOf<String, CharArray>() // pgp id, passphrase

    /**
     * Newest Samsung phones now feature a history of up to 30 items. To err on the side of caution,
     * push 35 fake ones.
     */
    private const val CLIPBOARD_CLEAR_COUNT = 35
    var clearTimer: ScheduledExecutorService? = null

    /** Gets the relative path to the repository */
    fun getRelativePath(fullPath: String, repositoryPath: String): String =
      fullPath.replace(repositoryPath, "").replace("/+".toRegex(), "/")

    /** Gets the Parent path, relative to the repository */
    fun getParentPath(fullPath: String, repositoryPath: String): String {
      val relativePath = getRelativePath(fullPath, repositoryPath)
      val index = relativePath.lastIndexOf("/")
      return "/${relativePath.substring(startIndex = 0, endIndex = index + 1)}/"
        .replace("/+".toRegex(), "/")
    }

    /** /path/to/store/social/facebook.gpg -> social/facebook */
    @JvmStatic
    fun getLongName(fullPath: String, repositoryPath: String, basename: String): String {
      var relativePath = getRelativePath(fullPath, repositoryPath)
      return if (relativePath.isNotEmpty() && relativePath != "/") {
        // remove preceding '/'
        relativePath = relativePath.substring(1)
        if (relativePath.endsWith('/')) {
          relativePath + basename
        } else {
          "$relativePath/$basename"
        }
      } else {
        basename
      }
    }
  }
}
