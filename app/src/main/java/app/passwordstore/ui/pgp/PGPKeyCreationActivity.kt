/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.pgp

import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import app.passwordstore.R
import app.passwordstore.databinding.PgpKeyCreationActivityBinding
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.viewBinding
import dagger.hilt.android.AndroidEntryPoint
import java.nio.CharBuffer
import java.nio.charset.Charset
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import javax.inject.Inject
import kotlinx.coroutines.runBlocking
import androidx.core.widget.doOnTextChanged

@AndroidEntryPoint
class PGPKeyCreationActivity : AppCompatActivity() {

  private val binding by viewBinding(PgpKeyCreationActivityBinding::inflate)
  @Inject lateinit var keyManager: PGPKeyManager

  //  private val suggestedName by unsafeLazy { intent.getStringExtra(EXTRA_FILE_NAME) }
  //  private val suggestedUsername by unsafeLazy { intent.getStringExtra(EXTRA_USERNAME) }
  //  private val suggestedPass by unsafeLazy { intent.getCharArrayExtra(EXTRA_PASSWORD) }
  //  private val suggestedExtra by unsafeLazy { intent.getStringExtra(EXTRA_EXTRA_CONTENT) }
  //  private val shouldGeneratePassword by unsafeLazy {
  //    intent.getBooleanExtra(EXTRA_GENERATE_PASSWORD, false)
  //  }
  //  private val editing by unsafeLazy { intent.getBooleanExtra(EXTRA_EDITING, false) }
  //  private var oldCategory: String? = null

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    supportActionBar?.setDisplayHomeAsUpEnabled(true)
    title = getString(R.string.pgp_new_pgp_key_title)
    with(binding) {
        setContentView(root)
        repeatPassphrase.doOnTextChanged { _, _, _, _ ->
          repeatPassphraseInputLayout.error = null
        }
    }
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.pgp_key_manager_new_key, menu)
    return true
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    when (item.itemId) {
      android.R.id.home -> {
        setResult(RESULT_CANCELED)
        onBackPressedDispatcher.onBackPressed()
      }
      R.id.save_key -> {
        binding.repeatPassphraseInputLayout.error = "don't match"  
        // TODO create key
        encrypt()
      }
      else -> return super.onOptionsItemSelected(item)
    }
    return true
  }

  private fun CharArray.encodeToByteArray(charset: Charset = Charsets.UTF_8): ByteArray {
    val byteBuffer = charset.encode(CharBuffer.wrap(this))
    val byteArray = ByteArray(byteBuffer.remaining())
    byteBuffer.get(byteArray)
    return byteArray
  }

  private fun newKey(userId: String, passphrase: CharArray?): PGPKey? {
    val (key, error) = runBlocking { keyManager.generateKey(userId, passphrase) }
    if (error != null) throw error
    return key
  }

  /** Encrypts the password and the extra content */
  private fun encrypt() {
    //    with(binding) {
    //      val oldName = suggestedName
    //      val editName = filename.text.toString().trim()
    //      var editUsername = username.text.toString()
    //      val editPass = password.text?.let { CharArray(it.length) { i -> it[i] } } ?:
    // charArrayOf()
    //      val editExtra = extraContent.text.toString()
    //
    //      if (editName.isEmpty()) {
    //        snackbar(message = resources.getString(R.string.file_toast_text))
    //        return@with
    //      } else if (editName.contains('/')) {
    //        snackbar(message = resources.getString(R.string.invalid_filename_text))
    //        return@with
    //      }
    //
    //      if (!editUsername.isEmpty()) {
    //        editUsername = "\nusername:$editUsername"
    //      }
    //
    //      if (editPass.isEmpty() && editExtra.isEmpty()) {
    //        snackbar(message = resources.getString(R.string.empty_toast_text))
    //        return@with
    //      }
    //
    //      if (copy) {
    //        clearTimer?.shutdownNow()
    //        clearTimer = copyPasswordToClipboard(editPass)
    //      }
    //
    //      // pass enters the key ID into `.gpg-id`.
    //      val gpgIdentifiers = getPGPIdentifiers(directory.text.toString()) ?: return@with
    //      val path =
    //        when {
    //          // If we allowed the user to edit the relative path, we have to consider it here
    //          // instead of fullPath.
    //          directoryInputLayout.isEnabled -> {
    //            val editRelativePath = directory.text.toString().trim()
    //            if (editRelativePath.isEmpty()) {
    //              snackbar(message = resources.getString(R.string.path_toast_text))
    //              return
    //            }
    //            val passwordDirectory = Paths.get(repoPath, editRelativePath.trim('/'))
    //            passwordDirectory.createDirectories()
    //            if (!passwordDirectory.exists()) {
    //              snackbar(
    //                message =
    //                  "Failed to create directory
    // ${passwordDirectory.relativeTo(Paths.get(repoPath)).pathString}"
    //              )
    //              return
    //            }
    //
    //            "${passwordDirectory.pathString}/$editName.gpg"
    //          }
    //          else -> "$fullPath/$editName.gpg"
    //        }
    //
    //      lifecycleScope.launch(dispatcherProvider.main()) {
    //        runCatching {
    //            val result =
    //              withContext(dispatcherProvider.io()) {
    //                val outputStream = ByteArrayOutputStream()
    //                repository.encrypt(
    //                  gpgIdentifiers,
    //                  ByteArrayInputStream(
    //                    (editPass + "$editUsername\n$editExtra".toCharArray()).encodeToByteArray()
    //                  ),
    //                  outputStream,
    //                )
    //                outputStream
    //              }
    //            val passwordFile = Paths.get(path)
    //            // If we're not editing, this file should not already exist!
    //            // Additionally, if we were editing and the incoming and outgoing
    //            // filenames differ, it means we renamed. Ensure that the target
    //            // doesn't already exist to prevent an accidental overwrite.
    //            if (
    //              (!editing || (editing && suggestedName != passwordFile.nameWithoutExtension)) &&
    //                passwordFile.exists()
    //            ) {
    //              snackbar(message = getString(R.string.password_creation_duplicate_error))
    //              return@runCatching
    //            }
    //
    //            if (!passwordFile.toFile().isInsideRepository()) {
    //              snackbar(message = getString(R.string.message_error_destination_outside_repo))
    //              return@runCatching
    //            }
    //
    //            withContext(dispatcherProvider.io()) {
    // passwordFile.writeBytes(result.toByteArray()) }
    //
    //            // associate the new password name with the last name's timestamp in history
    //            val preference = getSharedPreferences("recent_password_history",
    // Context.MODE_PRIVATE)
    //            val oldFilePathHash =
    // "$repoPath/${oldCategory?.trim('/')}/$suggestedName.gpg".base64()
    //            val timestamp = preference.getString(oldFilePathHash)
    //            if (timestamp != null) {
    //              preference.edit {
    //                remove(oldFilePathHash)
    //                putString(passwordFile.absolutePathString().base64(), timestamp)
    //              }
    //            }
    //
    //            val returnIntent = Intent()
    //            returnIntent.putExtra(RETURN_EXTRA_CREATED_FILE, path)
    //            returnIntent.putExtra(RETURN_EXTRA_NAME, editName)
    //            returnIntent.putExtra(RETURN_EXTRA_LONG_NAME, getLongName(fullPath, repoPath,
    // editName))
    //
    //            if (shouldGeneratePassword) {
    //              val directoryStructure =
    // AutofillPreferences.directoryStructure(applicationContext)
    //              val entry =
    //                passwordEntryFactory.create(
    //                  (editPass + "$editUsername\n$editExtra".toCharArray()).encodeToByteArray()
    //                )
    //              returnIntent.putExtra(RETURN_EXTRA_PASSWORD, entry.password)
    //              val username =
    //                entry.username ?: directoryStructure.getUsernameFor(passwordFile.toFile())
    //              returnIntent.putExtra(RETURN_EXTRA_USERNAME, username)
    //            }
    //
    //            if (
    //              directoryInputLayout.isVisible &&
    //                directoryInputLayout.isEnabled &&
    //                oldName != editName
    //            ) {
    //              val oldPath = Paths.get(repoPath, oldCategory?.trim('/') ?: "", "$oldName.gpg")
    //              if (
    //                oldPath.exists() && !oldPath.isSameFileAs(passwordFile) &&
    // !oldPath.deleteIfExists()
    //              ) {
    //                setResult(RESULT_CANCELED)
    //                MaterialAlertDialogBuilder(this@PasswordCreationActivity)
    //                  .setTitle(R.string.password_creation_file_fail_title)
    //                  .setMessage(
    //                    getString(R.string.password_creation_file_delete_fail_message, oldName)
    //                  )
    //                  .setCancelable(false)
    //                  .setPositiveButton(android.R.string.ok) { _, _ -> finish() }
    //                  .show()
    //                return@runCatching
    //              }
    //            }
    //
    //            val commitMessageRes =
    //              if (editing) R.string.git_commit_edit_text else R.string.git_commit_add_text
    //            lifecycleScope.launch {
    //              commitChange(
    //                  resources.getString(commitMessageRes, getLongName(fullPath, repoPath,
    // editName))
    //                )
    //                .onSuccess {
    //                  setResult(RESULT_OK, returnIntent)
    //                  finish()
    //                }
    //            }
    //          }
    //          .onFailure { e ->
    //            if (e is IOException) {
    //              logcat(ERROR) { e.asLog("Failed to write password file") }
    //              setResult(RESULT_CANCELED)
    //              MaterialAlertDialogBuilder(this@PasswordCreationActivity)
    //                .setTitle(getString(R.string.password_creation_file_fail_title))
    //                .setMessage(getString(R.string.password_creation_file_write_fail_message))
    //                .setCancelable(false)
    //                .setPositiveButton(android.R.string.ok) { _, _ -> finish() }
    //                .show()
    //            } else {
    //              logcat(ERROR) { e.asLog() }
    //            }
    //          }
    //      }
    //    }
  }

  companion object {

    //    private const val KEY_PWGEN_TYPE_CLASSIC = "classic"
    //    private const val KEY_PWGEN_TYPE_DICEWARE = "diceware"
    //    const val PASSWORD_RESULT_REQUEST_KEY = "PASSWORD_GENERATOR"
    //    const val OTP_RESULT_REQUEST_KEY = "OTP_IMPORT"
    //    const val RESULT = "RESULT"
    //    const val RETURN_EXTRA_CREATED_FILE = "CREATED_FILE"
    //    const val RETURN_EXTRA_NAME = "NAME"
    //    const val RETURN_EXTRA_LONG_NAME = "LONG_NAME"
    //    const val RETURN_EXTRA_USERNAME = "USERNAME"
    //    const val RETURN_EXTRA_PASSWORD = "PASSWORD"
    //    const val EXTRA_FILE_NAME = "FILENAME"
    //    const val EXTRA_USERNAME = "USERNAME"
    //    const val EXTRA_PASSWORD = "PASSWORD"
    //    const val EXTRA_EXTRA_CONTENT = "EXTRA_CONTENT"
    //    const val EXTRA_GENERATE_PASSWORD = "GENERATE_PASSWORD"
    //    const val EXTRA_EDITING = "EDITING"
  }
}
