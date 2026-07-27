/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.crypto

import android.annotation.SuppressLint
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.os.Build
import android.os.Bundle
import android.provider.MediaStore
import android.text.InputType
import android.view.Menu
import android.view.MenuItem
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.annotation.RequiresApi
import androidx.core.content.edit
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderCreateCredentialRequest
import androidx.credentials.webauthn.PublicKeyCredentialCreationOptions
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.errors.NoKeysProvidedException
import app.passwordstore.crypto.errors.UnusableKeyException
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.passfile.joinToCharArray
import app.passwordstore.data.passfile.splitToCharArrayListAt
import app.passwordstore.data.passfile.trimEnd
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.databinding.PasskeyCreationActivityBinding
import app.passwordstore.injection.prefs.CredentialUsernames
import app.passwordstore.injection.prefs.PasswordHistory
import app.passwordstore.ui.dialogs.OtpImportDialogFragment
import app.passwordstore.ui.folderselect.SelectFolderActivity
import app.passwordstore.ui.passwords.PasswordStore
import app.passwordstore.util.auth.BiometricAuthenticator
import app.passwordstore.util.auth.BiometricAuthenticator.Result
import app.passwordstore.util.credman.CredmanUtils
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import app.passwordstore.util.extensions.asLog
import app.passwordstore.util.extensions.b64Encode
import app.passwordstore.util.extensions.base64
import app.passwordstore.util.extensions.commitChange
import app.passwordstore.util.extensions.enableEdgeToEdgeView
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.isInsideRepository
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.toByteArray
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.wipe
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.onOk
import com.github.michaelbull.result.runCatching
import com.github.michaelbull.result.unwrapError
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.zxing.BinaryBitmap
import com.google.zxing.LuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.integration.android.IntentIntegrator
import com.google.zxing.integration.android.IntentIntegrator.QR_CODE
import com.google.zxing.qrcode.QRCodeReader
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.CharBuffer
import java.nio.file.Files
import java.nio.file.Paths
import java.security.SecureRandom
import javax.inject.Inject
import kotlin.io.path.absolutePathString
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.isDirectory
import kotlin.io.path.pathString
import kotlin.io.path.writeBytes
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@OptIn(kotlin.ExperimentalUnsignedTypes::class)
@AndroidEntryPoint
@SuppressLint("RestrictedApi")
class PasskeyCreationActivity : BasePGPActivity() {

  @CredentialUsernames @Inject lateinit var credentialUsernames: SharedPreferences
  @PasswordHistory @Inject lateinit var passwordHistory: SharedPreferences

  private val binding by viewBinding(PasskeyCreationActivityBinding::inflate)
  @Inject lateinit var passwordEntryFactory: PasswordEntry.Factory

  private val suggestedName by unsafeLazy {
    intent.getStringExtra(PasswordCreationActivity.EXTRA_FILE_NAME)
  }

  private val suggestedEntryChars by unsafeLazy {
    intent.getCharArrayExtra(PasswordCreationActivity.EXTRA_ENTRY)
  }

  private val editing by unsafeLazy {
    intent.getBooleanExtra(PasswordCreationActivity.EXTRA_EDITING, false)
  }

  @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
  private fun getProviderRequest(): ProviderCreateCredentialRequest? =
    PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)

  @RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
  private fun getPublicKeyRequest(
    providerRequest: ProviderCreateCredentialRequest
  ): CreatePublicKeyCredentialRequest? =
    if (providerRequest.callingRequest is CreatePublicKeyCredentialRequest)
      providerRequest.callingRequest as CreatePublicKeyCredentialRequest
    else null

  private val otpImportAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == RESULT_OK) {
        binding.otpImportButton.isVisible = false
        val intentResult = IntentIntegrator.parseActivityResult(RESULT_OK, result.data)
        val contents = "${intentResult.contents}\n"
        binding.extraContent.text?.let { currentExtras ->
          if (currentExtras.isNotEmpty() && currentExtras.last() != '\n')
            binding.extraContent.append("\n$contents")
          else binding.extraContent.append(contents)
        }
        snackbar(message = getString(R.string.otp_import_success))
      } else {
        snackbar(message = getString(R.string.otp_import_failure_generic))
      }
    }

  private val imageImportAction =
    registerForActivityResult(ActivityResultContracts.GetContent()) { imageUri ->
      if (imageUri == null) {
        snackbar(message = getString(R.string.otp_import_failure_no_selection))
        return@registerForActivityResult
      }
      val bitmap =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          ImageDecoder.decodeBitmap(ImageDecoder.createSource(contentResolver, imageUri))
            .copy(Bitmap.Config.ARGB_8888, true)
        } else {
          @Suppress("DEPRECATION") MediaStore.Images.Media.getBitmap(contentResolver, imageUri)
        }
      val intArray = IntArray(bitmap.width * bitmap.height)
      // copy pixel data from the Bitmap into the 'intArray' array
      bitmap.getPixels(intArray, 0, bitmap.width, 0, 0, bitmap.width, bitmap.height)
      val source: LuminanceSource = RGBLuminanceSource(bitmap.width, bitmap.height, intArray)
      val binaryBitmap = BinaryBitmap(HybridBinarizer(source))

      val reader = QRCodeReader()
      runCatching {
        val result = reader.decode(binaryBitmap)
        val text = result.text
        binding.extraContent.text?.let { currentExtras ->
          if (currentExtras.isNotEmpty() && currentExtras.last() != '\n')
            binding.extraContent.append("\n$text")
          else binding.extraContent.append(text)
        }
        snackbar(message = getString(R.string.otp_import_success))
        binding.otpImportButton.isVisible = false
      }
        .onErr { snackbar(message = getString(R.string.otp_import_failure_generic)) }
    }

  override fun onDestroy() {
    with(binding) {
      extraContent.text?.clear()
    }
    super.onDestroy()
  }

  private val selectFolderAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == RESULT_OK) {
        val rpId =
          result.data?.getStringExtra(PasswordStore.REQUEST_ARG_PATH)?.let { oldPath ->
            Paths.get(oldPath).fileName.toString()
          }
        val relPath =
          result.data?.getStringExtra(SelectFolderActivity.SELECTED_FOLDER_PATH)?.let { fullPath ->
            PasswordRepository.getRelativePath(fullPath, repoPath)
          } ?: ""
        rpId?.let {
          val path =
            if (relPath.isEmpty()) "/${rpId}"
            else if (Paths.get(relPath).endsWith(rpId)) relPath
            else Paths.get(relPath, rpId).absolutePathString()
          binding.directory.setText(path)
        }
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    supportActionBar?.setDisplayHomeAsUpEnabled(true)
    title = if (editing) getString(R.string.edit_passkey) else getString(R.string.new_passkey_title)

    with(binding) {
      enableEdgeToEdgeView(root)
      setContentView(root)

      otpImportButton.setOnClickListener {
        supportFragmentManager.setFragmentResultListener(
          PasswordCreationActivity.OTP_RESULT_REQUEST_KEY,
          this@PasskeyCreationActivity,
        ) { requestKey, bundle ->
          if (requestKey == PasswordCreationActivity.OTP_RESULT_REQUEST_KEY) {
            val contents = bundle.getString(PasswordCreationActivity.RESULT)
            extraContent.text?.let { currentExtras ->
              if (currentExtras.isNotEmpty() && currentExtras.last() != '\n')
                extraContent.append("\n$contents")
              else extraContent.append(contents)
            }
          }
        }
        val hasCamera = packageManager?.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY) == true
        if (hasCamera) {
          val items =
            arrayOf(
              getString(R.string.otp_import_qr_code),
              getString(R.string.otp_import_from_file),
              getString(R.string.otp_import_manual_entry),
            )
          MaterialAlertDialogBuilder(this@PasskeyCreationActivity)
            .setItems(items) { _, index ->
              when (index) {
                0 ->
                  otpImportAction.launch(
                    IntentIntegrator(this@PasskeyCreationActivity)
                      .setOrientationLocked(false)
                      .setBeepEnabled(false)
                      .setDesiredBarcodeFormats(QR_CODE)
                      .createScanIntent()
                  )
                1 -> {
                  runCatching { imageImportAction.launch("image/*") }
                    .onErr { e ->
                      logcat(ERROR) { e.asLog() }
                      e.message?.let { message -> snackbar(message = message) }
                    }
                }
                2 -> OtpImportDialogFragment().show(supportFragmentManager, "OtpImport")
              }
            }
            .show()
        } else {
          OtpImportDialogFragment().show(supportFragmentManager, "OtpImport")
        }
      }

      directory.inputType = InputType.TYPE_NULL
      directory.setOnClickListener {
        val intent = Intent(this@PasskeyCreationActivity, SelectFolderActivity::class.java)
        intent.putExtra(PasswordStore.REQUEST_ARG_PATH, directory.text.toString().trimEnd('/'))
        selectFolderAction.launch(intent)
      }

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
        val providerRequest = getProviderRequest()
        val publicKeyRequest = providerRequest?.let { getPublicKeyRequest(it) }
        publicKeyRequest?.let { request -> // passkey creation requested
          val credentialId = ByteArray(32)
          SecureRandom().nextBytes(credentialId)

          val requestOptions = PublicKeyCredentialCreationOptions(request.requestJson)

          val suggestedFullPath =
            findSubdirectoryRecursively(repoPath, requestOptions.rp.id)
              ?: Paths.get(repoPath, requestOptions.rp.id).absolutePathString()
          val relPath = PasswordRepository.getRelativePath(suggestedFullPath, repoPath)

          directory.setText(relPath)
          credId.setText(credentialId.toHexString())
          credAlgorithm.setText(CredmanUtils.getPreferredAlgorithm(requestOptions).toString())
          username.setText(requestOptions.user.name)
          requestOptions.user.displayName?.let {
            fullname.setText(it)
            fullnameLayout.isVisible = it != requestOptions.user.name
          }
        }
      }

      if (editing) {
        val relPath = PasswordRepository.getRelativePath(fullPath, repoPath)
        directory.setText(if (relPath.isEmpty()) "/" else relPath)

        val suggestedEntry: PasswordEntry? = suggestedEntryChars?.let { encrypted ->
          AESEncryption.decrypt(encrypted)?.let { decrypted ->
            passwordEntryFactory.create(decrypted).also { decrypted.wipe() }
          }
        }

        val passkey = suggestedEntry?.let { retrievePasskey(it, stripped = true) }

        credId.setText(passkey?.idHex())
        credAlgorithm.setText(passkey?.getAlgorithmString())
        username.setText(passkey?.user?.name)
        revealPasskeyUsername.isChecked = passkey?.user?.revealName ?: false
        passkey?.user?.displayName?.let {
          fullname.setText(it)
          fullnameLayout.isVisible = it != passkey?.user?.name
        }

        suggestedEntry?.extraContentChars?.let {
          val charBuf =
            if (it.last() == '\n') CharBuffer.wrap(it.copyOfRange(0, it.size - 1))
            else CharBuffer.wrap(it)
          extraContent.setText(charBuf)
          charBuf.array().wipe()
        }

        suggestedEntry?.clear()
      }

      extraContent.doAfterTextChanged { updateViewState() }
    }

    updateViewState()
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.pgp_handler_new_password, menu)
    return true
  }

  override fun onPrepareOptionsMenu(menu: Menu): Boolean {
    menu.findItem(R.id.save_and_copy_password).setVisible(false).setEnabled(false)
    return true
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    when (item.itemId) {
      android.R.id.home -> {
        setResult(RESULT_CANCELED)
        onBackPressedDispatcher.onBackPressed()
      }
      R.id.save_password -> {
        if (PasswordRepository.isEmpty()) {
          MaterialAlertDialogBuilder(this)
            .setCancelable(false)
            .setTitle(R.string.error)
            .setIcon(R.drawable.ic_crossmark_red_24dp)
            .setMessage(R.string.creation_dialog_text)
            .setPositiveButton(R.string.dialog_ok) { _, _ ->
              setResult(RESULT_CANCELED)
              finish()
            }
            .show()
        } else if (!editing && !BiometricAuthenticator.canAuthenticate(this, allowPin = true)) {
          MaterialAlertDialogBuilder(this)
            .setCancelable(false)
            .setTitle(R.string.error)
            .setIcon(R.drawable.ic_crossmark_red_24dp)
            .setMessage(R.string.passkey_biometric_auth_missing_error)
            .setPositiveButton(R.string.git_server_hostkey_dialog_abort) { _, _ ->
              setResult(RESULT_CANCELED)
              finish()
            }
            .show()
        } else {
          requireKeysExist {
            requireEncryptionKeysExist(binding.directory.text.toString()) { ids ->
              // biometric auth needed for passkey creation
              if (!editing)
                BiometricAuthenticator.authenticate(this, allowPin = true) { result ->
                  when (result) {
                    is Result.Success -> encrypt(ids)
                    is Result.Retry -> {}
                    else -> finish()
                  }
                }
              else encrypt(ids)
            }
          }
        }
      }
      else -> return super.onOptionsItemSelected(item)
    }
    return true
  }

  private fun updateViewState() =
    with(binding) {
      // use PasswordEntry to parse extras for OTP
      val entry = passwordEntryFactory.create("PLACEHOLDER\n${extraContent.text}".toCharArray())
      val hasTotp = entry.hasTotp()
      entry.clear()
      otpImportButton.isVisible = !hasTotp
    }

  /** encrypts passkey (edited or newly created) and saves it to the store */
  private fun encrypt(identifiers: List<PGPIdentifier>) {
    with(binding) {
      val gpgIdentifiers = getPGPIdentifiers(directory.text.toString())
      if (gpgIdentifiers.isNullOrEmpty()) return@with

      lifecycleScope.launch(dispatcherProvider.main()) {
        runCatching {
          var credentialHexId = binding.credId.text.toString()

          val returnIntent = Intent()

          // passkey creation
          val passkey =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
              val providerRequest = getProviderRequest()
              val publicKeyRequest = providerRequest?.let { getPublicKeyRequest(it) }
              val requestOptions = publicKeyRequest?.let {
                PublicKeyCredentialCreationOptions(it.requestJson)
              }

              val passkeyAndCreatePublicKeyCredentialResponse = requestOptions?.let { options ->
                requireNotNull(providerRequest) { "providerRequest must not be null here" }
                requireNotNull(publicKeyRequest) { "publicKeyRequest must not be null here" }
                CredmanUtils.buildCreatePublicKeyCredentialResponse(
                  options,
                  credentialHexId,
                  providerRequest.callingAppInfo,
                  publicKeyRequest.clientDataHash,
                )
              }

              passkeyAndCreatePublicKeyCredentialResponse?.let { response ->
                PendingIntentHandler.setCreateCredentialResponse(returnIntent, response.second)
                response.first
              }
            } else null

          // passkey as b64url-encoded cbor for storage in password file
          val passkeyCborBase64 =
            if (passkey != null) {
              // new passkey
              passkey.user.revealName = revealPasskeyUsername.isChecked
              passkey.toCbor()?.b64Encode().also { passkey.clearPrivateKey() }
            } else {
              // edit passkey
              suggestedEntryChars?.let { encrypted ->
                AESEncryption.decrypt(encrypted)?.let { decrypted ->
                  val entry = passwordEntryFactory.create(decrypted).also { decrypted.wipe() }
                  val storedPasskey = retrievePasskey(entry).also { entry.clear() }
                  storedPasskey?.user?.revealName?.let {
                    storedPasskey.user.revealName = revealPasskeyUsername.isChecked
                  }
                  storedPasskey?.toCbor()?.b64Encode()?.also {
                    storedPasskey.clearPrivateKey()
                  }
                }
              }
            } ?: throw NullPointerException()

          // apply any modifications done on the entry, and encrypt it for storage
          var editExtra =
            extraContent.text?.let { CharArray(it.length) { i -> it[i] } } ?: charArrayOf()

          // fix extra content formatting
          if (!editExtra.isEmpty()) {
            editExtra = editExtra.let {
              val extraLines = it.splitToCharArrayListAt('\n').map { it.trimEnd() }
              it?.wipe()
              val editExtra = extraLines.joinToCharArray('\n')?.trimEnd()
              val editExtraPlusLineFeed = editExtra?.let { it + '\n' }
              editExtra?.wipe()
              editExtraPlusLineFeed ?: charArrayOf()
            }
          }

          val contentChars = (passkeyCborBase64 + '\n' + editExtra)
          val contentBytes = contentChars.toByteArray()
          contentChars.wipe()
          passkeyCborBase64.wipe()
          editExtra?.wipe()

          val (succeededUserEmails, encryptionResult) =
            withContext(dispatcherProvider.io()) {
              repository.encrypt(
                identifiers,
                ByteArrayInputStream(contentBytes),
                ByteArrayOutputStream(),
              )
            }
          contentBytes.wipe()

          if (encryptionResult.isErr) throw encryptionResult.unwrapError()
          if (succeededUserEmails.isNullOrEmpty()) throw UnusableKeyException

          val failedUserEmails =
            identifiers
              .map { id ->
                repository.getEmailFromKeyId(id)
                  ?: run {
                    if (!repository.hasKey(id))
                      "\n${id}: ${getString(R.string.pgp_unknown_key_identifier)}"
                    else
                      "\n${id}: ${getString(R.string.password_creation_file_encryption_failed_expired_key)}"
                  }
              }
              .distinct()
              .filter { it !in succeededUserEmails ?: emptyList() }

          val path = run { // password item's full file path string
            val editRelativePath = directory.text.toString().trim()
            val passwordDirectory = Paths.get(repoPath, editRelativePath.trim('/'))
            passwordDirectory.createDirectories() // ensure destination dir exists
            if (!passwordDirectory.exists()) { // should not happen
              snackbar(message = "Failed to create directory ${editRelativePath.trimEnd('/')}")
              return@runCatching
            }

            "${passwordDirectory.pathString}/$credentialHexId.gpg"
          }

          val passkeyFile = Paths.get(path)
          /* If we were editing and the incoming and outgoing file paths differ, it means we renamed. Ensure
           * that the target doesn't already exist to prevent an accidental overwrite. */
          if (
            editing &&
              "${fullPath.trimEnd('/')}/$suggestedName.gpg" != passkeyFile.absolutePathString() &&
              passkeyFile.exists()
          ) {
            snackbar(message = getString(R.string.password_creation_duplicate_error))
            return@runCatching
          }

          if (!passkeyFile.toFile().isInsideRepository()) {
            snackbar(message = getString(R.string.message_error_destination_outside_repo))
            return@runCatching
          }

          withContext(dispatcherProvider.io()) {
            passkeyFile.writeBytes(encryptionResult.getOrThrow().toByteArray())
          }

          // create/update timestamp on the current passkey file
          passwordHistory.edit {
            suggestedName?.let { oldFile ->
              val oldFilePathHash = "${fullPath.trimEnd('/')}/$oldFile.gpg".base64()
              remove(oldFilePathHash)
            }
            putString(
              passkeyFile.absolutePathString().base64(),
              System.currentTimeMillis().toString(),
            )
          }

          lifecycleScope.launch {
            val commitMessageRes =
              if (editing) R.string.git_commit_edit_passkey_text
              else R.string.git_commit_add_passkey_text

            commitChange(
                resources.getString(
                  commitMessageRes,
                  directory.text.toString().trim().trim('/') + "/" + credentialHexId,
                )
              )
              .onOk {
                setResult(RESULT_OK, returnIntent)

                // maintain cred hex ID <-> user name map for display on passkey selector
                credentialUsernames.edit {
                  if (revealPasskeyUsername.isChecked) {
                    val displayUser =
                      if ("${fullname.text}" != "${username.text}")
                        "${username.text} (${fullname.text})"
                      else "${username.text}"
                    putString(
                      credentialHexId,
                      AESEncryption.encrypt(
                          displayUser.toCharArray(),
                          keyType = KeyType.PERSISTENT,
                        )
                        ?.concatToString(),
                    )
                  } else {
                    remove(credentialHexId)
                  }
                }

                val dialog =
                  MaterialAlertDialogBuilder(this@PasskeyCreationActivity)
                    .setCancelable(false)
                    .setPositiveButton(android.R.string.ok) { _, _ -> finish() }
                var messageText =
                  getString(
                    R.string.password_creation_file_encryption_succeeded_ids_message,
                    succeededUserEmails.joinToString(),
                  )
                if (!failedUserEmails.isEmpty()) {
                  dialog.setTitle(R.string.password_creation_file_encryption_partial_success_title)
                  messageText +=
                    getString(
                      R.string.password_creation_file_encryption_failed_ids_message,
                      failedUserEmails.joinToString(),
                    )
                } else {
                  val title =
                    if (editing)
                      getString(R.string.password_creation_edit_file_encryption_success_title)
                    else getString(R.string.password_creation_new_file_encryption_success_title)
                  dialog.setTitle(title)
                }
                dialog.setMessage(messageText)
                dialog.show()
              }
          }
        }
          .onErr { e ->
            logcat(ERROR) { e.asLog() }
            setResult(RESULT_CANCELED)
            val errMessage =
              when (e) {
                is IOException -> getString(R.string.password_creation_file_write_fail_message)
                is NoKeysProvidedException ->
                  getString(R.string.password_creation_no_keys_provided_message)
                is UnusableKeyException ->
                  getString(R.string.password_creation_unusable_encryption_key_error_message)
                else -> e.message ?: e.toString()
              }
            MaterialAlertDialogBuilder(this@PasskeyCreationActivity)
              .setIcon(R.drawable.ic_crossmark_red_24dp)
              .setTitle(getString(R.string.error))
              .setMessage(errMessage)
              .setCancelable(false)
              .setPositiveButton(android.R.string.ok) { _, _ -> finish() }
              .show()
          }
      }
    }
  }

  private fun findSubdirectoryRecursively(rootPath: String, targetName: String): String? {
    val match =
      Files.walk(Paths.get(rootPath))
        .filter { it.isDirectory() && it.fileName.toString() == targetName }
        .findFirst()
        .orElse(null)
    return match?.let { match.absolutePathString() }
  }
}
