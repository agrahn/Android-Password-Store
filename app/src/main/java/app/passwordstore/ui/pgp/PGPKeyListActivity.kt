/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.pgp

import android.nfc.TagLostException
import com.yubico.yubikit.openpgp.Do
import app.passwordstore.crypto.errors.NoMatchingKeyException
import com.yubico.yubikit.openpgp.KeyRef
import kotlinx.collections.immutable.toPersistentList
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Bundle
import android.text.Spannable
import android.text.SpannableString
import android.text.style.ImageSpan
import android.view.View
import android.widget.CheckBox
import android.widget.TextView
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.contract.ActivityResultContracts.CreateDocument
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.fragment.app.setFragmentResultListener
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.data.crypto.CryptoRepository
import app.passwordstore.injection.prefs.SettingsPreferences
import app.passwordstore.ui.APSAppBar
import app.passwordstore.ui.compose.theme.APSTheme
import app.passwordstore.ui.dialogs.AddPgpKeyBottomSheet
import app.passwordstore.ui.dialogs.PasswordDialog
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.settings.PreferenceKeys.TOKEN_LINKED_PGP_IDS
import app.passwordstore.util.viewmodel.PGPKeyListViewModel
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.onSuccess
import com.github.michaelbull.result.runCatching
import com.github.michaelbull.result.unwrap
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.ApplicationNotAvailableException
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.OpenPgpSession
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.SecureRandom
import javax.inject.Inject
import kotlinx.collections.immutable.toPersistentList
import kotlinx.coroutines.launch
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

@AndroidEntryPoint
class PGPKeyListActivity : AppCompatActivity() {

  @Inject lateinit var cryptoRepository: CryptoRepository
  @Inject lateinit var pgpKeyManager: PGPKeyManager
  @Inject @SettingsPreferences lateinit var settings: SharedPreferences
  lateinit var yubikit: YubiKitManager

  /* Counter for the user's passphrase attempts */
  private var retries = 0

  private val viewModel: PGPKeyListViewModel by viewModels()

  private val keyAction =
    registerForActivityResult(StartActivityForResult()) {
      if (it.resultCode == RESULT_OK) {
        viewModel.updateKeySet()
      }
    }

  private var keyNumericId: String? = null
  private var keyContentsWithArmor: ByteArray? = null

  private val keyExportAction =
    registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) {
      uri ->
      if (uri != null) {
        writeBytesToUri(uri, keyContentsWithArmor)
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    val isSelecting = intent.extras?.getBoolean(EXTRA_KEY_SELECTION) ?: false
    val selectedKeyIds = mutableSetOf<String>()
    supportFragmentManager.setFragmentResultListener(PGP_KEY_ADD_REQUEST_KEY, this) { _, bundle ->
      when (bundle.getString(ACTION_KEY)) {
        ACTION_IMPORT_FILE -> keyAction.launch(Intent(this, PGPKeyImportActivity::class.java))
        ACTION_NEW_PGP_KEY -> keyAction.launch(Intent(this, PGPKeyCreationActivity::class.java))
      }
    }

    if(!isSelecting) {
      yubikit = YubiKitManager(this)
      yubikit.startUsbDiscovery(UsbConfiguration()) { device -> 
	    selectedIdentifierForLinkHw?.let {connectHw(it, device)}
        device.setOnClosed {
	        selectedIdentifierForLinkHw = null
        }
	  }
	}  

    setContent {
      APSTheme {
        Scaffold(
          topBar = {
            APSAppBar(
              title =
                if (isSelecting) stringResource(R.string.activity_label_pgp_key_select)
                else stringResource(R.string.activity_label_pgp_key_manager),
              navigationIcon = painterResource(R.drawable.ic_arrow_back_24dp),
              onNavigationIconClick = {
                if (selectedKeyIds.isNotEmpty()) {
                  val result = Intent()
                  result.putExtra(EXTRA_SELECTED_KEY, selectedKeyIds.joinToString(separator = "\n"))
                  setResult(RESULT_OK, result)
                }
                finish()
              },
              backgroundColor = MaterialTheme.colorScheme.surface,
            )
          },
          floatingActionButton = {
            FloatingActionButton(
              onClick = {
                AddPgpKeyBottomSheet().show(supportFragmentManager, "ADD_PGP_KEY_BOTTOM_SHEET")
              }
            ) {
              Icon(
                painter = painterResource(R.drawable.ic_add_48dp),
                stringResource(R.string.pref_import_pgp_key_title),
              )
            }
          },
        ) { paddingValues ->
          val tokenLinkedIds =
            viewModel.keys.filter { id ->
              val keyId =
                KeyUtils.tryGetId(pgpKeyManager.getKeyById(id).unwrap()) // ensure numeric key ID
                ?: throw NullPointerException()
              (settings.getStringSet(TOKEN_LINKED_PGP_IDS, null) ?: setOf<String>()).contains(
                keyId.toString()
              )
            }
          KeyList(
            identifiers = viewModel.keys,
            tokenLinkedIds = tokenLinkedIds.toPersistentList(),
            hasSecretKey = ::hasSecretKey,
            onChangePassphraseClick = ::changeKeyPassphrase,
            onDeleteItemClick = ::deleteKey,
            onExportItemClick = ::exportKey,
            onExportPublicClick = ::exportPublicKey,
            onLinkHwClick = ::onLinkHwClick,
            modifier = Modifier.padding(paddingValues),
            onKeySelected =
              if (isSelecting) {
                { identifier, isSelected ->
                  val keyId =
                    KeyUtils.tryGetId(
                      pgpKeyManager.getKeyById(identifier).unwrap()
                    ) // ensure numeric key ID
                    ?: throw NullPointerException()
                  if (isSelected) selectedKeyIds.add(keyId.toString())
                  else selectedKeyIds.remove(keyId.toString())
                }
              } else null,
          )
        }
      }
    }
  }

  override fun onResume() {
    super.onResume()
    viewModel.updateKeySet()
    if(!(intent.extras?.getBoolean(EXTRA_KEY_SELECTION) ?: false))
      lifecycleScope.launch {
        runCatching {
          yubikit.startNfcDiscovery(NfcConfiguration().timeout(15000), this@PGPKeyListActivity) {
            device ->
	        selectedIdentifierForLinkHw?.let {connectHw(it, device)}
            device.remove {
	            selectedIdentifierForLinkHw = null
            }
          }
        }
	  }  
  }

  override fun onPause() {
    runCatching { yubikit.stopNfcDiscovery(this) }
    super.onPause()
  }

  override fun onDestroy() {
    runCatching { yubikit.stopUsbDiscovery() }
    super.onDestroy()
  }

  private fun hasSecretKey(identifier: PGPIdentifier): Boolean =
    cryptoRepository.hasSecretKey(identifier)

  private fun changeKeyPassphrase(identifier: PGPIdentifier) {
    val intent = Intent(this, PGPKeyChangePassphraseActivity::class.java)
    intent.putExtra(PGPKeyChangePassphraseActivity.EXTRA_SELECTED_IDENTIFIER, identifier.toString())
    keyAction.launch(intent)
  }

  private fun decryptionTest(openPgpSession: OpenPgpSession): String {
//    //passtest
//    val cipherTextWithArmor =
//      """
//          -----BEGIN PGP MESSAGE-----
//                    
//          hQGMA1+zW06M+3VwAQwAoDf3Ty669GOO6AfcQqoJN1ABQpUd0BKF1HiWnZwr0kzz
//          SHTVwQVxR2LC8MHmi+riAslNBfoFcVd2jgSbzoNT6C2kRd4qVnM9OYE789w8abtq
//          /Fa7s+TsKAiv+BwonU1r+PJ8O8zVm1MGoq33glOiKDgnmk6Q7iLVWe+uhNrYXlpR
//          lTToO5GRmFvYNUXecUWYSrrVMB0wb1qV3Z6MNBY1voD9hjIQYnc10YsBcDe4+7bQ
//          QAgo6ENt+XYKJFvvRyb9aTyBN+Lhw/oc8FBfY4NcXReX8twLZRf8hHq9ff3lxfVZ
//          IK3+c+BpVZ4o99s5E8xx/uN7wmtce6eVPzVY1RF8ZmfEg3xoHmn0AzvYgCUPOrca
//          K0IgpqoluRUmIhhn91zkK+5xtCJVgGpKqrxY1jR6ne0QyiU7fdDoF67M3unnULeS
//          pv2hlme4e3NZqQpfogFSBeusfqi4JDaXS+ol4bSX/oIRkDNmsWawsNFygi1FscsQ
//          rlviFkYFZFSvc0/ZK2rZ0kIB62BPgOmqV1EedQ64uOAMDMk/ob/KJL+1goZpGUTC
//          WydWkRrVDtd2pYq7yS7NzEGaVJpBV0NOCRPVIJTUD38QykQ=
//          =l97u
//          -----END PGP MESSAGE-----
//      """
//        .trimIndent()
//
    //passtest2
    val cipherTextWithArmor =
      """
          -----BEGIN PGP MESSAGE-----
          
          hF4D9de8BCyNdHMSAQdAA8L5smQDLI98R+EanyseF2WnbJylEh+peo7Fv/AP3Uww
          BsKmAfm06gPxbmjxb0slhx51aND0kiXE+eNUoQG1BzmGbFYQI+owWDVqwMcfQPum
          0k8B3yCX7xPnoRlze//1eU/k/UHJz9lhyWyV4hOIWpxjgZCpvn4xru0qy86sYK98
          mErFsRStBxY/S56JCTy9wZsFfYXg1UBesDcb2f35SUoK
          =kAe3
          -----END PGP MESSAGE-----
      """.trimIndent()
//
//    //passtest, passtest2
//    val cipherTextWithArmor =
//      """
//        -----BEGIN PGP MESSAGE-----
//        
//        hQGMA1+zW06M+3VwAQwAhw/v6EMvOKONeBJF0JqGqW8+v8dPhRjUn6IQ6ikrnLbv
//        j3zJhJj3XANDqFXtlVxbNhvW6GFBUumWF6Ug8veGLqGTqJkhTS+Zdf6YylVDLCQj
//        w/bVSJfCW/3j+AbVqVud8cjrGYvA3pQ+sappqeJg7JG8wGXjKNEDw8Ix2lxPOwuN
//        1Adg5/JGOtZQK5138H8ATAjEB3SSnH8R6fqTQCa5GB+enhG3v+XQVFy8SsbPFGJk
//        t3u4oyHFO7JmcIX+rIp4/9yOnvcZqrHdNSNq+vRI2/KMTXPHRI9zMq3TXsvm76N7
//        fFItshECZpYy63FZRrlUMRXx6+W6Hw6gzDZx9kpp/lEvEiSu9bqFoAqZsAAsd1py
//        5+r2WZTqXqK0AmE77J/EID3yL4makPIPhKa7RMjUEze7DsYZ/w90JBAh2bvfEFXk
//        wR4W7OCL7DMi2qsuxoh46KvefSAmCnUwdjYSnKYGaTRg9My7OR9FzR6BH3pdu+2N
//        1uAnO9nx8PaRM/Z1UOFuhF4D9de8BCyNdHMSAQdAPRM0StcoHZWQDLrO1tUh84UO
//        EAx/kpcn5Ux9RLyr3G4wNY1d7DKp+8gv2y1ein6Nu5hS8g1QaWedZ+1JHrJGwmNp
//        +USInvQXx6w+4k+t49EP0k8B8sxgxAYa+3NWbBLayifv1QoHqECv5qdfYkQlnbml
//        jcS9vE8wLBGrcljbHWudMY9w8Erb06EDVq8tayd398wTlA7VKKOqGr4HT5p85c9z
//        =yDst
//        -----END PGP MESSAGE-----
//    """.trimIndent()
//    
    logcat { "++++++++++++++++ A verified-----------------" }
    openPgpSession.verifyUserPin("123456".toCharArray(), true)
    logcat { "++++++++++++++++ B verified-----------------" }
    val encSessionKey = cryptoRepository.removeArmor(cipherTextWithArmor.toByteArray())
    val sessionKey =  openPgpSession.decrypt(encSessionKey)
    logcat { "session key :" + sessionKey.toString() }
    logcat { "algorithm :" + sessionKey[0].toUByte().toInt() }
    logcat { "length :" + sessionKey.size.toInt() }
    //val pgpSessionKey = KeyUtils.createPGPSessionKey(sessionKey)
    //// return openPgpSession.decrypt(cipherTextWithArmor.toByteArray()).decodeToString()
    //// decryption
    // val message = "hello".toByteArray()
    // val publicKey = openPgpSession.getPublicKey(KeyRef.DEC).toPublicKey() // get decryption key
    // from yubikey
    // val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    // cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    // val cipherText = cipher.doFinal(message);
    //
    // openPgpSession.verifyUserPin("123456".toCharArray(), true)
    //return openPgpSession.decrypt(cipherText).decodeToString();
    //logcat { "pgp session key: " + pgpSessionKey.toString() }
    return sessionKey.toString();
  }

  private fun deleteKey(identifier: PGPIdentifier) {
    val keyIdPassedIn =
      KeyUtils.tryGetId(pgpKeyManager.getKeyById(identifier).unwrap())
        ?: throw NullPointerException()
    val tokenLinkedIds = settings.getStringSet(TOKEN_LINKED_PGP_IDS, setOf<String>())
    settings.edit {
      putStringSet(
        TOKEN_LINKED_PGP_IDS,
        tokenLinkedIds?.minus(keyIdPassedIn.toString()) ?: setOf<String>(),
      )
    }
    viewModel.deleteKey(identifier)
  }

  private fun exportKey(identifier: PGPIdentifier) {
    retries = 0
    lifecycleScope.launch {
      if (cryptoRepository.isPasswordProtected(listOf(identifier))) {
        // export as symmetrically encrypted file after passphrase verification
        askPassphrase(identifier)
      } else if (hasSecretKey(identifier)) {
        // a secret key without passphrase is encrypted and exported without verification
        confirmBackupCode(identifier, generateBackupCode())
      } else {
        // write public key to file unencrypted
        writeBackupFile(identifier)
      }
    }
  }

  private fun exportPublicKey(identifier: PGPIdentifier) {
    lifecycleScope.launch { writeBackupFile(identifier) }
  }

  private var connectHwDialog: AlertDialog? = null

  private fun onLinkHwClick(identifier: PGPIdentifier) {
    selectedIdentifierForLinkHw = identifier

    val connectHwDialogView = layoutInflater.inflate(R.layout.dialog_message, null)
    connectHwDialogView.findViewById<TextView>(R.id.dialog_message).text =
      resources.getString(R.string.pgp_key_manager_link_token_message)

    if (hasSecretKey(identifier)) {
      val warningMessage = resources.getString(R.string.pgp_key_manager_link_token_warning_message)
      val spannable = SpannableString("! $warningMessage")
      val icon = ContextCompat.getDrawable(this, R.drawable.ic_warning_red_24dp)
      icon?.setBounds(0, 0, icon.intrinsicWidth, icon.intrinsicHeight)
      icon?.let {
        val imageSpan = ImageSpan(it, ImageSpan.ALIGN_BOTTOM)
        spannable.setSpan(imageSpan, 0, 1, Spannable.SPAN_INCLUSIVE_EXCLUSIVE)
      }
      val warningMessageView =
        connectHwDialogView.findViewById<TextView>(R.id.dialog_extended_message)
      warningMessageView.text = spannable
      warningMessageView.visibility = View.VISIBLE
    }

    connectHwDialog =
      MaterialAlertDialogBuilder(this)
        .setTitle(R.string.pgp_key_manager_connect_token_dialog_title)
        .setView(connectHwDialogView)
        .setNegativeButton(R.string.dialog_cancel) { _, _ ->
          selectedIdentifierForLinkHw = null
		}
        .setCancelable(false)
        .create()
    connectHwDialog?.show()
  }

  private var openPgpAppMissingDialog: AlertDialog? = null

  private fun connectHw(identifier: PGPIdentifier, device: YubiKeyDevice) {
    device.requestConnection(SmartCardConnection::class.java) { result ->
      openPgpAppMissingDialog?.dismiss()
      if (result.isSuccess) {
        val connection = result.getValue()
        runCatching { linkHwKey(identifier, OpenPgpSession(connection)) }
          .onFailure { e ->
            if (e is ApplicationNotAvailableException)
              runOnUiThread {
                if (openPgpAppMissingDialog == null)
                  openPgpAppMissingDialog =
                    MaterialAlertDialogBuilder(this)
                      .setTitle(R.string.pgp_key_manager_missing_openpgp_capability_warning_title)
                      .setMessage(
                        R.string.pgp_key_manager_missing_openpgp_capability_warning_message
                      )
                      .setIcon(R.drawable.ic_warning_red_24dp)
                      .setPositiveButton(R.string.dialog_ok, null)
                      .create()
                openPgpAppMissingDialog?.show()
              }
	        else if(e is TagLostException)
              snackbar(message = resources.getString(R.string.pgp_key_hardware_lost_connection))
            logcat(ERROR) { e.asLog() }
          }
        connectHwDialog?.dismiss()
      }
    }
  }

  private var matchingKeyNotFoundDialog: AlertDialog? = null

  /**
   * Get the KeyId from the connected hardware key, using the encryption key fingerprint it contains
   */
  private fun getKeyIdFromHwKey(openPgpSession: OpenPgpSession) : KeyId? {
    /* Extract the encryption key (DEC) fingerprint (20 bytes) from Application Related
     * Data (tag 0x6E) array. We use tag 0xC4 that preceedes the combined (SIG+DEC+AUT)
     * fingerprints within the app related data array to localise and then slice out the
     * DEC fingerprint.
     */
    val tag0x6EString = openPgpSession.getData(0x6E).toHexString() // Application Related Data
    val tag0xC4String = "c407" + openPgpSession.getData(0xC4).toHexString() // preceeding data
	val leadingRegex = "^6e.*${tag0xC4String}".toRegex()
	val combinedFingerprintsPlus = tag0x6EString.replaceFirst(leadingRegex, "").hexToByteArray()
	require(combinedFingerprintsPlus[0].toUByte().toInt() == 0xC5) // tag ID of combined FPs
    require(combinedFingerprintsPlus[1].toUByte().toInt() >= 60) // length of combined fingerprints subarray
	val fingerPrintBytes = combinedFingerprintsPlus.copyOfRange(2+20, 2+40) // skip SIG fingerprint and drop trailing bytes
	return PGPIdentifier.fromString(fingerPrintBytes.toHexString()) as KeyId
  }

  private fun linkHwKey(identifier: PGPIdentifier, openPgpSession: OpenPgpSession) {
     matchingKeyNotFoundDialog?.dismiss()
     runCatching {
		// extract encryption key identifier from hardware key
        val encKeyId = getKeyIdFromHwKey(openPgpSession) ?: throw NoMatchingKeyException
	    // get public key with matching fingerprint from Passwordstore
        val pgpPublicKey = pgpKeyManager.getKeyById(encKeyId, publicOnly=true).getOrThrow()

	    // get public key from Passwordstore that corresponds to passed-in identifier
        val pgpPublicKeyPassedIn = pgpKeyManager.getKeyById(identifier, publicOnly=true).getOrThrow()

		// make sure they are the same
		if(!pgpPublicKey.contents.contentEquals(pgpPublicKeyPassedIn.contents)) throw NoMatchingKeyException

        val tokenLinkedIds = settings.getStringSet(TOKEN_LINKED_PGP_IDS, setOf<String>())
        settings.edit {
          putStringSet(
            TOKEN_LINKED_PGP_IDS,
            tokenLinkedIds?.plus(encKeyId.toString()) ?: setOf<String>(),
          )
        }
        viewModel.deleteKey(encKeyId)
        viewModel.addKey(pgpPublicKey)
      }
      .onFailure { e ->
        runOnUiThread {
          if (matchingKeyNotFoundDialog == null)
            matchingKeyNotFoundDialog =
              MaterialAlertDialogBuilder(this)
                .setTitle(R.string.pgp_key_manager_no_matching_key_on_token_warning_title)
                .setMessage(R.string.pgp_key_manager_no_matching_key_on_token_warning_message)
                .setIcon(R.drawable.ic_warning_red_24dp)
                .setPositiveButton(R.string.dialog_ok, null)
                .create()
          matchingKeyNotFoundDialog?.show()
        }

        logcat { e.asLog() }
      }
    //runCatching {
    //    val clearText = decryptionTest(openPgpSession)
    //    logcat { "++++++++++++++++++++++++++++++++++:" + clearText }
    //  }
    //  .onFailure { e -> logcat { e.asLog() } }
  }

  private fun askPassphrase(identifier: PGPIdentifier, isError: Boolean = false) {
    if (++retries > MAX_RETRIES) return

    val shortUserId = cryptoRepository.getEmailFromKeyId(identifier) ?: return
    val label = "${resources.getString(R.string.pgp_id_label)} ${shortUserId}"
    val dialog = PasswordDialog.newInstance(label, onCancelFinish = false)
    if (isError) dialog.setError()
    dialog.show(supportFragmentManager, "PASSWORD_DIALOG")
    dialog.setFragmentResultListener(PasswordDialog.PASSWORD_RESULT_KEY) { key, bundle ->
      if (key == PasswordDialog.PASSWORD_RESULT_KEY) {
        val passphrase =
          requireNotNull(bundle.getCharArray(PasswordDialog.PASSWORD_PHRASE_KEY)) {
            "returned passphrase is null"
          }
        lifecycleScope.launch {
          if (cryptoRepository.isPasswordCorrect(identifier, passphrase)) {
            confirmBackupCode(identifier, generateBackupCode())
          } else {
            askPassphrase(identifier, isError = true)
          }
        }
      }
    }
  }

  private fun generateBackupCode(numberOfGroups: Int = 9, digitsPerGroup: Int = 4) =
    List(numberOfGroups) { SecureRandom().nextInt(Math.pow(10.0, 1.0 * digitsPerGroup).toInt()) }
      .map { "$it".padStart(digitsPerGroup, '0') }
      .joinToString(separator = "-")

  private fun confirmBackupCode(identifier: PGPIdentifier, code: String) {
    val dialogView = layoutInflater.inflate(R.layout.dialog_with_ckeckbox, null)
    val checkBox = dialogView.findViewById<CheckBox>(R.id.checkbox)

    val dialog =
      MaterialAlertDialogBuilder(this)
        .setTitle(R.string.pgp_key_backupcode_title)
        .setView(dialogView)
        .setMessage(code)
        .setPositiveButton(R.string.dialog_ok) { _, _ ->
          lifecycleScope.launch { writeBackupFile(identifier, code) }
        }
        .setNegativeButton(R.string.dialog_cancel, null)
        .setCancelable(false)
        .create()

    dialog.setOnShowListener {
      val positiveButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
      positiveButton.isEnabled = false // start disabled
      checkBox.setText(R.string.pgp_key_backupcode_confirmation)
      checkBox.setOnCheckedChangeListener { _, isChecked -> positiveButton.isEnabled = isChecked }
    }

    dialog.show()
  }

  private fun writeBackupFile(identifier: PGPIdentifier, code: String? = null) {
    val keyIdAndContent = run {
      val key = pgpKeyManager.getKeyById(identifier, withArmor = true).unwrap()
      val contents =
        if (code != null) { // encrypt secret keys symmetrically
          val keyContents = ByteArrayOutputStream()
          val result =
            cryptoRepository.encryptSym(
              code.toCharArray(),
              key.contents.inputStream(),
              keyContents,
              withArmor = true,
            )
          if (result.isOk) {
            val encrypted = result.getOrThrow().toByteArray()
            val firstNewline = encrypted.indexOf('\n'.code.toByte())
            val firstLine = encrypted.copyOfRange(0, firstNewline + 1)
            val remainingLines = encrypted.copyOfRange(firstNewline + 1, encrypted.size)
            // OpenKeychain backup format
            firstLine +
              "Passphrase-Format: numeric9x4\n".toByteArray(Charsets.UTF_8) +
              remainingLines
          } else null
        } else {
          KeyUtils.extractPublicKeyData(key)
        }
      pgpKeyManager.getKeyId(key) to contents
    }

    keyNumericId = keyIdAndContent.first?.toString()
    keyContentsWithArmor = keyIdAndContent.second

    if (keyContentsWithArmor != null) {
      val fileName = "keyID-${keyNumericId}." + (code?.let { "sec" } ?: "pub") + ".pgp"
      keyExportAction.launch(fileName)
    } else {
      snackbar(message = resources.getString(R.string.pgp_key_export_failed))
    }
  }

  private fun writeBytesToUri(uri: Uri, source: ByteArray?) {
    runCatching {
        val outputStream = contentResolver.openOutputStream(uri) ?: throw IOException()
        source?.inputStream().use { src -> outputStream.use { dest -> src?.copyTo(dest) } }
      }
      .onSuccess { snackbar(message = resources.getString(R.string.pgp_key_export_succeeded)) }
      .onFailure { e ->
        logcat(ERROR) { e.asLog() }
        snackbar(message = resources.getString(R.string.pgp_key_export_failed))
      }
  }

  companion object {
    const val MAX_RETRIES = 3

    const val EXTRA_SELECTED_KEY = "SELECTED_KEY"
    const val EXTRA_KEY_SELECTION = "KEY_SELECTION_MODE"

    const val PGP_KEY_ADD_REQUEST_KEY = "add_pgp_key"
    const val ACTION_KEY = "action"
    const val ACTION_IMPORT_FILE = "from_file"
    const val ACTION_NEW_PGP_KEY = "generate_new"

    private var selectedIdentifierForLinkHw : PGPIdentifier? = null

    fun newSelectionActivity(context: Context): Intent {
      val intent = Intent(context, PGPKeyListActivity::class.java)
      intent.putExtra(EXTRA_KEY_SELECTION, true)
      return intent
    }
  }
}
