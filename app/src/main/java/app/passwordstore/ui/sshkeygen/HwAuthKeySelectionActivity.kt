/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.sshkeygen

import androidx.appcompat.app.AlertDialog
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.appcompat.app.AppCompatActivity
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.git.sshj.SshKey
import com.github.michaelbull.result.fold
import com.github.michaelbull.result.get
import com.github.michaelbull.result.onFailure
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.ApplicationNotAvailableException
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.OpenPgpSession
import com.yubico.yubikit.core.keys.PublicKeyValues
import com.yubico.yubikit.openpgp.KeyRef

@AndroidEntryPoint // required for dependency injection to work
class HwAuthKeySelectionActivity : AppCompatActivity() {

  lateinit var yubikit: YubiKitManager
  var yubiDevice: YubiKeyDevice? = null

  @Inject lateinit var pgpKeyManager: PGPKeyManager

  private val pgpKeySelectionAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == RESULT_OK) {
        runCatching {
            val data = result.data ?: throw NullPointerException("result data is null")
            val keyId =
              data.getStringExtra(PGPKeyListActivity.EXTRA_SELECTED_KEY)?.let {
                PGPIdentifier.fromString(it)
              } ?: throw NullPointerException("key ID is null")
            val key =
              pgpKeyManager.getKeyById(keyId).get()
                ?: throw NullPointerException("returned key ${keyId} is null")
            SshKey.usePgpAuthKey(key)
          }
          .fold(
            success = {
              setResult(RESULT_OK)
              var dialog = ShowSshKeyFragment()
              dialog.setCancelable(false)
              dialog.show(supportFragmentManager, "public_key")
            },
            failure = { e ->
              e.printStackTrace()
              MaterialAlertDialogBuilder(this)
                .setCancelable(false)
                .setTitle(R.string.error)
                .setMessage(e.message)
                .setPositiveButton(R.string.dialog_ok) { _, _ -> finish() }
                .show()
            },
          )
      } else {
        finish()
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    if (SshKey.exists && SshKey.type != SshKey.Type.ImportedPGP) {
      MaterialAlertDialogBuilder(this).run {
        setCancelable(false)
        setTitle(R.string.ssh_keygen_existing_title)
        setMessage(R.string.ssh_keygen_replace_with_hw_key_message)
        setPositiveButton(R.string.ssh_keygen_replace_with_hw_key) { _, _ -> startYkUsbDiscovery() }
        setNegativeButton(R.string.ssh_keygen_existing_keep) { _, _ ->
          setResult(RESULT_CANCELED)
          finish()
        }
        show()
      }
    } else {
      startYkUsbDiscovery()
    }
  }

  override fun onResume() {
    super.onResume()
    lifecycleScope.launch {
      runCatching {
        yubikit.startNfcDiscovery(NfcConfiguration().timeout(15000), this@PGPKeyListActivity) {
          device ->
          connectHw(device)
          device.remove { snackbar(message = "Device removed") }
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

  private fun startYkUsbDiscovery() {
    yubikit = YubiKitManager(this)
    yubikit.startUsbDiscovery(UsbConfiguration()) { device ->
      yubiDevice = device
      snackbar(message = "Device connected")
      connectHw(device)
      device.setOnClosed { 
          snackbar(message = "Device closed")
          yubiDevice = null
      }
    }
  }

  private var openPgpAppMissingDialog: AlertDialog? = null

  private fun connectHw(device: YubiKeyDevice) {
    device.requestConnection(SmartCardConnection::class.java) { result ->
      openPgpAppMissingDialog?.dismiss()
      if (result.isSuccess) {

        val connection = result.getValue()

        runCatching {
          val openPgpSession = OpenPgpSession(connection)  

          val fingerPrint = openPgpSession.getApplicationRelatedData().getDiscretionary().getFingerprint(KeyRef.SIG) ?:
            throw NullPointerException("Hardware key does not provide a signing key")
          val keyId = PGPIdentifier.fromString(fingerPrint.toHexString()) as KeyId

          val pubKey = openPgpSession.getPublicKey(KeyRef.SIG).toPublicKey()

          SshKey.useHwKey(pubKey, keyId)
        }
        .fold(
          success = {
            setResult(RESULT_OK)
            var dialog = ShowSshKeyFragment()
            dialog.setCancelable(false)
            dialog.show(supportFragmentManager, "public_key")
          },
          failure = { e ->
            e.printStackTrace()
            MaterialAlertDialogBuilder(this)
              .setCancelable(false)
              .setTitle(R.string.error)
              .setMessage(e.message)
              .setPositiveButton(R.string.dialog_ok) { _, _ -> finish() }
              .show()
          },
        )
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
            else if (e is TagLostException)
              snackbar(message = resources.getString(R.string.pgp_key_hardware_lost_connection))
            logcat(ERROR) { e.asLog() }
          }
        connectHwDialog?.dismiss()
      }
    }
  }

}
