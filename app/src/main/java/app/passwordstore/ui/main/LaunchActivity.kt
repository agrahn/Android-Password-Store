/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.main

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager.Authenticators
import app.passwordstore.R
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.ui.crypto.DecryptActivity
import app.passwordstore.ui.passwords.PasswordStore
import app.passwordstore.util.auth.BiometricAuthenticator
import app.passwordstore.util.auth.BiometricAuthenticator.Result
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.settings.PreferenceKeys
import com.google.android.material.dialog.MaterialAlertDialogBuilder

@SuppressLint("CustomSplashScreen")
class LaunchActivity : AppCompatActivity() {

  private val enrollFingerprintActivity =
    registerForActivityResult(StartActivityForResult()) { activityResult ->
      if (activityResult.resultCode == RESULT_OK) startTargetActivity(false)
      else finishAndRemoveTask()
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    val prefs = sharedPrefs
    if (prefs.getBoolean(PreferenceKeys.BIOMETRIC_AUTH_2, false)) {
      BiometricAuthenticator.authenticate(this, allowPin = true) { result ->
        when (result) {
          is Result.Success -> {
            startTargetActivity(false)
          }
          is Result.HardwareUnavailableOrDisabled -> {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
              val enrollFingerprintIntent =
                Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                  putExtra(
                    Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                    Authenticators.BIOMETRIC_STRONG,
                  )
                }
              enrollFingerprintActivity.launch(enrollFingerprintIntent)
            } else {
              MaterialAlertDialogBuilder(this)
                .setTitle(getString(R.string.pref_biometric_auth_summary_error))
                .setMessage(getString(R.string.check_devicelock_settings_dialog_message))
                .setPositiveButton(getString(R.string.dialog_ok)) { _, _ -> finishAndRemoveTask() }
                .show()
            }
          }
          is Result.Retry -> {}
          else -> {
            finishAndRemoveTask()
          }
        }
      }
    } else {
      startTargetActivity(true)
    }
  }

  private fun getDecryptIntent(): Intent {
    return Intent(this, DecryptActivity::class.java)
  }

  private fun startTargetActivity(noAuth: Boolean) {
    val intentToStart =
      if (intent.action == ACTION_DECRYPT_PASS)
        getDecryptIntent().apply {
          putExtra(
            BasePGPActivity.EXTRA_FILE_PATH,
            intent.getStringExtra(BasePGPActivity.EXTRA_FILE_PATH),
          )
          putExtra(
            BasePGPActivity.EXTRA_REPO_PATH,
            intent.getStringExtra(BasePGPActivity.EXTRA_REPO_PATH),
          )
        }
      else Intent(this, PasswordStore::class.java).setAction(Intent.ACTION_VIEW)
    startActivity(intentToStart)

    Handler(Looper.getMainLooper()).postDelayed({ finish() }, if (noAuth) 0L else 500L)
  }

  companion object {

    const val ACTION_DECRYPT_PASS = "DECRYPT_PASS"
  }
}
