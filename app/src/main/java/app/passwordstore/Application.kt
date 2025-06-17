/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore

// import androidx.appcompat.app.AppCompatDelegate
import android.app.Activity
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.os.StrictMode
import android.view.View
import android.view.WindowInsetsController
import androidx.appcompat.app.AppCompatDelegate.*
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.injection.context.FilesDirPath
import app.passwordstore.injection.prefs.SettingsPreferences
import app.passwordstore.ui.crypto.BasePGPActivity.Companion.cachedPassphrases
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.features.Features
import app.passwordstore.util.git.sshj.setUpBouncyCastleForSshj
import app.passwordstore.util.proxy.ProxyUtils
import app.passwordstore.util.settings.GitSettings
import app.passwordstore.util.settings.PreferenceKeys
import app.passwordstore.util.settings.runMigrations
import com.google.android.material.color.DynamicColors
import dagger.hilt.android.HiltAndroidApp
import java.util.concurrent.Executors
import javax.inject.Inject
import logcat.AndroidLogcatLogger
import logcat.LogPriority.DEBUG
import logcat.LogPriority.VERBOSE
import logcat.LogcatLogger
import logcat.logcat

@Suppress("Unused")
@HiltAndroidApp
class Application : android.app.Application(), SharedPreferences.OnSharedPreferenceChangeListener {

  @Inject @SettingsPreferences lateinit var prefs: SharedPreferences
  @Inject @FilesDirPath lateinit var filesDirPath: String
  @Inject lateinit var dispatcherProvider: DispatcherProvider
  @Inject lateinit var gitSettings: GitSettings
  @Inject lateinit var proxyUtils: ProxyUtils
  @Inject lateinit var features: Features

  override fun onCreate() {
    super.onCreate()
    instance = this
    if (
      BuildConfig.ENABLE_DEBUG_FEATURES ||
        prefs.getBoolean(PreferenceKeys.ENABLE_DEBUG_LOGGING, false)
    ) {
      LogcatLogger.install(AndroidLogcatLogger(DEBUG))
      setVmPolicy()
    }
    prefs.registerOnSharedPreferenceChangeListener(this)
    setNightMode()
    setUpBouncyCastleForSshj()
    runMigrations(filesDirPath, prefs, gitSettings)
    proxyUtils.setDefaultProxy()
    DynamicColors.applyToActivitiesIfAvailable(this)
    setupScreenOffHandler()
    PasswordRepository.gpgidCurPath = PasswordRepository.getRepositoryDirectory()
    PasswordRepository.gpgidChecked = true
    /**
     * This way, when the app is restarted, a new AES key is generated to encrypt the passphrase
     * cached in memory.
     */
    AESEncryption.deleteKey()

    // adjust navigation icons according to current dark/light mode
    registerActivityLifecycleCallbacks(
      object : ActivityLifecycleCallbacks {
        override fun onActivityResumed(activity: Activity) {
          // Determine the desired navigation bar color and icon style
          /* val isNightMode = when (AppCompatDelegate.getDefaultNightMode()) {
              AppCompatDelegate.MODE_NIGHT_YES -> true
              AppCompatDelegate.MODE_NIGHT_NO -> false
              else -> {
                  // Fallback to current configuration if mode is FOLLOW_SYSTEM or UNSPECIFIED
                  val nightModeFlags = activity.resources.configuration.uiMode and
                          android.content.res.Configuration.UI_MODE_NIGHT_MASK
                  nightModeFlags == android.content.res.Configuration.UI_MODE_NIGHT_YES
              }
          } */

          val nightModeFlags =
            activity.resources.configuration.uiMode and
              android.content.res.Configuration.UI_MODE_NIGHT_MASK
          val isNightMode = nightModeFlags == android.content.res.Configuration.UI_MODE_NIGHT_YES

          val useDarkIcons = !isNightMode

          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            activity.window.insetsController?.let { controller ->
              if (useDarkIcons) {
                controller.setSystemBarsAppearance(
                  WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
                  WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
                )
              } else {
                controller.setSystemBarsAppearance(
                  0,
                  WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
                )
              }
            }
          } else {
            @Suppress("DEPRECATION")
            activity.window.decorView.systemUiVisibility =
              if (useDarkIcons) {
                activity.window.decorView.systemUiVisibility or
                  View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
              } else {
                activity.window.decorView.systemUiVisibility and
                  View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR.inv()
              }
          }
        }

        // Required overrides with empty implementations:
        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}

        override fun onActivityStarted(activity: Activity) {}

        override fun onActivityPaused(activity: Activity) {}

        override fun onActivityStopped(activity: Activity) {}

        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}

        override fun onActivityDestroyed(activity: Activity) {}
      }
    )
  }

  private fun setupScreenOffHandler() {
    val screenOffReceiver: BroadcastReceiver =
      object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
          if (intent.action == Intent.ACTION_SCREEN_OFF) {
            cachedPassphrases.values.forEach { it.fill('\u0000') }
            cachedPassphrases.clear()
          }
        }
      }
    val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
    registerReceiver(screenOffReceiver, filter)
  }

  override fun onTerminate() {
    prefs.unregisterOnSharedPreferenceChangeListener(this)
    super.onTerminate()
  }

  override fun onSharedPreferenceChanged(prefs: SharedPreferences, key: String?) {
    if (key == PreferenceKeys.APP_THEME) {
      setNightMode()
    }
  }

  private fun setVmPolicy() {
    val builder =
      StrictMode.VmPolicy.Builder()
        .detectActivityLeaks()
        .detectFileUriExposure()
        .detectLeakedClosableObjects()
        .detectLeakedRegistrationObjects()
        .detectLeakedSqlLiteObjects()

    builder.detectContentUriWithoutPermission()

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      builder.detectCredentialProtectedWhileLocked().detectImplicitDirectBoot()
    }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      builder.detectNonSdkApiUsage()
    }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      builder.detectIncorrectContextUse().detectUnsafeIntentLaunch()
    }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      builder.penaltyListener(Executors.newSingleThreadExecutor()) { violation ->
        logcat(VERBOSE) { violation.stackTraceToString() }
      }
    } else {
      builder.penaltyLog()
    }

    val policy = builder.build()
    StrictMode.setVmPolicy(policy)
  }

  private fun setNightMode() {
    setDefaultNightMode(
      when (prefs.getString(PreferenceKeys.APP_THEME) ?: getString(R.string.app_theme_def)) {
        "light" -> MODE_NIGHT_NO
        "dark" -> MODE_NIGHT_YES
        "follow_system" -> MODE_NIGHT_FOLLOW_SYSTEM
        else -> MODE_NIGHT_AUTO_BATTERY
      }
    )
  }

  companion object {

    lateinit var instance: Application
  }
}
