/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.settings

import android.content.SharedPreferences
import android.text.InputType
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.injection.prefs.PGPPassphrases
import app.passwordstore.util.auth.BiometricAuthenticator
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.crypto.AESEncryption.KeyType
import app.passwordstore.util.extensions.persistentPassphrases
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.settings.PreferenceKeys
import de.Maxr1998.modernpreferences.PreferenceScreen
import de.Maxr1998.modernpreferences.helpers.editText
import de.Maxr1998.modernpreferences.helpers.onClick
import de.Maxr1998.modernpreferences.helpers.singleChoice
import de.Maxr1998.modernpreferences.helpers.switch
import de.Maxr1998.modernpreferences.preferences.choice.SelectionItem
import javax.inject.Inject

class PasswordSettings(private val activity: FragmentActivity) : SettingsProvider {

  @PGPPassphrases @Inject lateinit var persistentPassphrases: SharedPreferences

  override fun provideSettings(builder: PreferenceScreen.Builder) {
    builder.apply {
      val values = activity.resources.getStringArray(R.array.pwgen_provider_values)
      val labels = activity.resources.getStringArray(R.array.pwgen_provider_labels)
      val items = values.zip(labels).map { SelectionItem(it.first, it.second, null) }
      singleChoice(PreferenceKeys.PREF_KEY_PWGEN_TYPE, items) {
        initialSelection = "diceware"
        titleRes = R.string.pref_password_generator_type_title
      }
      val canAuthenticate = BiometricAuthenticator.canAuthenticate(activity)
      if (!canAuthenticate) {
        activity.sharedPrefs.edit { putBoolean(PreferenceKeys.UNLOCK_PASSWORDS_WITH_PIN, false) }
      }
      switch(PreferenceKeys.UNLOCK_PASSWORDS_WITH_PIN) {
        titleRes = R.string.unlock_password_with_pin_pref_title
        defaultValue = false
        enabled = canAuthenticate
        summaryRes = R.string.unlock_password_with_pin_pref_summary
        onClick {
          /* Don't allow disabling biom. authentication if AES key has been invalidated.
           * This is to prevent a malicious user from adding their fingerprint unnoticed. */
          if (
            !checked &&
              AESEncryption.getCipher(keyType = KeyType.PERSISTENT_WITH_AUTHENTICATION) == null
          ) {
            checked = true
            activity.sharedPrefs.edit { putBoolean(PreferenceKeys.UNLOCK_PASSWORDS_WITH_PIN, true) }
          } else {
            AESEncryption.deleteKey(keyType = KeyType.PERSISTENT_WITH_AUTHENTICATION)
            activity.persistentPassphrases.edit { clear() }
          }
          false
        }
      }
      switch(PreferenceKeys.SHOW_PASSWORD) {
        titleRes = R.string.show_password_pref_title
        summaryRes = R.string.show_password_pref_summary
        defaultValue = true
      }
      switch(PreferenceKeys.COPY_ON_DECRYPT) {
        titleRes = R.string.pref_copy_title
        summaryRes = R.string.pref_copy_summary
        defaultValue = false
      }
      editText(PreferenceKeys.GENERAL_SHOW_TIME) {
        titleRes = R.string.pref_clipboard_timeout_title
        summaryProvider = { timeout ->
          activity.getString(R.string.pref_clipboard_timeout_summary, timeout ?: "45")
        }
        textInputType = InputType.TYPE_CLASS_NUMBER
      }
      switch(PreferenceKeys.CLEAR_CLIPBOARD_HISTORY) {
        defaultValue = false
        titleRes = R.string.pref_clear_clipboard_title
        summaryRes = R.string.pref_clear_clipboard_summary
      }
    }
  }
}
