/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.settings

import androidx.fragment.app.FragmentActivity
import app.passwordstore.BuildConfig
import app.passwordstore.R
import app.passwordstore.util.settings.PreferenceKeys
import de.Maxr1998.modernpreferences.PreferenceScreen
import de.Maxr1998.modernpreferences.helpers.switch

class MiscSettings(private val activity: FragmentActivity) : SettingsProvider {

  override fun provideSettings(builder: PreferenceScreen.Builder) {
    builder.apply {
      switch(PreferenceKeys.ENABLE_DEBUG_LOGGING) {
        defaultValue = false
        titleRes = R.string.pref_debug_logging_title
        summaryRes = R.string.pref_debug_logging_summary
        visible = !BuildConfig.DEBUG
      }
    }
  }
}
