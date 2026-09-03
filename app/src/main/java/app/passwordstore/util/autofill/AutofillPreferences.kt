/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.autofill

import android.content.Context
import androidx.core.content.edit
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.services.getDefaultUsername
import app.passwordstore.util.settings.DirectoryStructure
import app.passwordstore.util.settings.PreferenceKeys
import com.github.androidpasswordstore.autofillparser.Credentials
import java.io.File

object AutofillPreferences {

  fun directoryStructure(context: Context): DirectoryStructure {
    val value = context.sharedPrefs.getString(PreferenceKeys.DIRECTORY_STRUCTURE)
    return DirectoryStructure.fromValue(value)
  }

  fun strictDomainSearch(context: Context, strict: Boolean? = null): Boolean =
    strict?.also {
      context.sharedPrefs.edit { putBoolean(PreferenceKeys.STRICT_DOMAIN_SEARCH, strict) }
    } ?: context.sharedPrefs.getBoolean(PreferenceKeys.STRICT_DOMAIN_SEARCH, true)

  fun addQuickSelectButton(context: Context, enabled: Boolean? = null): Boolean =
    enabled?.also {
      context.sharedPrefs.edit { putBoolean(PreferenceKeys.DOMAIN_QUICK_SELECT_ADD, enabled) }
    } ?: context.sharedPrefs.getBoolean(PreferenceKeys.DOMAIN_QUICK_SELECT_ADD, true)

  fun removeQuickSelectButtons(context: Context, enabled: Boolean? = null): Boolean =
    enabled?.also {
      context.sharedPrefs.edit { putBoolean(PreferenceKeys.DOMAIN_QUICK_SELECT_REMOVE, enabled) }
    } ?: context.sharedPrefs.getBoolean(PreferenceKeys.DOMAIN_QUICK_SELECT_REMOVE, false)

  fun credentialsFromStoreEntry(
    context: Context,
    file: File,
    entry: PasswordEntry,
    origin: String?,
    directoryStructure: DirectoryStructure,
  ): Credentials {
    // Always give priority to a username stored in the encrypted extras
    val username =
      entry.username
        ?: directoryStructure.getUsernameFor(file, origin)?.toCharArray()
        ?: context.getDefaultUsername()?.toCharArray()
    val totp = if (entry.hasTotp()) entry.currentOtp.value else null
    return Credentials(username, entry.password, totp)
  }
}
