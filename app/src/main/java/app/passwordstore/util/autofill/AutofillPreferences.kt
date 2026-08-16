/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.autofill

import android.content.Context
import androidx.core.content.edit
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.repo.PasswordRepository
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

  /**
   * The directory Autofill-saved credentials should be placed under, relative to the repository
   * root. Backed by [PreferenceKeys.AUTOFILL_SAVE_DIRECTORY]; falls back to the repository root
   * itself when unset. This only affects saves made through the Autofill framework (the system
   * "Save to Password Store?" prompt) — it has no effect on entries created from within the app.
   */
  fun saveDirectory(context: Context): File {
    val root = PasswordRepository.getRepositoryDirectory()
    // Drop empty and ".." segments to prevent escaping the repository root.
    val configured =
      context.sharedPrefs
        .getString(PreferenceKeys.AUTOFILL_SAVE_DIRECTORY)
        ?.split('/')
        ?.filter { it.isNotBlank() && it != ".." }
        ?.joinToString("/")
        ?.takeUnless { it.isBlank() }
    return if (configured == null) root else root.resolve(configured)
  }

  fun strictDomainSearch(context: Context): Boolean {
    return context.sharedPrefs.getBoolean(PreferenceKeys.STRICT_DOMAIN_SEARCH, true)
  }

  fun setStrictDomainSearch(context: Context, strict: Boolean) {
    context.sharedPrefs.edit { putBoolean(PreferenceKeys.STRICT_DOMAIN_SEARCH, strict) }
  }

  fun credentialsFromStoreEntry(
    context: Context,
    file: File,
    entry: PasswordEntry,
    directoryStructure: DirectoryStructure,
  ): Credentials {
    // Always give priority to a username stored in the encrypted extras
    val username =
      entry.username
        ?: directoryStructure.getUsernameFor(file)?.toCharArray()
        ?: context.getDefaultUsername()?.toCharArray()
    val totp = if (entry.hasTotp()) entry.currentOtp.value else null
    return Credentials(username, entry.password, totp)
  }
}
