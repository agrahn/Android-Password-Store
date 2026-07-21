/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.crypto

import android.content.SharedPreferences
import androidx.core.content.edit
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.injection.prefs.SettingsPreferences
import javax.inject.Inject
import org.bouncycastle.util.encoders.Hex

class OpenPgpSmartcardStore
@Inject
constructor(@SettingsPreferences private val preferences: SharedPreferences) {

  fun associate(primaryKeyId: PGPIdentifier.KeyId, fingerprints: List<ByteArray>, url: String?) {
    preferences.edit {
      putString(
        fingerprintKey(primaryKeyId),
        fingerprints.joinToString("\n") { Hex.toHexString(it) },
      )
      putString(urlKey(primaryKeyId), url.orEmpty())
    }
  }

  fun hasAssociation(primaryKeyId: PGPIdentifier.KeyId): Boolean =
    !preferences.getString(fingerprintKey(primaryKeyId), null).isNullOrBlank()

  fun getFingerprints(primaryKeyId: PGPIdentifier.KeyId): List<ByteArray> =
    preferences
      .getString(fingerprintKey(primaryKeyId), null)
      ?.lineSequence()
      ?.map { it.trim() }
      ?.filter { it.isNotEmpty() }
      ?.map { Hex.decode(it) }
      ?.toList()
      .orEmpty()

  private fun fingerprintKey(primaryKeyId: PGPIdentifier.KeyId) =
    "$PREFERENCE_PREFIX.${primaryKeyId.id}.fingerprints"

  private fun urlKey(primaryKeyId: PGPIdentifier.KeyId) =
    "$PREFERENCE_PREFIX.${primaryKeyId.id}.url"

  companion object {
    private const val PREFERENCE_PREFIX = "openpgp_smartcard"
  }
}
