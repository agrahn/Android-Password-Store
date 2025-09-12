/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

/** [CryptoOptions] implementation for PGPainless decrypt operations. */
public class PGPDecryptOptions private constructor(private val values: Map<String, Boolean>) :
  CryptoOptions {

  internal companion object {
    const val WITH_SESSION_KEY = "WITH_SESSION_KEY"
  }

  override fun isOptionEnabled(option: String): Boolean {
    return values.getOrDefault(option, false)
  }

  /** Implementation of a builder pattern for [PGPDecryptOptions]. */
  public class Builder {
    private val optionsMap = mutableMapOf<String, Boolean>()

    /**
     * Toggle whether the decryption operation treats the passed-in PGPKey as a
     * session key for symmetric decryption.
     */
    public fun withSessionKey(withSessionKey: Boolean): Builder {
      optionsMap[WITH_SESSION_KEY] = withSessionKey
      return this
    }

    /** Build the final [PGPDecryptOptions] object. */
    public fun build(): PGPDecryptOptions {
      return PGPDecryptOptions(optionsMap)
    }
  }
}
