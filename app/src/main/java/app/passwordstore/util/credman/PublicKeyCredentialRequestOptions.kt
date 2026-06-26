/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.credman

import app.passwordstore.util.extensions.b64Decode

data class PublicKeyCredentialRequestOptions(
  val allowCredentials: List<PublicKeyCredentialDescriptor> = emptyList(),
  val challenge: String = "",
  val extensions: Map<String, Any> = emptyMap(),
  val hints: List<String> = emptyList(),
  val rpId: String = "",
  val timeout: Long = 0,
  val userVerification: String = "",
) {
  data class PublicKeyCredentialDescriptor(
    val id: String = "",
    val transports: List<String> = emptyList(),
    val type: String = "",
  ) {
    fun idHex(): String? = id.toCharArray().b64Decode()?.toHexString()
  }
}
