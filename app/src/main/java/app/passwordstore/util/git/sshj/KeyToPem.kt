/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */
package app.passwordstore.util.git.sshj

import java.security.PrivateKey
import java.util.Base64

fun pkcs8PemString(priv: PrivateKey): String {
  val b64 = Base64.getEncoder().encodeToString(priv.encoded)
  return buildString {
    append("-----BEGIN PRIVATE KEY-----\n")
    append(b64.chunked(64).joinToString("\n"))
    append("\n-----END PRIVATE KEY-----\n")
  }
}
