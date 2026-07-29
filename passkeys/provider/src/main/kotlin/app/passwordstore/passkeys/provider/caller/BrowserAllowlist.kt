/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.provider.caller

import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

public data class TrustedBrowserEntry(
  val packageName: String,
  val signingCertificateDigestSha256: Set<String>,
)

public object BrowserAllowlist {

  public val DEFAULT_ALLOWLIST: List<TrustedBrowserEntry> =
    listOf(
      TrustedBrowserEntry(
        packageName = "com.android.chrome",
        signingCertificateDigestSha256 =
          setOf("F0FD6C5B410F25CB25C3B53346C8972FAE30F8EE7411DF910480AD6B2D60DB83"),
      ),
      TrustedBrowserEntry(
        packageName = "org.mozilla.fenix",
        signingCertificateDigestSha256 =
          setOf("5004779088E7F988D5BC5CC5F8798FEBF4F8CD084A1B2A46EFD4C8EE4AEAF211"),
      ),
      TrustedBrowserEntry(
        packageName = "org.mozilla.firefox",
        signingCertificateDigestSha256 =
          setOf("A78B62A5165B4494B2FEAD9E76A280D22D937FEE6251AECE599446B2EA319B04"),
      ),
    )

  public fun findEntry(
    allowlist: List<TrustedBrowserEntry>,
    packageName: String,
  ): TrustedBrowserEntry? {
    return allowlist.firstOrNull { it.packageName == packageName }
  }

  public fun isCertificateAccepted(
    entry: TrustedBrowserEntry,
    certificateDigestSha256: String,
  ): Boolean {
    return entry.signingCertificateDigestSha256.any { pinned ->
      pinned.equals(certificateDigestSha256, ignoreCase = true)
    }
  }

  public fun isCertificateAcceptedHex(
    entry: TrustedBrowserEntry,
    hexDigest: String,
  ): Boolean {
    return entry.signingCertificateDigestSha256.any { pinned ->
      pinned.replace(":", "").lowercase() == hexDigest.lowercase()
    }
  }

  public fun toPrivilegedAllowlistJson(entry: TrustedBrowserEntry): String = buildJsonObject {
    putJsonArray("apps") {
      add(
        buildJsonObject {
          put("type", "android")
          putJsonObject("info") {
            put("package_name", entry.packageName)
            putJsonArray("signatures") {
              entry.signingCertificateDigestSha256.forEach { digest ->
                add(
                  buildJsonObject {
                    put("build", "release")
                    put(
                      "cert_fingerprint_sha256",
                      digest.replace(":", "").chunked(2).joinToString(":"),
                    )
                  }
                )
              }
            }
          }
        }
      )
    }
  }
    .toString()
}
