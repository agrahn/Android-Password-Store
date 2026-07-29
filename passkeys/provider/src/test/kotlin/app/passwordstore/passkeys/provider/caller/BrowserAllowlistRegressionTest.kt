/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.provider.caller

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class BrowserAllowlistRegressionTest {

  @Test
  fun `Firefox release pin matches Google privileged app allowlist`() {
    val entry =
      BrowserAllowlist.DEFAULT_ALLOWLIST.single { it.packageName == "org.mozilla.firefox" }

    assertEquals(
      setOf("A78B62A5165B4494B2FEAD9E76A280D22D937FEE6251AECE599446B2EA319B04"),
      entry.signingCertificateDigestSha256,
    )
    assertTrue(
      BrowserAllowlist.isCertificateAcceptedHex(
        entry,
        "a78b62a5165b4494b2fead9e76a280d22d937fee6251aece599446b2ea319b04",
      )
    )
  }

  @Test
  fun `Firefox and Fenix keep their distinct release pins`() {
    val firefox =
      BrowserAllowlist.DEFAULT_ALLOWLIST.single { it.packageName == "org.mozilla.firefox" }
    val fenix = BrowserAllowlist.DEFAULT_ALLOWLIST.single { it.packageName == "org.mozilla.fenix" }

    assertNotEquals(firefox.signingCertificateDigestSha256, fenix.signingCertificateDigestSha256)
  }
}
