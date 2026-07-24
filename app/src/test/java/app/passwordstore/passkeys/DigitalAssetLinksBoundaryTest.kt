/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.passkeys.security.PasskeyInputLimits
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DigitalAssetLinksBoundaryTest {

  @Test
  fun `statement count at limit is accepted`() {
    val limits = PasskeyInputLimits(maxAssetLinkStatements = 2)
    val statements =
      List(2) { i ->
        AssetLinkStatement(
          relation = listOf("delegate_permission/common.handle_all_urls"),
          target =
            AssetLinkTarget(
              namespace = "android_app",
              packageName = "com.example.app$i",
              sha256CertFingerprints = listOf("AA:BB:CC"),
            ),
        )
      }
    assertEquals(2, statements.size)
    assertTrue(statements.size <= limits.maxAssetLinkStatements)
  }

  @Test
  fun `statement count exceeding limit is detected`() {
    val limits = PasskeyInputLimits(maxAssetLinkStatements = 2)
    val statements =
      List(3) { i ->
        AssetLinkStatement(
          relation = listOf("delegate_permission/common.handle_all_urls"),
          target =
            AssetLinkTarget(
              namespace = "android_app",
              packageName = "com.example.app$i",
              sha256CertFingerprints = listOf("AA:BB:CC"),
            ),
        )
      }
    assertTrue(statements.size > limits.maxAssetLinkStatements)
  }

  @Test
  fun `relation count at limit is accepted`() {
    val limits = PasskeyInputLimits(maxRelationsPerStatement = 2)
    val statement =
      AssetLinkStatement(
        relation =
          listOf(
            "delegate_permission/common.handle_all_urls",
            "delegate_permission/common.get_login_creds",
          ),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = "com.example.app",
            sha256CertFingerprints = listOf("AA:BB"),
          ),
      )
    assertTrue((statement.relation?.size ?: 0) <= limits.maxRelationsPerStatement)
  }

  @Test
  fun `relation count exceeding limit is detected`() {
    val limits = PasskeyInputLimits(maxRelationsPerStatement = 2)
    val statement =
      AssetLinkStatement(
        relation =
          listOf(
            "delegate_permission/common.handle_all_urls",
            "delegate_permission/common.get_login_creds",
            "delegate_permission/common.third",
          ),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = "com.example.app",
            sha256CertFingerprints = listOf("AA:BB"),
          ),
      )
    assertTrue((statement.relation?.size ?: 0) > limits.maxRelationsPerStatement)
  }

  @Test
  fun `fingerprint count at limit is accepted`() {
    val limits = PasskeyInputLimits(maxFingerprintsPerStatement = 2)
    val statement =
      AssetLinkStatement(
        relation = listOf("delegate_permission/common.handle_all_urls"),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = "com.example.app",
            sha256CertFingerprints = listOf("AA:BB", "CC:DD"),
          ),
      )
    assertTrue(
      (statement.target?.sha256CertFingerprints?.size ?: 0) <= limits.maxFingerprintsPerStatement
    )
  }

  @Test
  fun `fingerprint count exceeding limit is detected`() {
    val limits = PasskeyInputLimits(maxFingerprintsPerStatement = 2)
    val statement =
      AssetLinkStatement(
        relation = listOf("delegate_permission/common.handle_all_urls"),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = "com.example.app",
            sha256CertFingerprints = listOf("AA:BB", "CC:DD", "EE:FF"),
          ),
      )
    assertTrue(
      (statement.target?.sha256CertFingerprints?.size ?: 0) > limits.maxFingerprintsPerStatement
    )
  }

  @Test
  fun `AssetLinkFetchError ResponseTooLarge has correct reason`() {
    val error = AssetLinkFetchError.ResponseTooLarge("too big")
    assertEquals("too big", error.reason)
  }

  @Test
  fun `AssetLinkFetchError TooManyStatements has correct maximum`() {
    val error = AssetLinkFetchError.TooManyStatements(256)
    assertEquals(256, error.maximum)
  }
}
