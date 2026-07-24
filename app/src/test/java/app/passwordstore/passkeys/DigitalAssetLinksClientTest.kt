/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.passkeys.crypto.AssetLinkCapability
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json

class DigitalAssetLinksClientTest {

  private val passkeyRelation = "delegate_permission/common.handle_all_urls"
  private val loginRelation = "delegate_permission/common.get_login_creds"
  private val testPackage = "com.github.android"
  private val testFingerprint =
    "DF:08:C9:F2:D8:09:18:9D:9D:50:64:97:C1:57:45:A7:39:5A:41:53:6E:FB:43:3E:3A:EE:1A:ED:BE:11:B2:61"
  private val testDigest: String =
    Base64.getUrlEncoder()
      .withoutPadding()
      .encodeToString(testFingerprint.split(':').map { it.toInt(16).toByte() }.toByteArray())

  @Test
  fun `parses standard Android app asset link fields`() {
    val statements =
      Json.decodeFromString<List<AssetLinkStatement>>(
        """
        [{
          "relation": ["delegate_permission/common.handle_all_urls"],
          "target": {
            "namespace": "android_app",
            "package_name": "com.github.android",
            "sha256_cert_fingerprints": [
              "DF:08:C9:F2:D8:09:18:9D:9D:50:64:97:C1:57:45:A7:39:5A:41:53:6E:FB:43:3E:3A:EE:1A:ED:BE:11:B2:61"
            ]
          }
        }]
        """
      )

    assertEquals(
      listOf("delegate_permission/common.handle_all_urls"),
      statements.single().relation,
    )
    assertEquals("com.github.android", statements.single().target?.packageName)
    assertEquals(1, statements.single().target?.sha256CertFingerprints?.size)
    val stmt = statements.single()
    assertTrue(
      stmt.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    )
    assertFalse(
      stmt.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        "com.attacker.app",
        setOf(testDigest),
      )
    )
    assertFalse(
      stmt.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf("not-a-digest"),
      )
    )
  }

  @Test
  fun `rejects nonstandard relation names`() {
    val statement =
      AssetLinkStatement(
        relation = listOf("delegate_permission/common_get_login_creds"),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = "com.github.android",
            sha256CertFingerprints = listOf("AA:BB"),
          ),
      )

    assertFalse(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        "com.github.android",
        setOf("qrs"),
      )
    )
  }

  @Test
  fun `handle_all_urls authorizes passkey ceremony`() {
    val statement =
      AssetLinkStatement(
        relation = listOf(passkeyRelation),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = testPackage,
            sha256CertFingerprints = listOf(testFingerprint),
          ),
      )
    assertTrue(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    )
  }

  @Test
  fun `get_login_creds alone rejected for passkey ceremony`() {
    val statement =
      AssetLinkStatement(
        relation = listOf(loginRelation),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = testPackage,
            sha256CertFingerprints = listOf(testFingerprint),
          ),
      )
    assertFalse(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    )
  }

  @Test
  fun `get_login_creds authorizes login credential access`() {
    val statement =
      AssetLinkStatement(
        relation = listOf(loginRelation),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = testPackage,
            sha256CertFingerprints = listOf(testFingerprint),
          ),
      )
    assertTrue(
      statement.authorizesAndroidApp(
        AssetLinkCapability.LOGIN_CREDENTIAL_ACCESS,
        testPackage,
        setOf(testDigest),
      )
    )
  }

  @Test
  fun `both relations authorizes passkey ceremony`() {
    val statement =
      AssetLinkStatement(
        relation = listOf(passkeyRelation, loginRelation),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = testPackage,
            sha256CertFingerprints = listOf(testFingerprint),
          ),
      )
    assertTrue(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    )
  }

  @Test
  fun `correct relation but wrong package rejected`() {
    val statement =
      AssetLinkStatement(
        relation = listOf(passkeyRelation),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = "com.other.app",
            sha256CertFingerprints = listOf(testFingerprint),
          ),
      )
    assertFalse(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    )
  }

  @Test
  fun `correct relation and package but wrong certificate rejected`() {
    val statement =
      AssetLinkStatement(
        relation = listOf(passkeyRelation),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = testPackage,
            sha256CertFingerprints = listOf("AA:BB:CC:DD"),
          ),
      )
    assertFalse(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    )
  }

  @Test
  fun `correct target under different statement only accepted when all fields match`() {
    val wrongStatement =
      AssetLinkStatement(
        relation = listOf(loginRelation),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = testPackage,
            sha256CertFingerprints = listOf(testFingerprint),
          ),
      )
    val rightStatement =
      AssetLinkStatement(
        relation = listOf(passkeyRelation),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = testPackage,
            sha256CertFingerprints = listOf(testFingerprint),
          ),
      )
    val statements = listOf(wrongStatement, rightStatement)
    val matched = statements.any {
      it.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    }
    assertTrue(matched)
  }

  @Test
  fun `nonstandard underscore relation name rejected`() {
    val statement =
      AssetLinkStatement(
        relation = listOf("delegate_permission/common_handle_all_urls"),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = testPackage,
            sha256CertFingerprints = listOf(testFingerprint),
          ),
      )
    assertFalse(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    )
  }

  @Test
  fun `empty relation list rejected`() {
    val statement =
      AssetLinkStatement(
        relation = emptyList(),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = testPackage,
            sha256CertFingerprints = listOf(testFingerprint),
          ),
      )
    assertFalse(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    )
  }

  @Test
  fun `null relation list rejected`() {
    val statement =
      AssetLinkStatement(
        relation = null,
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = testPackage,
            sha256CertFingerprints = listOf(testFingerprint),
          ),
      )
    assertFalse(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    )
  }

  @Test
  fun `relation in web namespace target rejected`() {
    val statement =
      AssetLinkStatement(
        relation = listOf(passkeyRelation),
        target =
          AssetLinkTarget(
            namespace = "web",
            site = "https://example.com",
            packageName = testPackage,
            sha256CertFingerprints = listOf(testFingerprint),
          ),
      )
    assertFalse(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    )
  }

  @Test
  fun `cached login credential access cannot authorize passkey ceremony`() {
    val cache = AssetLinkCache(maxEntries = 64, ttlMs = 5 * 60 * 1_000L)
    val loginKey =
      AssetLinkCacheKey(
        "example.com",
        testPackage,
        setOf(testDigest),
        AssetLinkCapability.LOGIN_CREDENTIAL_ACCESS,
      )
    val passkeyKey =
      AssetLinkCacheKey(
        "example.com",
        testPackage,
        setOf(testDigest),
        AssetLinkCapability.PASSKEY_CEREMONY,
      )
    cache.put(loginKey)
    assertTrue(cache.get(loginKey))
    assertFalse(cache.get(passkeyKey))
  }

  @Test
  fun `certificate rotation with either valid fingerprint accepted`() {
    val oldFingerprint =
      "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
    val statement =
      AssetLinkStatement(
        relation = listOf(passkeyRelation),
        target =
          AssetLinkTarget(
            namespace = "android_app",
            packageName = testPackage,
            sha256CertFingerprints = listOf(testFingerprint, oldFingerprint),
          ),
      )
    val oldDigest =
      Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(oldFingerprint.split(':').map { it.toInt(16).toByte() }.toByteArray())
    assertTrue(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(testDigest),
      )
    )
    assertTrue(
      statement.authorizesAndroidApp(
        AssetLinkCapability.PASSKEY_CEREMONY,
        testPackage,
        setOf(oldDigest),
      )
    )
  }

  @Test
  fun `AssetLinkCapability maps to correct relations`() {
    assertEquals(passkeyRelation, AssetLinkCapability.PASSKEY_CEREMONY.requiredRelation)
    assertEquals(loginRelation, AssetLinkCapability.LOGIN_CREDENTIAL_ACCESS.requiredRelation)
  }

  @Test
  fun `AssetLinkCapability has exactly two values`() {
    assertEquals(2, AssetLinkCapability.entries.size)
  }
}
