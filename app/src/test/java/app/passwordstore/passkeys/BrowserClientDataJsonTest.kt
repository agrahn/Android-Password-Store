/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class BrowserClientDataJsonTest {

  @Test
  fun `get assertion includes challenge and correct type`() {
    val result = buildResponseClientDataJson("get", "dGVzdC1jaGFsbGVuZ2U", "https://example.com")
    val json = Json.parseToJsonElement(result.decodeToString()).jsonObject

    assertEquals("webauthn.get", json.getValue("type").jsonPrimitive.content)
    assertEquals("dGVzdC1jaGFsbGVuZ2U", json.getValue("challenge").jsonPrimitive.content)
    assertEquals("https://example.com", json.getValue("origin").jsonPrimitive.content)
    assertEquals(false, json.getValue("crossOrigin").jsonPrimitive.boolean)
  }

  @Test
  fun `create attestation includes challenge and correct type`() {
    val result =
      buildResponseClientDataJson("create", "Y3JlYXRlLWNoYWxsZW5nZQ", "https://rp.example.org")
    val json = Json.parseToJsonElement(result.decodeToString()).jsonObject

    assertEquals("webauthn.create", json.getValue("type").jsonPrimitive.content)
    assertEquals("Y3JlYXRlLWNoYWxsZW5nZQ", json.getValue("challenge").jsonPrimitive.content)
    assertEquals("https://rp.example.org", json.getValue("origin").jsonPrimitive.content)
    assertEquals(false, json.getValue("crossOrigin").jsonPrimitive.boolean)
  }

  @Test
  fun `null challenge omits challenge field`() {
    val result = buildResponseClientDataJson("get", null, "https://example.com")
    val json = Json.parseToJsonElement(result.decodeToString()).jsonObject

    assertEquals("webauthn.get", json.getValue("type").jsonPrimitive.content)
    assertNull(json["challenge"])
    assertEquals("https://example.com", json.getValue("origin").jsonPrimitive.content)
  }

  @Test
  fun `extractChallengeFromRequestJson extracts base64url challenge`() {
    val requestJson =
      """{"rpId":"example.com","challenge":"dGVzdC1jaGFsbGVuZ2U","allowCredentials":[]}"""
    assertEquals("dGVzdC1jaGFsbGVuZ2U", extractChallengeFromRequestJson(requestJson))
  }

  @Test
  fun `extractChallengeFromRequestJson returns null for missing challenge`() {
    val requestJson = """{"rpId":"example.com","allowCredentials":[]}"""
    assertNull(extractChallengeFromRequestJson(requestJson))
  }

  @Test
  fun `extractChallengeFromRequestJson returns null for invalid json`() {
    assertNull(extractChallengeFromRequestJson("not json"))
    assertNull(extractChallengeFromRequestJson(""))
  }

  @Test
  fun `challenge passes through without re-encoding`() {
    val base64UrlChallenge = "abc123-_noPadding"
    val result = buildResponseClientDataJson("get", base64UrlChallenge, "https://example.com")
    val json = Json.parseToJsonElement(result.decodeToString()).jsonObject

    assertEquals(base64UrlChallenge, json.getValue("challenge").jsonPrimitive.content)
  }
}
