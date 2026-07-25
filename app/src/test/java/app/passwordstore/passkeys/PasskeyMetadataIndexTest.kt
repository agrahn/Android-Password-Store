/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkeys

import java.io.File
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class PasskeyMetadataIndexTest {

  @get:Rule val tempFolder = TemporaryFolder()

  private lateinit var indexFile: File
  private lateinit var index: PasskeyMetadataIndex

  @BeforeTest
  fun setup() {
    indexFile = File(tempFolder.root, "passkey-metadata-index.json")
    index = PasskeyMetadataIndex.forTesting(indexFile)
  }

  @AfterTest
  fun tearDown() {
    tempFolder.root.deleteRecursively()
  }

  @Test
  fun `get returns null for missing credential`() {
    assertNull(index.get("missing".toByteArray()))
  }

  @Test
  fun `put and get round-trips correctly`() {
    val credentialId = "cred-1".toByteArray()
    val entry = MetadataEntry(userName = "alice", userDisplayName = "Alice", rpId = "example.com")
    index.put(credentialId, entry)

    val result = index.get(credentialId)
    assertNotNull(result)
    assertEquals("alice", result.userName)
    assertEquals("Alice", result.userDisplayName)
    assertEquals("example.com", result.rpId)
  }

  @Test
  fun `getByRpId returns matching entries`() {
    index.put("cred-1".toByteArray(), MetadataEntry("alice", "Alice", "example.com"))
    index.put("cred-2".toByteArray(), MetadataEntry("bob", "Bob", "example.com"))
    index.put("cred-3".toByteArray(), MetadataEntry("carol", "Carol", "other.com"))

    val results = index.getByRpId("example.com")
    assertEquals(2, results.size)
    val usernames = results.map { it.second.userName }.toSet()
    assertTrue("alice" in usernames)
    assertTrue("bob" in usernames)
  }

  @Test
  fun `getByRpId returns empty for unknown rpId`() {
    index.put("cred-1".toByteArray(), MetadataEntry("alice", "Alice", "example.com"))
    assertTrue(index.getByRpId("unknown.com").isEmpty())
  }

  @Test
  fun `remove deletes entry`() {
    val credentialId = "cred-1".toByteArray()
    index.put(credentialId, MetadataEntry("alice", "Alice", "example.com"))
    assertNotNull(index.get(credentialId))

    index.remove(credentialId)
    assertNull(index.get(credentialId))
  }

  @Test
  fun `clear removes all entries`() {
    index.put("cred-1".toByteArray(), MetadataEntry("alice", "Alice", "example.com"))
    index.put("cred-2".toByteArray(), MetadataEntry("bob", "Bob", "other.com"))

    index.clear()
    assertNull(index.get("cred-1".toByteArray()))
    assertNull(index.get("cred-2".toByteArray()))
  }

  @Test
  fun `hasEntriesForRpId returns correct result`() {
    assertFalse(index.hasEntriesForRpId("example.com"))
    index.put("cred-1".toByteArray(), MetadataEntry("alice", "Alice", "example.com"))
    assertTrue(index.hasEntriesForRpId("example.com"))
    assertFalse(index.hasEntriesForRpId("other.com"))
  }

  @Test
  fun `data persists across instances`() {
    val credentialId = "cred-1".toByteArray()
    index.put(credentialId, MetadataEntry("alice", "Alice", "example.com", createdAt = 12345L))

    val index2 = PasskeyMetadataIndex.forTesting(indexFile)
    val result = index2.get(credentialId)
    assertNotNull(result)
    assertEquals("alice", result.userName)
    assertEquals(12345L, result.createdAt)
  }

  @Test
  fun `put overwrites existing entry`() {
    val credentialId = "cred-1".toByteArray()
    index.put(credentialId, MetadataEntry("alice", "Alice", "example.com"))
    index.put(credentialId, MetadataEntry("alice2", "Alice Updated", "example.com"))

    val result = index.get(credentialId)
    assertNotNull(result)
    assertEquals("alice2", result.userName)
    assertEquals("Alice Updated", result.userDisplayName)
  }
}
