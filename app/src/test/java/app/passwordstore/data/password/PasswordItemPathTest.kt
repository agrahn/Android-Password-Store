/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.password

import app.passwordstore.data.repo.store.StoreNode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The paths a store entry is addressed by.
 *
 * An item used to carry a [java.io.File] and the store root it belonged to; it now carries a
 * [StoreNode] and derives every path from [StoreNode.path]. These are the derivations the list, the
 * search and the intents read, and none of them may consult a filesystem.
 */
class PasswordItemPathTest {

  @Test
  fun fullPathToParentIsTheDirectoryWithATrailingSeparator() {
    assertEquals(
      "work/example.org/",
      item("john.gpg", "work/example.org/john.gpg").fullPathToParent,
    )
    assertEquals("work/", item("john.gpg", "work/john.gpg").fullPathToParent)
    assertEquals("", item("secret.gpg", "secret.gpg").fullPathToParent)
  }

  @Test
  fun longNameIsThePathWithoutTheGpgExtension() {
    assertEquals("work/example.org/john", item("john.gpg", "work/example.org/john.gpg").longName)
    assertEquals("secret", item("secret.gpg", "secret.gpg").longName)
    assertEquals("work/notes.txt", item("notes.txt", "work/notes.txt").longName)
  }

  @Test
  fun nameKeepsItsExtensionAndToStringDropsTheGpgOne() {
    assertEquals("john.gpg", item("john.gpg", "work/john.gpg").name)
    assertEquals("john", item("john.gpg", "work/john.gpg").toString())
    assertEquals("notes.txt", item("notes.txt", "work/notes.txt").toString())
  }

  @Test
  fun identityIsTheStorePathAlone() {
    // Two nodes for the same path are the same entry: an item is not tied to one node instance.
    assertEquals(
      item("john.gpg", "work/john.gpg"),
      PasswordItem.newPassword("john.gpg", FakeStoreNode("john.gpg", "work/john.gpg")),
    )
    assertNotEquals(item("john.gpg", "work/john.gpg"), item("john.gpg", "life/john.gpg"))
  }

  @Test
  fun categoriesSortBeforePasswordsOfTheSameName() {
    val category = PasswordItem.newCategory("example.org", FakeStoreNode("example.org", "work"))
    val password = item("example.org.gpg", "work/example.org.gpg")
    assertTrue(category < password)
    assertTrue(password > category)
  }
}

private fun item(name: String, path: String): PasswordItem =
  PasswordItem.newPassword(name, FakeStoreNode(name, path))

/** A node that refuses every operation; these tests only read the paths derived from [path]. */
private class FakeStoreNode(override val name: String, override val path: String) : StoreNode {

  override val isDirectory: Boolean = false

  override val isFile: Boolean = true

  override fun exists(): Boolean = false

  override fun children(): List<StoreNode> = emptyList()

  override fun parent(): StoreNode? = null

  override fun findChild(name: String): StoreNode? = null

  override fun readLines(): List<String> = emptyList()

  override fun readBytes(): ByteArray = ByteArray(0)

  override fun writeBytes(bytes: ByteArray) = Unit

  override fun writeText(text: String) = Unit

  override fun createFile(name: String): StoreNode = this

  override fun createDirectory(name: String): StoreNode = this

  override fun rename(newName: String) = Unit

  override fun deleteRecursively() = Unit

  override fun walk(include: (StoreNode) -> Boolean): List<StoreNode> = emptyList()
}
