/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo.store

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The rule that decides whether the user is warned that saving will not create a git commit.
 *
 * A folder store that contains a `.git` is the only case: the app cannot commit there, and a user
 * who syncs that folder from a computer would otherwise expect a commit. Everything else is silent.
 */
class NeedsCommitWarningTest {

  @Test
  fun folderWithGitMetadataWarns() {
    assertTrue(FakeBackend(gitCapable = false, hasGit = true).needsCommitWarning())
  }

  @Test
  fun folderWithoutGitMetadataIsSilent() {
    assertFalse(FakeBackend(gitCapable = false, hasGit = false).needsCommitWarning())
  }

  @Test
  fun gitCapableStoreNeverWarns() {
    assertFalse(FakeBackend(gitCapable = true, hasGit = true).needsCommitWarning())
  }

  @Test
  fun gitCapableStoreWithoutRepositoryIsSilent() {
    assertFalse(FakeBackend(gitCapable = true, hasGit = false).needsCommitWarning())
  }

  private class FakeBackend(override val gitCapable: Boolean, private val hasGit: Boolean) :
    StoreBackend {

    override val root: StoreNode =
      object : StoreNode by UnsupportedNode() {
        override val path: String = ""
      }

    override fun resolve(path: String): StoreNode = root

    override fun invalidate() = Unit

    override fun hasGitDir(): Boolean = hasGit
  }

  /** A node that refuses every operation; these tests only look at the backend predicate. */
  private class UnsupportedNode : StoreNode {
    override val name: String = ""
    override val path: String = ""
    override val isDirectory: Boolean = false
    override val isFile: Boolean = false

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
}
