/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.Rule
import org.junit.rules.TemporaryFolder

class PasswordRepositoryTest {
  @get:Rule val tmp = TemporaryFolder()

  @Test
  fun createRepositoryInitsEmptyFolder() {
    val dir = tmp.newFolder()
    PasswordRepository.createRepository(dir)
    assertTrue(File(dir, ".git").isDirectory)
  }

  @Test
  fun createRepositoryInitsMissingFolder() {
    val dir = File(tmp.newFolder(), "store")
    PasswordRepository.createRepository(dir)
    assertTrue(File(dir, ".git").isDirectory)
  }

  @Test
  fun createRepositoryLeavesNonEmptyFolderAlone() {
    val dir = tmp.newFolder()
    File(dir, "a.gpg").writeText("x")
    PasswordRepository.createRepository(dir)
    assertFalse(File(dir, ".git").exists())
    assertEquals("x", File(dir, "a.gpg").readText())
  }
}
