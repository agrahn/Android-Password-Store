/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The store paths every list row, autofill match and intent is built from.
 *
 * These helpers used to do arithmetic on absolute filesystem paths. They now normalise a
 * store-relative path, which is the only form a folder store has, so the cases below are the
 * contract the rest of the app reads its paths with.
 */
class PasswordRepositoryPathTest {

  @Test
  fun emptyRelativePathIsTheStoreRoot() {
    assertEquals("", PasswordRepository.getRelativePath(""))
    assertEquals("", PasswordRepository.getRelativePath("/"))
    assertEquals("", PasswordRepository.getRelativePath("."))
  }

  @Test
  fun relativePathCollapsesSeparatorsAndTrimsTheEnds() {
    assertEquals("work/example.org", PasswordRepository.getRelativePath("work//example.org"))
    assertEquals("work/example.org", PasswordRepository.getRelativePath("/work/example.org/"))
  }

  @Test
  fun aLeadingDotSegmentSurvives() {
    // Pinned, not endorsed: only a path that is exactly "." answers the store root, so a caller
    // passing "./work" gets "./work" back, which is not the form the documentation above promises.
    // It is harmless for lookups — every backend normalises the path again when it resolves the
    // node — and it is a display path everywhere else, so it stays as it is.
    assertEquals("", PasswordRepository.getRelativePath("."))
    assertEquals("./work/example.org", PasswordRepository.getRelativePath("./work/example.org"))
  }

  @Test
  fun longNameDropsTheGpgExtensionOnly() {
    assertEquals(
      "work/example.org/john",
      PasswordRepository.getLongName("work/example.org/john.gpg"),
    )
    assertEquals("secret", PasswordRepository.getLongName("secret.gpg"))
    assertEquals("work/notes.txt", PasswordRepository.getLongName("work/notes.txt"))
  }

  @Test
  fun parentPathKeepsASeparatorAndIsEmptyAtTheRoot() {
    assertEquals(
      "work/example.org/",
      PasswordRepository.getParentPath("work/example.org/john.gpg"),
    )
    assertEquals("", PasswordRepository.getParentPath("secret.gpg"))
    assertEquals("", PasswordRepository.getParentPath("/secret.gpg"))
  }
}
