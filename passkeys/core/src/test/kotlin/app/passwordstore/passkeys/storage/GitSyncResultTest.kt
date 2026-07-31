/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GitSyncResultTest {

  @Test
  fun `known unrelated Git changes do not invalidate passkey index`() {
    val result =
      GitSyncResult(
        oldHead = "old",
        newHead = "new",
        worktreeChanged = true,
        conflicts = emptyList(),
        changedPaths = setOf("passwords/example.gpg"),
      )

    assertFalse(result.affectsPasskeys())
  }

  @Test
  fun `changed passkey file affects passkey index`() {
    val result =
      GitSyncResult(
        oldHead = "old",
        newHead = "new",
        worktreeChanged = true,
        conflicts = emptyList(),
        changedPaths = setOf("fido2/example.com/abcd.gpg"),
      )

    assertTrue(result.affectsPasskeys())
  }

  @Test
  fun `gpg id change affects passkey index`() {
    val result =
      GitSyncResult(
        oldHead = "old",
        newHead = "new",
        worktreeChanged = true,
        conflicts = emptyList(),
        changedPaths = setOf(".gpg-id"),
      )

    assertTrue(result.affectsPasskeys())
  }
}
