/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.git

import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

class GitOperationCoordinatorTest {

  @Test
  fun `serializes concurrent git operations`() = runBlocking {
    val firstEntered = CompletableDeferred<Unit>()
    val releaseFirst = CompletableDeferred<Unit>()
    val secondStarted = CompletableDeferred<Unit>()
    val secondEntered = AtomicBoolean(false)

    val first =
      launch(Dispatchers.Default) {
        GitOperationCoordinator.withLock {
          firstEntered.complete(Unit)
          releaseFirst.await()
        }
      }

    firstEntered.await()

    val second =
      launch(Dispatchers.Default) {
        secondStarted.complete(Unit)
        GitOperationCoordinator.withLock { secondEntered.set(true) }
      }

    secondStarted.await()
    assertFalse(secondEntered.get())

    releaseFirst.complete(Unit)
    withTimeout(1_000) { joinAll(first, second) }
    assertTrue(secondEntered.get())
  }

  @Test
  fun `releases lock when operation fails`() = runBlocking {
    try {
      GitOperationCoordinator.withLock<Unit> { error("boom") }
    } catch (_: IllegalStateException) {}

    var entered = false
    withTimeout(1_000) { GitOperationCoordinator.withLock { entered = true } }
    assertTrue(entered)
  }
}
