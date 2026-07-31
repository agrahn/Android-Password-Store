/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.git

import kotlinx.coroutines.sync.Mutex

/** Serializes Git operations that mutate the shared password-store repository. */
object GitOperationCoordinator {
  private val mutex = Mutex()

  suspend fun <T> withLock(block: suspend () -> T): T {
    mutex.lock()
    return try {
      block()
    } finally {
      mutex.unlock()
    }
  }
}
