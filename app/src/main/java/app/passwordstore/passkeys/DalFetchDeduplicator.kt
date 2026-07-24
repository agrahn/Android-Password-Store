/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal class DalFetchDeduplicator {

  private val inFlight = ConcurrentHashMap<String, Mutex>()

  suspend fun <V> deduplicate(key: String, block: suspend () -> V): V {
    val mutex = inFlight.computeIfAbsent(key) { Mutex() }
    mutex.withLock {
      return block()
    }
  }

  fun clear() {
    inFlight.clear()
  }
}
