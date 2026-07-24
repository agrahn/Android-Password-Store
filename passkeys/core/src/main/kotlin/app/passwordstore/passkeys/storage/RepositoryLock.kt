/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull

public class RepositoryLock {

  private val writeMutex = Mutex()
  private val readCountMutex = Mutex()
  @Volatile private var activeReaders = 0
  @Volatile private var writeLocked = false

  public suspend fun <T> withReadLock(timeoutMs: Long = 10_000L, block: suspend () -> T): T? {
    return withTimeoutOrNull(timeoutMs) {
      readCountMutex.withLock {
        while (writeLocked) {
          kotlinx.coroutines.yield()
        }
        activeReaders++
      }
      try {
        block()
      } finally {
        readCountMutex.withLock {
          activeReaders--
        }
      }
    }
  }

  public suspend fun <T> withWriteLock(timeoutMs: Long = 10_000L, block: suspend () -> T): T? {
    return withTimeoutOrNull(timeoutMs) {
      writeMutex.withLock {
        readCountMutex.withLock {
          while (activeReaders > 0) {
            kotlinx.coroutines.yield()
          }
          writeLocked = true
        }
        try {
          block()
        } finally {
          readCountMutex.withLock {
            writeLocked = false
          }
        }
      }
    }
  }
}
