/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.security

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasskeyConcurrencyLimiterTest {

  @Test
  fun `decryption semaphore limits concurrent decryptions`() = runBlocking {
    val limiter = PasskeyConcurrencyLimiter(maxConcurrentDecryptions = 2)
    var concurrent = 0
    var maxConcurrent = 0

    coroutineScope {
      val jobs =
        (1..5).map {
          async {
            limiter.decryptionSemaphore.acquire()
            try {
              synchronized(this@PasskeyConcurrencyLimiterTest) {
                concurrent++
                if (concurrent > maxConcurrent) maxConcurrent = concurrent
              }
              delay(50)
            } finally {
              synchronized(this@PasskeyConcurrencyLimiterTest) {
                concurrent--
              }
              limiter.decryptionSemaphore.release()
            }
          }
        }
      jobs.awaitAll()
    }

    assertTrue("Max concurrent should be <= 2 but was $maxConcurrent", maxConcurrent <= 2)
  }

  @Test
  fun `DAL fetch semaphore limits concurrent fetches`() = runBlocking {
    val limiter = PasskeyConcurrencyLimiter(maxConcurrentDalFetches = 3)
    var concurrent = 0
    var maxConcurrent = 0

    coroutineScope {
      val jobs =
        (1..8).map {
          async {
            limiter.dalFetchSemaphore.acquire()
            try {
              synchronized(this@PasskeyConcurrencyLimiterTest) {
                concurrent++
                if (concurrent > maxConcurrent) maxConcurrent = concurrent
              }
              delay(30)
            } finally {
              synchronized(this@PasskeyConcurrencyLimiterTest) {
                concurrent--
              }
              limiter.dalFetchSemaphore.release()
            }
          }
        }
      jobs.awaitAll()
    }

    assertTrue("Max concurrent should be <= 3 but was $maxConcurrent", maxConcurrent <= 3)
  }

  @Test
  fun `index rebuild semaphore serializes rebuilds`() = runBlocking {
    val limiter = PasskeyConcurrencyLimiter(maxConcurrentIndexRebuilds = 1)
    var concurrent = 0
    var maxConcurrent = 0

    coroutineScope {
      val jobs =
        (1..3).map {
          async {
            limiter.indexRebuildSemaphore.acquire()
            try {
              synchronized(this@PasskeyConcurrencyLimiterTest) {
                concurrent++
                if (concurrent > maxConcurrent) maxConcurrent = concurrent
              }
              delay(30)
            } finally {
              synchronized(this@PasskeyConcurrencyLimiterTest) {
                concurrent--
              }
              limiter.indexRebuildSemaphore.release()
            }
          }
        }
      jobs.awaitAll()
    }

    assertEquals(1, maxConcurrent)
  }

  @Test
  fun `custom concurrency limits are accepted`() {
    val limiter =
      PasskeyConcurrencyLimiter(
        maxConcurrentDecryptions = 4,
        maxConcurrentDalFetches = 8,
        maxConcurrentIndexRebuilds = 2,
      )
    assertEquals(4, limiter.maxConcurrentDecryptions)
    assertEquals(8, limiter.maxConcurrentDalFetches)
    assertEquals(2, limiter.maxConcurrentIndexRebuilds)
  }
}
