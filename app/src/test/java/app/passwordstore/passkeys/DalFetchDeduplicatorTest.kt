/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DalFetchDeduplicatorTest {

  @Test
  fun `deduplicate serializes calls with same key`() = runBlocking {
    val deduplicator = DalFetchDeduplicator()
    var concurrent = 0
    var maxConcurrent = 0
    val lock = Any()

    coroutineScope {
      val jobs =
        (1..5).map {
          async {
            deduplicator.deduplicate("rp1") {
              synchronized(lock) {
                concurrent++
                if (concurrent > maxConcurrent) maxConcurrent = concurrent
              }
              delay(30)
              synchronized(lock) {
                concurrent--
              }
              "result"
            }
          }
        }
      jobs.awaitAll()
    }

    assertEquals(1, maxConcurrent)
  }

  @Test
  fun `deduplicate allows parallel calls with different keys`() = runBlocking {
    val deduplicator = DalFetchDeduplicator()
    var concurrent = 0
    var maxConcurrent = 0
    val lock = Any()

    coroutineScope {
      val jobs =
        (1..4).map { i ->
          async {
            deduplicator.deduplicate("rp$i") {
              synchronized(lock) {
                concurrent++
                if (concurrent > maxConcurrent) maxConcurrent = concurrent
              }
              delay(50)
              synchronized(lock) {
                concurrent--
              }
              "result-$i"
            }
          }
        }
      jobs.awaitAll()
    }

    assertTrue("Expected some parallelism but max was $maxConcurrent", maxConcurrent > 1)
  }

  @Test
  fun `clear removes all in-flight entries`() = runBlocking {
    val deduplicator = DalFetchDeduplicator()
    deduplicator.deduplicate("rp1") { "result" }
    deduplicator.clear()
    val result = deduplicator.deduplicate("rp1") { "new-result" }
    assertEquals("new-result", result)
  }
}
