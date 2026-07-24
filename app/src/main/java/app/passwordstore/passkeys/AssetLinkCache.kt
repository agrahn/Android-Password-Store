/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import app.passwordstore.passkeys.crypto.AssetLinkCapability
import java.util.concurrent.ConcurrentHashMap

internal data class AssetLinkCacheKey(
  val rpId: String,
  val packageName: String,
  val certDigests: Set<String>,
  val capability: AssetLinkCapability,
)

internal class AssetLinkCache(
  private val maxEntries: Int = 64,
  private val ttlMs: Long = 5 * 60 * 1_000L,
) {

  private val cache = ConcurrentHashMap<AssetLinkCacheKey, Long>()

  fun get(key: AssetLinkCacheKey): Boolean {
    val timestamp = cache[key] ?: return false
    if (System.currentTimeMillis() - timestamp > ttlMs) {
      cache.remove(key)
      return false
    }
    return true
  }

  fun put(key: AssetLinkCacheKey) {
    val now = System.currentTimeMillis()
    if (cache.size >= maxEntries) {
      val expired = cache.entries.filter { now - it.value > ttlMs }.map { it.key }
      expired.forEach { cache.remove(it) }
    }
    cache[key] = now
    if (cache.size > maxEntries) {
      val oldest = cache.minByOrNull { it.value }?.key
      if (oldest != null) cache.remove(oldest)
    }
  }

  fun clear() {
    cache.clear()
  }
}
