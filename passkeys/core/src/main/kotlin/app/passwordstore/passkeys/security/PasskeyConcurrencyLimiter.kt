/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.security

import kotlinx.coroutines.sync.Semaphore

public class PasskeyConcurrencyLimiter(
  public val maxConcurrentDecryptions: Int = 2,
  public val maxConcurrentDalFetches: Int = 4,
  public val maxConcurrentIndexRebuilds: Int = 1,
) {
  public val decryptionSemaphore: Semaphore = Semaphore(maxConcurrentDecryptions)
  public val dalFetchSemaphore: Semaphore = Semaphore(maxConcurrentDalFetches)
  public val indexRebuildSemaphore: Semaphore = Semaphore(maxConcurrentIndexRebuilds)

  public companion object {
    public val DEFAULT: PasskeyConcurrencyLimiter = PasskeyConcurrencyLimiter()
  }
}
