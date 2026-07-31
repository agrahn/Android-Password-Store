/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import com.github.michaelbull.result.Result

public fun interface PasskeyRemoteRefresher {
  public suspend fun refresh(): Result<Unit, Throwable>
}
