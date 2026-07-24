/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public class DurabilityIndeterminateException(
  public val observedVersion: DurableFileVersion? = null,
  message: String = "Durability could not be verified",
) : Exception(message)
