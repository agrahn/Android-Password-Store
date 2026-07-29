/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public class MissingRecipientKeyException(public val identifier: String) :
  IllegalStateException("Recipient not found: $identifier")
