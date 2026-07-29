/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class RecipientPolicyErrorMappingTest {

  @Test
  fun `missing recipient preserves identifier for actionable UI`() {
    val identifier = "4d15c881d2257a11"

    val exception =
      recipientPolicyErrorToException(RecipientPolicyError.RecipientNotFound(identifier))

    assertIs<MissingRecipientKeyException>(exception)
    assertEquals(identifier, exception.identifier)
  }
}
