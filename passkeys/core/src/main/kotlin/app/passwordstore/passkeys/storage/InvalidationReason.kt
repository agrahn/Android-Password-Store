/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

public enum class InvalidationReason {
  GIT_SYNC_COMPLETED,
  GIT_HEAD_CHANGED,
  LOCAL_SAVE,
  LOCAL_UPDATE,
  LOCAL_DELETE,
  REPOSITORY_REINITIALIZED,
  GPG_ID_CHANGED,
  CLEAR_CREDENTIAL_STATE,
  FILESYSTEM_NOTIFICATION,
  MERGE_CONFLICT,
  EXPLICIT_REQUEST,
  DURABILITY_FAILURE,
}
