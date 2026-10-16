/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo.store

/**
 * Where the password store lives.
 *
 * The mode is a user preference; [StoreBackend] is what actually serves it. [INTERNAL] is the
 * app-private directory, which is git-backed. [SAF] is a folder the user picked with the Storage
 * Access Framework, which jgit cannot open and which is therefore never git-backed.
 */
enum class StoreMode {
  INTERNAL,
  SAF;

  companion object {
    /** Any unrecognised or absent value means [INTERNAL], so a bad pref cannot lock the app out. */
    fun from(value: String?): StoreMode = entries.firstOrNull { it.name == value } ?: INTERNAL
  }
}
