/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo.store

/**
 * Provides access to the password store wherever it happens to live.
 *
 * The backend is the single source of truth for the location of the store. Nothing else in the app
 * may decide where the store is; callers ask [root] or [resolve] instead.
 */
interface StoreBackend {

  /** The root of the store. Its [StoreNode.path] is always the empty string. */
  val root: StoreNode

  /**
   * Resolves the store-relative [path] to a node. The node is returned whether or not it exists;
   * check [StoreNode.exists] to find out.
   *
   * An empty path resolves to [root].
   */
  fun resolve(path: String): StoreNode
}
