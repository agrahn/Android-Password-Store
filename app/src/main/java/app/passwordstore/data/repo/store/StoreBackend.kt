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
   * Whether git operations are possible against this backend at all.
   *
   * False for a folder store: jgit needs a filesystem path and a Storage Access Framework tree is
   * not one, so no git command can ever run against it.
   */
  val gitCapable: Boolean

  /**
   * Resolves the store-relative [path] to a node. The node is returned whether or not it exists;
   * check [StoreNode.exists] to find out.
   *
   * An empty path resolves to [root].
   */
  fun resolve(path: String): StoreNode

  /**
   * Forgets every view of the store this backend has cached, so the next read comes from the store
   * itself.
   *
   * A backend that reads the store directly has nothing to forget. A backend whose reads are
   * questions to another process has to be told, because nothing reports a store that another
   * program changed.
   */
  fun invalidate()

  /**
   * Whether the store root contains a `.git` directory.
   *
   * This is detection only: it never means the app can use that repository. jgit cannot open a
   * Storage Access Framework tree, so a `.git` inside a SAF store is never read or written. It
   * exists to tell a user that no commit will be created when they save into such a store.
   */
  fun hasGitDir(): Boolean
}
