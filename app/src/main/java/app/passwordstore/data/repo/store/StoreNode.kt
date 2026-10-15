/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo.store

/**
 * A single entry of the password store, addressed independently of where the store physically
 * lives.
 *
 * [path] is the store-relative identity of the node: `/`-separated, no leading or trailing
 * separator, `""` for the store root.
 */
interface StoreNode {

  /** File name of this node, without any path component. */
  val name: String

  /** Store-relative path of this node. See the class documentation for the exact format. */
  val path: String

  val isDirectory: Boolean

  val isFile: Boolean

  fun exists(): Boolean

  /**
   * Immediate children of this node, in the order reported by the backing store. Returns an empty
   * list for files and for unreadable directories.
   */
  fun children(): List<StoreNode>

  /** The parent directory of this node, or `null` if this node is the store root. */
  fun parent(): StoreNode?

  /** The child named [name], or `null` if there is no such child. */
  fun findChild(name: String): StoreNode?

  fun readLines(): List<String>

  /** Writes [text] to this node, creating any missing parent directories. */
  fun writeText(text: String)

  fun createFile(name: String): StoreNode

  /**
   * Every node in this subtree that satisfies [include], in depth-first pre-order, starting with
   * this node.
   *
   * This is the single recursive traversal of the store; callers must not implement their own.
   */
  fun walk(include: (StoreNode) -> Boolean): List<StoreNode>
}

/**
 * Whether this node is [root] itself or lives below it.
 *
 * This is a pure path prefix check on store-relative paths. It must not be implemented as a
 * substring match: `/data/store-backup` is not inside `/data/store`.
 */
internal fun StoreNode.isUnder(root: StoreNode): Boolean {
  if (root.path.isEmpty()) return true
  return path == root.path || path.startsWith("${root.path}/")
}

/**
 * The `.gpg-id` file governing this node: the nearest one declared by this directory or one of its
 * ancestors below [root], or `null` if this subtree declares no key.
 */
fun StoreNode.findGpgId(root: StoreNode): StoreNode? {
  var dir: StoreNode? = this
  while (dir != null && dir.isUnder(root)) {
    val gpgId = dir.findChild(GPG_ID)
    if (gpgId != null) return gpgId
    if (dir == root) return null
    dir = dir.parent()
  }
  return null
}

/** Writes [keyId] to the `.gpg-id` file of this directory. */
fun StoreNode.writeGpgId(keyId: String) {
  findChild(GPG_ID)?.writeText("$keyId\n") ?: createFile(GPG_ID).writeText("$keyId\n")
}

/** Name of the file that associates a directory with the PGP keys used for it. */
const val GPG_ID = ".gpg-id"
