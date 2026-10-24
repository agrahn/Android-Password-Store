/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.password

import android.content.Context
import android.content.Intent
import app.passwordstore.data.repo.store.StoreNode
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.ui.main.LaunchActivity

/**
 * One entry of the store: a password, a category, a `.gpg-id` or anything else.
 *
 * An item is identified by its [node], whose [StoreNode.path] is store-relative. Intents built from
 * an item carry that relative path, never an absolute one, so they work for every backend.
 */
data class PasswordItem(
  val name: String,
  val parent: PasswordItem? = null,
  val type: Char,
  val node: StoreNode,
) : Comparable<PasswordItem> {

  /** Store-relative path of the directory holding this item, with a trailing separator. */
  val fullPathToParent: String
    get() = node.path.substringBeforeLast('/', "").let { if (it.isEmpty()) "" else "$it/" }

  /** Store-relative path of this item without its `.gpg` extension. */
  val longName: String
    get() = node.path.removeSuffix(".gpg")

  override fun equals(other: Any?): Boolean {
    return (other is PasswordItem) && (other.node.path == node.path)
  }

  override fun compareTo(other: PasswordItem): Int {
    return (type + name).compareTo(other.type + other.name, ignoreCase = true)
  }

  override fun toString(): String {
    return name.replace("\\.gpg$".toRegex(), "")
  }

  override fun hashCode(): Int {
    return 0
  }

  /** Creates an [Intent] to launch this [PasswordItem] through the authentication process. */
  fun createAuthEnabledIntent(context: Context): Intent {
    val intent = Intent(context, LaunchActivity::class.java)
    intent.putExtra("NAME", toString()) // this.toString
    intent.putExtra(BasePGPActivity.EXTRA_FILE_PATH, node.path)
    intent.putExtra(BasePGPActivity.EXTRA_REPO_PATH, fullPathToParent)
    intent.action = LaunchActivity.ACTION_DECRYPT_PASS
    return intent
  }

  companion object {

    const val TYPE_CATEGORY = 'c'
    const val TYPE_PASSWORD = 'p'
    const val TYPE_GPG_ID = 'g'
    const val TYPE_OTHER = 'o' // unknown type, no effort is made to decrypt or display contents

    @JvmStatic
    fun newCategory(name: String, node: StoreNode, parent: PasswordItem): PasswordItem {
      return PasswordItem(name, parent, TYPE_CATEGORY, node)
    }

    @JvmStatic
    fun newCategory(name: String, node: StoreNode): PasswordItem {
      return PasswordItem(name, null, TYPE_CATEGORY, node)
    }

    @JvmStatic
    fun newPassword(name: String, node: StoreNode, parent: PasswordItem): PasswordItem {
      return PasswordItem(name, parent, TYPE_PASSWORD, node)
    }

    @JvmStatic
    fun newPassword(name: String, node: StoreNode): PasswordItem {
      return PasswordItem(name, null, TYPE_PASSWORD, node)
    }

    @JvmStatic
    fun newGpgIdItem(name: String, node: StoreNode, parent: PasswordItem): PasswordItem {
      return PasswordItem(name, parent, TYPE_GPG_ID, node)
    }

    @JvmStatic
    fun newGpgIdItem(name: String, node: StoreNode): PasswordItem {
      return PasswordItem(name, null, TYPE_GPG_ID, node)
    }

    @JvmStatic
    fun newOtherItem(name: String, node: StoreNode, parent: PasswordItem): PasswordItem {
      return PasswordItem(name, parent, TYPE_OTHER, node)
    }

    @JvmStatic
    fun newOtherItem(name: String, node: StoreNode): PasswordItem {
      return PasswordItem(name, null, TYPE_OTHER, node)
    }
  }
}
