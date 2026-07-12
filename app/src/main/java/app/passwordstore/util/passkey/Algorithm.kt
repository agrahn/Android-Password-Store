/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.passkey

enum class Algorithm(val id: Int, val algorithmName: String) {
  EDDSA(-8, "Ed25519"),
  ES256(-7, "ES256"),
  RS256(-257, "RS256");

  fun toLong(): Long = id.toLong()

  override fun toString(): String = "${algorithmName} (${id})"

  companion object {
    private val mapById = entries.associateBy { it.id }
    private val mapByName = entries.associateBy { it.algorithmName.lowercase() }

    fun fromId(id: Int): Algorithm? = mapById[id]

    fun fromName(name: String?): Algorithm? = name?.lowercase()?.let { mapByName[it] }
  }
}
