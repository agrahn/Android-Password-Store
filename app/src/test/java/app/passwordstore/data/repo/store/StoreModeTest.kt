/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo.store

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The store mode preference decides which backend serves the store.
 *
 * [StoreMode.from] is the only reader of that preference, and it has to answer for every value the
 * pref can hold, including ones no build of this app ever wrote into it.
 */
class StoreModeTest {

  @Test
  fun knownNamesMapToTheirMode() {
    assertEquals(StoreMode.SAF, StoreMode.from(StoreMode.SAF.name))
    assertEquals(StoreMode.INTERNAL, StoreMode.from(StoreMode.INTERNAL.name))
  }

  @Test
  fun absentValueMeansInternal() {
    assertEquals(StoreMode.INTERNAL, StoreMode.from(null))
  }

  @Test
  fun unknownValueMeansInternal() {
    // A bad pref must not lock the app out of a store: the app-private one always opens.
    assertEquals(StoreMode.INTERNAL, StoreMode.from(""))
    assertEquals(StoreMode.INTERNAL, StoreMode.from("FOLDER"))
  }

  @Test
  fun nameMatchIsCaseSensitive() {
    // Pinned, not endorsed: a pref written by hand in lower case falls back to the app-private
    // store, so a user who hand-edits it back to "SAF" gets the picked folder again.
    assertEquals(StoreMode.INTERNAL, StoreMode.from("saf"))
  }
}
