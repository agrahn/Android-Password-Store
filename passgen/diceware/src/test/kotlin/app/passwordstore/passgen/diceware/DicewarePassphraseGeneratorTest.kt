/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passgen.diceware

import kotlin.random.Random
import kotlin.test.assertEquals
import org.junit.Test

class DicewarePassphraseGeneratorTest {
  /** Pre-seeded [Random] instance to ensure tests are deterministic. */
  private val random = Random(1_00_000)

  private val intGenerator = RandomIntGenerator { it.random(random) }

  @Test
  fun generatePassphrase() {
    val die = Die(6, intGenerator)

    val generator = DicewarePassphraseGenerator(die, WordListParserTest.getDefaultWordList())

    assertEquals(
      "Salvation_Cozily_Croon_Trustee_Fidgety",
      generator.generatePassphrase(5, '_', false, true),
    )
  }
}
