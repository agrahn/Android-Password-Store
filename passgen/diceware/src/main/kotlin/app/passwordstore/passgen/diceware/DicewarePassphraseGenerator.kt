/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passgen.diceware

import java.io.InputStream
import java.security.SecureRandom
import java.util.Locale
import javax.inject.Inject

/**
 * Password generator implementing the Diceware passphrase generation mechanism. For detailed
 * information on how this works, see https://theworld.com/~reinhold/diceware.html.
 */
public class DicewarePassphraseGenerator
@Inject
constructor(private val die: Die, wordList: InputStream) {

  private val wordMap = WordListParser.parse(wordList)
  private val random = SecureRandom()

  /** Generates a passphrase with [wordCount] words. */
  public fun generatePassphrase(
    wordCount: Int,
    separator: Char,
    includeNumeral: Boolean,
    capitalise: Boolean,
  ): String {
    return buildString {
      val numeralPos = random.nextInt(wordCount)
      repeat(wordCount) { idx ->
        append(
          wordMap[die.rollMultiple(DIGITS)]?.let {
            if (capitalise)
              it.replaceFirstChar {
                if (it.isLowerCase()) it.titlecase(Locale.getDefault()) else it.toString()
              }
            else it
          } ?: throw NullPointerException()
        )
        if (idx == numeralPos && includeNumeral) append("${random.nextInt(10)}")
        if (idx < wordCount - 1) append(separator)
      }
    }
  }

  private companion object {

    /** Number of digits used by indices in the default wordlist. */
    const val DIGITS: Int = 5
  }
}
