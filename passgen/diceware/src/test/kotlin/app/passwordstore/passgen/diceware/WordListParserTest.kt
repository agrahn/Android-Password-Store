/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passgen.diceware

import java.io.File
import java.io.InputStream
import kotlin.test.Test
import kotlin.test.assertEquals

class WordListParserTest {
  @Test
  fun parseWordList() {
    val stream = "11111\tabcde\n22222\tfghij".byteInputStream()
    val parsedMap = WordListParser.parse(stream)
    assertEquals(2, parsedMap.size)
    assertEquals("abcde", parsedMap[11111])
    assertEquals("fghij", parsedMap[22222])
  }

  @Test
  fun parseDefaultWordList() {
    val wordlist = getDefaultWordList()
    val parsedMap = WordListParser.parse(wordlist)
    assertEquals(7776, parsedMap.size)
    assertEquals("zoom", parsedMap[66666])
    assertEquals("salute", parsedMap[52621])
  }

  companion object {
    fun getDefaultWordList(): InputStream {
      /**
       * load directly from filesystem (AGP 9.5+ does not include src/main/res/raw on the unit test
       * classpath)
       */
      val file = File("src/main/res/raw/diceware_wordlist.txt")
      if (file.exists()) return file.inputStream()

      throw IllegalArgumentException(
        "Could not find diceware_wordlist.txt on the filesystem." +
          "Ensure src/main/res/raw/diceware_wordlist.txt exists."
      )
    }
  }
}
