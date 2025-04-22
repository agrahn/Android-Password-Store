/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package mozilla.components.lib.publicsuffixlist

import java.io.BufferedReader
import java.io.InputStreamReader
import kotlin.test.Test

class PublicSuffixListLoaderTest {
  @Test
  fun testLoadingBundledPublicSuffixList() {
    val sizesReader =
      BufferedReader(
        InputStreamReader(
          requireNotNull(javaClass.classLoader) { "Null classloader????" }
            .getResourceAsStream("sizes")
        )
      )
    val publicSuffixSize = sizesReader.readLine().toInt()
    val exceptionSize = sizesReader.readLine().toInt()
    requireNotNull(javaClass.classLoader) { "Null classloader????" }
      .getResourceAsStream("publicsuffixes")
      .buffered()
      .use { stream -> PublicSuffixListLoader.load(stream, publicSuffixSize, exceptionSize) }
  }
}
