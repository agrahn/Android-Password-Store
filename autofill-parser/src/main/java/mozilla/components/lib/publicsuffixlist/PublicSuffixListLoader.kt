/*
 * SPDX-License-Identifier: (LGPL-3.0-only WITH LGPL-3.0-linking-exception) OR MPL-2.0
 */

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package mozilla.components.lib.publicsuffixlist

import android.content.Context
import java.io.BufferedInputStream
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader

private const val PUBLIC_SUFFIX_LIST_FILE = "publicsuffixes"
private const val PUBLIC_SUFFIX_SIZES_FILE = "sizes"

internal object PublicSuffixListLoader {

  fun load(
    inputStream: BufferedInputStream,
    publicSuffixSize: Int,
    exceptionSize: Int,
  ): PublicSuffixListData =
    inputStream.use { stream ->
      val publicSuffixBytes = stream.readFully(publicSuffixSize)
      val exceptionBytes = stream.readFully(exceptionSize)
      PublicSuffixListData(publicSuffixBytes, exceptionBytes)
    }

  fun load(context: Context): PublicSuffixListData = run {
    val sizesReader =
      BufferedReader(InputStreamReader(context.assets.open(PUBLIC_SUFFIX_SIZES_FILE).buffered()))
    val publicSuffixSize =
      sizesReader.readLine()?.toInt()
        ?: throw IOException("Could not read publicSuffixSize from file")
    val exceptionSize =
      sizesReader.readLine()?.toInt() ?: throw IOException("Could not read exceptionSize from file")
    load(context.assets.open(PUBLIC_SUFFIX_LIST_FILE).buffered(), publicSuffixSize, exceptionSize)
  }
}

@Suppress("MagicNumber")
private fun BufferedInputStream.readInt(): Int {
  return (read() and
    0xff shl
    24 or
    (read() and 0xff shl 16) or
    (read() and 0xff shl 8) or
    (read() and 0xff))
}

private fun BufferedInputStream.readFully(size: Int): ByteArray {
  val bytes = ByteArray(size)

  var offset = 0
  while (offset < size) {
    val read = read(bytes, offset, size - offset)
    if (read == -1) {
      throw IOException("Unexpected end of stream")
    }
    offset += read
  }

  return bytes
}
