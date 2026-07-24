/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.security

public class SensitiveChars private constructor(@PublishedApi internal var chars: CharArray?) :
  AutoCloseable {

  @Volatile private var released = false

  public fun chars(): CharArray = chars ?: throw IllegalStateException("Chars have been released")

  public fun isReleased(): Boolean = released

  public inline fun <T> borrow(block: (CharArray) -> T): T {
    val buf = chars ?: throw IllegalStateException("Chars have been released")
    return block(buf)
  }

  public fun release() {
    chars?.fill('\u0000')
    chars = null
    released = true
  }

  override fun close() {
    release()
  }

  override fun toString(): String = "SensitiveChars(<REDACTED>)"

  public companion object {
    public fun wrap(chars: CharArray): SensitiveChars = SensitiveChars(chars)

    public fun copyOf(chars: CharArray): SensitiveChars = SensitiveChars(chars.copyOf())
  }
}

public inline fun <T> CharArray.useSensitiveChars(block: (CharArray) -> T): T {
  try {
    return block(this)
  } finally {
    fill('\u0000')
  }
}

public inline fun <T> CharArray?.useSensitiveCharsOrNull(block: (CharArray) -> T): T? {
  if (this == null) return null
  try {
    return block(this)
  } finally {
    fill('\u0000')
  }
}
