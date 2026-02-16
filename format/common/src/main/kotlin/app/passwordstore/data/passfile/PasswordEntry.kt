/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.data.passfile

import androidx.annotation.VisibleForTesting
import app.passwordstore.util.time.UserClock
import app.passwordstore.util.totp.Otp
import app.passwordstore.util.totp.TotpFinder
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.mapBoth
import dagger.assisted.Assisted
import dagger.assisted.AssistedFactory
import dagger.assisted.AssistedInject
import kotlin.collections.set
import kotlin.coroutines.coroutineContext
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.isActive

/** Represents a single entry in the password store. */
public class PasswordEntry
@AssistedInject
constructor(
  /** A time source used to calculate the TOTP */
  private val clock: UserClock,
  /** [TotpFinder] implementation to extract data from a TOTP URI */
  private val totpFinder: TotpFinder,
  /** The content of this entry, as an array of Chars. */
  @Assisted chars: CharArray,
) {

  /** The password text for this entry. Can be null. */
  public val password: CharArray?

  /** The username for this entry. Can be null. */
  public val username: CharArray?

  /** The username for this entry. Can be null. */
  public lateinit var unsafeKeys: MutableSet<String>

  /** The totp entry extracted from the decrypted password file */
  private val totpString: String

  /** content of [chars] but with passwords and first username stripped. */
  public val extraContentChars: CharArray?

  /** A [String] to [CharArray] [Map] of the extra content of this entry, in a key:value fashion. */
  public val extraContent: Map<String, CharArray>

  /**
   * A [Flow] providing the current TOTP. It will start emitting only when collected. If this entry
   * does not have a TOTP secret, the flow will never emit. Users should call [hasTotp] before
   * collection to check if it is valid to collect this [Flow].
   */
  public val totp: Flow<Totp> = flow {
    require(totpSecret != null) { "Cannot collect this flow without a TOTP secret" }
    do {
      val otp = calculateTotp()
      val otpValue = otp.getOrThrow()
      emit(otpValue)
      delay(THOUSAND_MILLIS.milliseconds)
    } while (coroutineContext.isActive)
  }

  /** Obtain the [Totp.value] for this [PasswordEntry] at the current time. */
  public val currentOtp: Totp
    get() {
      val otp = calculateTotp()
      check(otp.isOk)
      return otp.getOrThrow()
    }

  private val totpSecret: String?

  public fun clear() {
    password?.fill('\u0000')
    username?.fill('\u0000')
    extraContent.values.forEach { it?.fill('\u0000') }
    extraContentChars?.fill('\u0000')
  }

  public fun clearExtra() {
    extraContent.values.forEach { it?.fill('\u0000') }
    extraContentChars?.fill('\u0000')
  }

  public fun clearExtraChars() {
    extraContentChars?.fill('\u0000')
  }

  private val allLines: List<CharArray>

  init {
    allLines = chars.splitToCharArrayListAt('\n')
    val (foundPassword, passContentWithoutPasswords) = findAndStripPassword(allLines)
    password = foundPassword
    val (foundUsername, passContentWithoutPasswordsAndFirstUsername) =
      findAndStripFirstUsername(passContentWithoutPasswords)
    username = foundUsername

    extraContentChars = passContentWithoutPasswordsAndFirstUsername.joinToCharArray('\n')

    val (foundTotp, extraContentWithoutAuthData) =
      findAndStripTotp(passContentWithoutPasswordsAndFirstUsername)
    totpString = foundTotp?.let { String(it) } ?: ""
    foundTotp?.fill('\u0000')

    val (unsafe, extraContentWithoutAuthDataAndUnsafeKeywords) =
      findAndStripUnsafeKeys(extraContentWithoutAuthData)
    unsafeKeys = unsafe

    extraContent = generateExtraContentPairs(extraContentWithoutAuthDataAndUnsafeKeywords)

    allLines.forEach { it?.fill('\u0000') }

    // Verify the TOTP secret is valid and disable TOTP if not.
    val secret = totpFinder.findSecret(totpString)
    totpSecret =
      if (secret != null && calculateTotp(secret).isOk) {
        secret
      } else {
        null
      }
  }

  public fun hasTotp(): Boolean {
    return totpSecret != null
  }

  @Suppress("ReturnCount")
  private fun findAndStripPassword(
    passContent: List<CharArray>
  ): Pair<CharArray?, List<CharArray>> {
    var lines = passContent
    var password: CharArray? = null

    // First line looks like a password
    if (
      !lines[0].isBlank() &&
        !USERNAME_FIELDS.plus(TotpFinder.TOTP_FIELDS).any {
          lines[0].startsWith(it, ignoreCase = true)
        }
    ) {
      password = lines[0].copyOf(lines[0].size)
      lines = lines.minus(lines[0])
      return Pair(password, lines)
    }

    if (lines[0].isBlank()) lines = lines.minus(lines[0])

    for (line in lines) {
      if (line.isBlank()) break // extra content starts
      for (prefix in PASSWORD_FIELDS) {
        if (line.startsWith(prefix, ignoreCase = true)) {
          password = line.copyOfRange(prefix.length, line.size).trimStart()
          lines = lines.minus(line)
          return Pair(password, lines)
        }
      }
    }

    return Pair(null, lines)
  }

  private fun findAndStripFirstUsername(
    passContent: List<CharArray>
  ): Pair<CharArray?, List<CharArray>> {
    var lines = passContent
    var username: CharArray? = null
    for (line in passContent) {
      if (line.isBlank()) break
      for (prefix in USERNAME_FIELDS) {
        if (line.startsWith(prefix, ignoreCase = true)) {
          username = line.copyOfRange(prefix.length, line.size).trimStart()
          lines = lines.minus(line)
          return Pair(username, lines)
        }
      }
    }
    return Pair(null, lines)
  }

  /* gopass-way of declaring sensitive extra-content keys denoting fields that should be displayed
   * as passwords:
   *
   *   unsafe-keys: key_1, key_2, ...
   *
   * such keys are placed in the returned string list */
  private fun findAndStripUnsafeKeys(
    passContent: List<CharArray>
  ): Pair<MutableSet<String>, List<CharArray>> {
    var lines = passContent
    val unsafe = mutableSetOf<String>()
    for (line in passContent) {
      if (line.isBlank()) break
      if (line.startsWith(UNSAFE_KEYS, ignoreCase = true)) {
        unsafe.addAll(
          line.copyOfRange(UNSAFE_KEYS.length, line.size).splitToCharArrayListAt(',').map {
            String(it).trim()
          }
        )
        lines = lines.minus(line)
      }
    }
    return Pair(unsafe, lines)
  }

  private fun findAndStripTotp(passContent: List<CharArray>): Pair<CharArray?, List<CharArray>> {
    var lines = passContent
    var totp: CharArray? = null
    for (line in passContent) {
      for (prefix in TotpFinder.TOTP_FIELDS) {
        if (line.startsWith(prefix, ignoreCase = true)) {
          totp = line // Last wins
          lines = lines.minus(line)
          break
        }
      }
    }
    return Pair(totp, lines)
  }

  private fun generateExtraContentPairs(passContent: List<CharArray>): Map<String, CharArray> {

    fun MutableMap<String, CharArray>.putOrAppend(key: String, value: CharArray) {
      val existing = this[key]
      this[key] =
        if (existing == null) {
          value
        } else {
          charArrayOf(*existing, '\n', *value).also {
            existing.fill('\u0000')
            value.fill('\u0000')
          }
        }
    }

    val items = mutableMapOf<String, CharArray>()
    var extraContentLines = mutableListOf<CharArray>()

    var extraContentStarted = false

    passContent.forEach { line ->
      // Split the line at the first ':' into key and value
      // "ABC : DEF:GHI" --> key = "ABC" value = "DEF:GHI"]
      // Note a valid key must not start with space, otherwise it is considered extra content.
      if (line.contains(':')) {
        val colonIndex = line.indexOf(':')
        val k = line.copyOfRange(0, colonIndex)
        val v =
          if (colonIndex + 2 < line.size) line.copyOfRange(colonIndex + 1, line.size)
          else charArrayOf()
        if (k.isBlank() || k.startsWith(" ") || k.startsWith("\\t") || extraContentStarted)
          extraContentLines.add(line)
        else {
          val kk = String(k).trimEnd()
          val key =
            if (kk.startsWith("*") && kk.endsWith("*")) {
              kk.substring(1, kk.length - 1).let {
                unsafeKeys.add(it)
                it
              }
            } else kk
          items.putOrAppend(key, v.trimStart().trimEnd())
        }
      } else {
        if (line.isBlank()) {
          extraContentStarted = true
          // Skip blank lines until something non-blank has been added to extra content
          if (!extraContentLines.isEmpty()) extraContentLines.add(line)
        } else extraContentLines.add(line)
      }
    }

    // Strip trailing empty lines from extra content
    while (extraContentLines.size > 0 && extraContentLines.last().isEmpty()) extraContentLines
      .removeAt(extraContentLines.size - 1)

    // adjust indent, trim ends
    while (
      !extraContentLines.isEmpty() &&
        (extraContentLines.filter { !it.isBlank() }.all { it.startsWith(" ") } ||
          extraContentLines.filter { !it.isBlank() }.all { it.startsWith("\\t") })
    ) {
      extraContentLines.forEach { l ->
        if (l.size > 1) {
          System.arraycopy(l, 1, l, 0, l.size - 1)
          l[l.size - 1] = ' '
        }
      }
    }
    val extraContentLinesAdjusted = extraContentLines.map { it.trimEnd() }

    // Add extra content as a single item `EXTRA_CONTENT`
    extraContentLinesAdjusted.forEach { items.putOrAppend(EXTRA_CONTENT, it) }

    return items
  }

  private fun calculateTotp(secret: String = totpSecret!!): Result<Totp, Throwable> {
    val digits = totpFinder.findDigits(totpString)
    val totpPeriod = totpFinder.findPeriod(totpString)
    val totpAlgorithm = totpFinder.findAlgorithm(totpString)
    val issuer = totpFinder.findIssuer(totpString)
    val millis = clock.millis()
    val remainingTime = (totpPeriod - ((millis / THOUSAND_MILLIS) % totpPeriod)).seconds
    return Otp.calculateCode(
        secret,
        millis / (THOUSAND_MILLIS * totpPeriod),
        totpAlgorithm,
        digits,
        issuer,
      )
      .mapBoth({ code -> Ok(Totp(code, remainingTime)) }, ::Err)
  }

  @AssistedFactory
  public interface Factory {
    public fun create(chars: CharArray): PasswordEntry
  }

  public companion object {

    public val EXTRA_CONTENT: String = "EXTRA_CONTENT"

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    public val USERNAME_FIELDS: Array<String> =
      arrayOf(
        "login:",
        "username:",
        "user:",
        "account:",
        "email:",
        "mail:",
        "name:",
        "handle:",
        "id:",
        "identity:",
      )

    private val UNSAFE_KEYS: String = "unsafe-keys:"

    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    public val PASSWORD_FIELDS: Array<String> = arrayOf("password:", "secret:", "pass:")

    private const val THOUSAND_MILLIS = 1000L
  }
}

/** CharArray extension */

/** Implements startsWith, trimStart, trimEnd and isBlank methods known from the String */
public fun CharArray.startsWith(prefix: String, ignoreCase: Boolean = false): Boolean {
  if (this.size < prefix.length) return false
  val prefixIterator = prefix.iterator()
  val thisIterator = this.iterator()
  while (prefixIterator.hasNext() && thisIterator.hasNext()) {
    if (!thisIterator.next().equals(prefixIterator.next(), ignoreCase)) {
      return false
    }
  }
  return true
}

public fun CharArray.trimStart(): CharArray {
  val firstNonWhitespaceIndex = indexOfFirst { !it.isWhitespace() }
  if (firstNonWhitespaceIndex == -1) return charArrayOf() // All whitespace or empty array

  val retValue = copyOfRange(firstNonWhitespaceIndex, size)
  fill('\u0000')
  return retValue
}

public fun CharArray.trimEnd(): CharArray {
  var last = lastIndex
  while (last >= 0 && this[last].isWhitespace()) last--
  return when {
    last < 0 -> CharArray(0)
    else -> {
      val retValue = copyOfRange(0, last + 1)
      fill('\u0000')
      retValue
    }
  }
}

public fun CharArray.isBlank(): Boolean = all { it.isWhitespace() }

/** Splits a CharArray at [c] into a list of CharArray, avoiding String as an intermediate. */
public fun CharArray.splitToCharArrayListAt(c: Char): List<CharArray> {
  val result = mutableListOf<CharArray>()
  val currentLine = mutableListOf<Char>()

  for (ch in this) {
    if (ch == c) {
      result.add(currentLine.toCharArray())
      currentLine.fill('\u0000')
      currentLine.clear()
    } else {
      currentLine.add(ch)
    }
  }
  result.add(currentLine.toCharArray()) // last line
  currentLine.fill('\u0000')

  return result
}

/**
 * Joins a list of CharArray at [c] into a list of CharArray, avoiding String as an intermediate.
 */
public fun List<CharArray>.joinToCharArray(separator: Char? = null): CharArray? {
  if (isEmpty() || size == 1 && last().isEmpty()) return null

  val totalChars = sumOf { it.size } + (separator?.let { size - 1 } ?: 0)

  val result = CharArray(totalChars)
  var pos = 0

  forEachIndexed { index, chunk ->
    if (chunk.isNotEmpty()) {
      chunk.copyInto(result, destinationOffset = pos)
      pos += chunk.size
    }
    if (index != lastIndex && separator != null) {
      result[pos++] = separator
    }
  }

  return result
}
