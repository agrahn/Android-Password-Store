/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
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
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
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
  /** The content of this entry, as an array of bytes. */
  @Assisted bytes: ByteArray,
) {

  /** The password text for this entry. Can be null. */
  public val password: CharArray?

  /** The username for this entry. Can be null. */
  public val username: String?

  /** The totp entry extracted from the decrypted password file */
  private val totpString: String

  /** String representation of [bytes] but with passwords and first username stripped. */
  public val extraContentString: String?

  /** A [String] to [String] [Map] of the extra content of this entry, in a key:value fashion. */
  public val extraContent: Map<String, String>

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

  /** Implements startsWith and trimStart methods known from the String class for CharArray. */
  private fun CharArray.startsWith(prefix: String, ignoreCase: Boolean = false): Boolean {
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

  private fun CharArray.trimStart(): CharArray {
    val firstNonWhitespaceIndex = this.indexOfFirst { !it.isWhitespace() }
    if (firstNonWhitespaceIndex == -1) return charArrayOf() // All whitespace or empty array

    return this.copyOfRange(firstNonWhitespaceIndex, this.size)
  }

  /**
   * Decodes and splits a ByteArray at [c] into a list of CharArray, avoiding String as an
   * intermediate.
   */
  private fun ByteArray.splitToCharArrayListAt(c: Char): List<CharArray> {
    val charBuffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(this))
    val result = mutableListOf<CharArray>()
    val currentLine = mutableListOf<Char>()

    for (ch in charBuffer) {
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

    charBuffer.array().fill('\u0000')

    return result
  }

  init {
    val (foundPassword, passContentWithoutPasswords) =
      findAndStripPassword(bytes.splitToCharArrayListAt('\n'))
    password = foundPassword
    val (foundUsername, passContentWithoutPasswordsAndFirstUsername) =
      findAndStripFirstUsername(passContentWithoutPasswords)
    username = foundUsername?.let { String(it) }
    extraContentString =
      passContentWithoutPasswordsAndFirstUsername.map { String(it) }.joinToString("\n")
    val (foundTotp, extraContentWithoutAuthData) =
      findAndStripTotp(passContentWithoutPasswordsAndFirstUsername)
    totpString = foundTotp?.let { String(it) } ?: ""
    extraContent = generateExtraContentPairs(extraContentWithoutAuthData)
    // Verify the TOTP secret is valid and disable TOTP if not.
    val secret = totpFinder.findSecret(foundTotp?.let { String(it) } ?: "")
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
      !USERNAME_FIELDS.plus(TotpFinder.TOTP_FIELDS).any {
        lines[0].startsWith(it, ignoreCase = true)
      }
    ) {
      password = lines[0]
      lines = lines.minus(lines[0])
    }
    for (line in lines) {
      for (prefix in PASSWORD_FIELDS) {
        if (line.startsWith(prefix, ignoreCase = true)) {
          // Last line with prefixed password wins
          password = line.copyOfRange(prefix.length, line.size)
          lines = lines.minus(line)
          break
        }
      }
    }
    password?.let {
      return Pair(password, lines)
    }
    /**
     * If the first line contains any of the other known prefixes, we assume that no password is
     * present
     */
    if (
      USERNAME_FIELDS.plus(TotpFinder.TOTP_FIELDS).any {
        passContent[0].startsWith(it, ignoreCase = true)
      }
    )
      return Pair(null, passContent)
    // Otherwise, we assume that the first line is the (un-prefixed) password
    return Pair(passContent[0], passContent.minus(passContent[0]))
  }

  private fun findAndStripFirstUsername(
    passContent: List<CharArray>
  ): Pair<CharArray?, List<CharArray>> {
    var lines = passContent
    var username: CharArray? = null
    for (line in passContent) {
      for (prefix in USERNAME_FIELDS) {
        if (line.startsWith(prefix, ignoreCase = true)) {
          username = line.copyOfRange(prefix.length, line.size).trimStart()
          lines = lines.minus(line)
          break
        }
      }
      if (username != null) break
    }
    return Pair(username, lines)
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

  private fun generateExtraContentPairs(passContent: List<CharArray>): Map<String, String> {
    fun MutableMap<String, String>.putOrAppend(key: String, value: String) {
      val existing = this[key]
      this[key] =
        if (existing == null) {
          value
        } else {
          "$existing\n$value"
        }
    }

    val items = mutableMapOf<String, String>()
    passContent.forEach { line ->
      // Split the line at the first ':' into key and value
      // "ABC : DEF:GHI" --> key = "ABC" value = " DEF:GHI"]
      val (key, value) =
        if (String(line).contains(':')) {
          val keyval = String(line).split(":", limit = 2)
          if (keyval.first().trim().isEmpty() && keyval.last().isEmpty()) "" to String(line)
          else keyval.first().trim() to keyval.last()
        } else {
          "" to String(line)
        }

      if (key.isNotEmpty()) {
        // If key is not empty, we can form a pair with this so add it to the map.
        items.putOrAppend(key, value)
      } else {
        // If key is empty, we were not able to form proper key-value pair.
        // So append the original line to an "EXTRA CONTENT" map entry
        if (value.isNotEmpty()) items.putOrAppend(EXTRA_CONTENT, String(line))
      }
    }

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
    public fun create(bytes: ByteArray): PasswordEntry
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
    @VisibleForTesting(otherwise = VisibleForTesting.PRIVATE)
    public val PASSWORD_FIELDS: Array<String> = arrayOf("password:", "secret:", "pass:")
    private const val THOUSAND_MILLIS = 1000L
  }
}
