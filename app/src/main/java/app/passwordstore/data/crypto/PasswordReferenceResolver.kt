/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.crypto

import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.passfile.isBlank
import app.passwordstore.data.passfile.joinToCharArray
import app.passwordstore.data.passfile.splitToCharArrayListAt
import app.passwordstore.data.passfile.startsWith
import app.passwordstore.util.totp.TotpFinder
import java.io.File
import javax.inject.Inject

/**
 * Resolves gopass-style `gopass://` cross-secret password references.
 *
 * A password entry whose password is `gopass://<path>` does not hold a real password; instead the
 * password of the entry at `<path>` (relative to the store root) should be used. References resolve
 * recursively (a target may itself be a reference) and circular references are rejected.
 *
 * The class is intentionally UI- and crypto-agnostic: decryption of the referenced file is supplied
 * by the caller as the [decrypt] lambda, so the interactive unlock machinery (passphrase prompts,
 * biometrics, key selection) lives in the activity layer while this class only orchestrates and
 * merges. The [merge] step is pure and unit-testable.
 */
class PasswordReferenceResolver
@Inject
constructor(private val passwordEntryFactory: PasswordEntry.Factory) {

  sealed interface Result {
    /** The fully-resolved plaintext, with the reference substituted by the target's password. */
    class Resolved(val plaintext: CharArray) : Result

    /** Resolution failed; [reason] explains why and the original entry should be shown as-is. */
    data class Unresolved(val reason: Reason) : Result
  }

  enum class Reason {
    /** A reference eventually points back at an already-visited entry. */
    CYCLE,
    /** References nest deeper than [MAX_DEPTH]. */
    TOO_DEEP,
    /** The referenced path is empty or escapes the store root. */
    INVALID_PATH,
    /** The user aborted, or no key was available, while unlocking a referenced entry. */
    ABORTED,
  }

  /**
   * Resolves any reference in [plaintext].
   *
   * @param plaintext the decrypted content of the origin entry (owned by the caller).
   * @param repoRoot the password store root directory.
   * @param originPath absolute path of the origin `.gpg` file, used to seed cycle detection.
   * @param decrypt unlocks a referenced file, returning its plaintext or `null` if unavailable.
   * @return [Result.Resolved] (its plaintext may be the same array when [plaintext] is not a
   *   reference) or [Result.Unresolved].
   */
  suspend fun resolve(
    plaintext: CharArray,
    repoRoot: File,
    originPath: String,
    decrypt: suspend (File) -> CharArray?,
  ): Result {
    val seed = runCatching { File(originPath).canonicalPath }.getOrDefault(originPath)
    return resolveRec(plaintext, repoRoot, setOf(seed), 0, decrypt)
  }

  private suspend fun resolveRec(
    plaintext: CharArray,
    repoRoot: File,
    visited: Set<String>,
    depth: Int,
    decrypt: suspend (File) -> CharArray?,
  ): Result {
    val entry = passwordEntryFactory.create(plaintext.copyOf())
    if (!entry.isReference()) {
      entry.clear()
      return Result.Resolved(plaintext)
    }
    val refPath = entry.referencePath()
    entry.clear()
    if (refPath.isNullOrBlank()) return Result.Unresolved(Reason.INVALID_PATH)
    if (depth >= MAX_DEPTH) return Result.Unresolved(Reason.TOO_DEEP)

    val targetFile = File(repoRoot, "$refPath.gpg")
    if (!targetFile.isInside(repoRoot)) return Result.Unresolved(Reason.INVALID_PATH)
    val canonical = runCatching { targetFile.canonicalPath }.getOrDefault(targetFile.path)
    if (canonical in visited) return Result.Unresolved(Reason.CYCLE)

    val targetPlaintext = decrypt(targetFile) ?: return Result.Unresolved(Reason.ABORTED)
    val targetResolved =
      resolveRec(targetPlaintext, repoRoot, visited + canonical, depth + 1, decrypt)
    val targetPlain =
      when (targetResolved) {
        is Result.Resolved -> targetResolved.plaintext
        is Result.Unresolved -> {
          targetPlaintext.fill('\u0000')
          return targetResolved
        }
      }

    val merged = merge(plaintext, targetPlain)
    targetPlain.fill('\u0000')
    if (!targetPlain.contentEquals(targetPlaintext)) targetPlaintext.fill('\u0000')
    return Result.Resolved(merged)
  }

  /**
   * Produces the effective plaintext for a reference: [origin]'s password line is replaced with
   * [target]'s password, and — only when [origin] does not define them itself — [target]'s username
   * and TOTP are inherited. Any other fields defined by [origin] are preserved. Pure; does not read
   * files or decrypt.
   */
  fun merge(origin: CharArray, target: CharArray): CharArray {
    val originEntry = passwordEntryFactory.create(origin.copyOf())
    val targetEntry = passwordEntryFactory.create(target.copyOf())

    val lines = origin.splitToCharArrayListAt('\n').toMutableList()
    replacePasswordLine(lines, targetEntry.password?.copyOf() ?: charArrayOf())

    val targetUsername = targetEntry.username
    if (originEntry.username == null && targetUsername != null) {
      lines.add("username: ".toCharArray() + targetUsername)
    }
    if (!originEntry.hasTotp() && targetEntry.hasTotp()) {
      findTotpLine(target)?.let { lines.add(it) }
    }

    val result = lines.joinToCharArray('\n') ?: charArrayOf()
    originEntry.clear()
    targetEntry.clear()
    return result
  }

  /**
   * Overwrites the password line of [lines] in place with [newPassword], mirroring
   * [PasswordEntry]'s own password detection (first non-blank line unless it is a username/TOTP
   * field, otherwise the first `password:`/`secret:`/`pass:` field).
   */
  private fun replacePasswordLine(lines: MutableList<CharArray>, newPassword: CharArray) {
    if (lines.isEmpty()) return
    val fieldPrefixes = PasswordEntry.USERNAME_FIELDS + TotpFinder.TOTP_FIELDS
    if (!lines[0].isBlank() && fieldPrefixes.none { lines[0].startsWith(it, ignoreCase = true) }) {
      lines[0] = newPassword
      return
    }
    for (i in lines.indices) {
      if (lines[i].isBlank()) break
      for (prefix in PasswordEntry.PASSWORD_FIELDS) {
        if (lines[i].startsWith(prefix, ignoreCase = true)) {
          lines[i] = "$prefix ".toCharArray() + newPassword
          return
        }
      }
    }
  }

  private fun findTotpLine(plaintext: CharArray): CharArray? {
    var found: CharArray? = null
    for (line in plaintext.splitToCharArrayListAt('\n')) {
      if (TotpFinder.TOTP_FIELDS.any { line.startsWith(it, ignoreCase = true) })
        found = line.copyOf()
    }
    return found
  }

  private fun File.isInside(root: File): Boolean {
    val rootPath = runCatching { root.canonicalPath }.getOrDefault(root.path)
    val thisPath = runCatching { canonicalPath }.getOrDefault(path)
    return thisPath == rootPath || thisPath.startsWith("$rootPath${File.separator}")
  }

  companion object {
    /** Maximum reference chain length before giving up (also bounds runaway recursion). */
    const val MAX_DEPTH: Int = 20
  }
}
