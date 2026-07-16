/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.crypto

import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.util.time.UserClock
import app.passwordstore.util.totp.UriTotpFinder
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class PasswordReferenceResolverTest {

  private val totpFinder = UriTotpFinder()

  private val factory =
    object : PasswordEntry.Factory {
      override fun create(chars: CharArray) = PasswordEntry(UserClock(), totpFinder, chars)
    }

  private val resolver = PasswordReferenceResolver(factory)
  private val repoRoot: File = Files.createTempDirectory("store").toFile()

  private fun path(name: String) = File(repoRoot, "$name.gpg").absolutePath

  private fun parse(chars: CharArray) = factory.create(chars.copyOf())

  @Test
  fun nonReferenceIsReturnedUnchanged() = runBlocking {
    val plain = "hunter2\nusername: alice".toCharArray()
    val result =
      resolver.resolve(plain, repoRoot, path("a")) { error("should not decrypt a non-reference") }
    val resolved = assertIs<PasswordReferenceResolver.Result.Resolved>(result)
    assertEquals("hunter2\nusername: alice", String(resolved.plaintext))
  }

  @Test
  fun substitutesPasswordAndInheritsUsername() = runBlocking {
    val origin = "gopass://services/db/pg".toCharArray()
    val result =
      resolver.resolve(origin, repoRoot, path("apps/billing")) { file ->
        assertEquals(File(repoRoot, "services/db/pg.gpg").canonicalPath, file.canonicalPath)
        "realpass\nusername: dbuser".toCharArray()
      }
    val resolved = assertIs<PasswordReferenceResolver.Result.Resolved>(result)
    val entry = parse(resolved.plaintext)
    assertEquals("realpass", entry.password?.let { String(it) })
    assertEquals("dbuser", entry.username?.let { String(it) })
  }

  @Test
  fun keepsOriginsOwnUsername() = runBlocking {
    val origin = "gopass://b\nusername: mine".toCharArray()
    val result =
      resolver.resolve(origin, repoRoot, path("a")) { "realpass\nusername: theirs".toCharArray() }
    val resolved = assertIs<PasswordReferenceResolver.Result.Resolved>(result)
    val entry = parse(resolved.plaintext)
    assertEquals("realpass", entry.password?.let { String(it) })
    assertEquals("mine", entry.username?.let { String(it) })
  }

  @Test
  fun resolvesNestedChain() = runBlocking {
    val origin = "gopass://b".toCharArray()
    val result =
      resolver.resolve(origin, repoRoot, path("a")) { file ->
        when (file.name) {
          "b.gpg" -> "gopass://c".toCharArray()
          "c.gpg" -> "finalpass\nusername: z".toCharArray()
          else -> error("unexpected file ${file.name}")
        }
      }
    val resolved = assertIs<PasswordReferenceResolver.Result.Resolved>(result)
    val entry = parse(resolved.plaintext)
    assertEquals("finalpass", entry.password?.let { String(it) })
    assertEquals("z", entry.username?.let { String(it) })
  }

  @Test
  fun detectsCycle() = runBlocking {
    // a -> b -> a
    val origin = "gopass://b".toCharArray()
    val result =
      resolver.resolve(origin, repoRoot, path("a")) { file ->
        when (file.name) {
          "b.gpg" -> "gopass://a".toCharArray()
          else -> error("unexpected file ${file.name}")
        }
      }
    val unresolved = assertIs<PasswordReferenceResolver.Result.Unresolved>(result)
    assertEquals(PasswordReferenceResolver.Reason.CYCLE, unresolved.reason)
  }

  @Test
  fun rejectsPathTraversal() = runBlocking {
    val origin = "gopass://../../../etc/passwd".toCharArray()
    val result =
      resolver.resolve(origin, repoRoot, path("a")) { error("should not decrypt an invalid path") }
    val unresolved = assertIs<PasswordReferenceResolver.Result.Unresolved>(result)
    assertEquals(PasswordReferenceResolver.Reason.INVALID_PATH, unresolved.reason)
  }

  @Test
  fun stopsAtMaxDepth() = runBlocking {
    // An unbounded chain ref0 -> ref1 -> ref2 -> ... must be cut off rather than recurse forever.
    val origin = "gopass://ref1".toCharArray()
    val result =
      resolver.resolve(origin, repoRoot, path("ref0")) { file ->
        val n = file.nameWithoutExtension.removePrefix("ref").toInt()
        "gopass://ref${n + 1}".toCharArray()
      }
    val unresolved = assertIs<PasswordReferenceResolver.Result.Unresolved>(result)
    assertEquals(PasswordReferenceResolver.Reason.TOO_DEEP, unresolved.reason)
  }

  @Test
  fun abortedUnlockLeavesReferenceUnresolved() = runBlocking {
    val origin = "gopass://b".toCharArray()
    val result = resolver.resolve(origin, repoRoot, path("a")) { null }
    val unresolved = assertIs<PasswordReferenceResolver.Result.Unresolved>(result)
    assertEquals(PasswordReferenceResolver.Reason.ABORTED, unresolved.reason)
  }

  @Test
  fun mergeInheritsTargetTotpWhenOriginHasNone() {
    val origin = "gopass://b".toCharArray()
    val target = "realpass\notpauth://totp/test?secret=JBSWY3DPEHPK3PXP".toCharArray()
    val merged = parse(resolver.merge(origin, target))
    assertEquals("realpass", merged.password?.let { String(it) })
    assertTrue(merged.hasTotp())
  }

  @Test
  fun mergeKeepsOriginTotpOverTarget() {
    val origin = "gopass://b\notpauth://totp/mine?secret=JBSWY3DPEHPK3PXP".toCharArray()
    val target = "realpass\notpauth://totp/theirs?secret=GEZDGNBVGY3TQOJQ".toCharArray()
    val merged = parse(resolver.merge(origin, target))
    // origin defines its own TOTP, so no extra TOTP line is appended from the target
    assertFalse(String(merged.extraContentChars ?: charArrayOf()).contains("theirs"))
    assertNull(merged.username)
  }
}
