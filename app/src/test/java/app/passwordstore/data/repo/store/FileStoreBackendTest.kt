/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo.store

import java.io.File
import java.io.IOException
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assume
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class FileStoreBackendTest {

  @get:Rule val tmp = TemporaryFolder()

  private lateinit var root: File
  private lateinit var backend: StoreBackend

  private fun setUpStore() {
    root = tmp.newFolder("store")
    backend = FileStoreBackend(root)
  }

  @Test
  fun topLevelNodeHasRootAsParent() {
    setUpStore()
    assertEquals("", backend.resolve("work").parent()?.path)
    assertNull(backend.root.parent())
  }

  @Test
  fun everyNodeIsUnderRoot() {
    setUpStore()
    assertEquals(true, backend.resolve("work/example.org").isUnder(backend.root))
  }

  @Test
  fun findGpgIdWalksUpToNearestAncestor() {
    setUpStore()
    File(root, "work").mkdirs()
    File(root, "work/example.org").mkdirs()
    File(root, "work/.gpg-id").writeText("ANCESTOR\n")
    File(root, "work/example.org/.gpg-id").writeText("OWN\n")

    val own = backend.resolve("work/example.org").findGpgId(backend.root)
    val inherited = backend.resolve("work").findGpgId(backend.root)
    assertEquals("work/example.org/.gpg-id", own?.path)
    assertEquals("work/.gpg-id", inherited?.path)
  }

  @Test
  fun findGpgIdReturnsNullWhenNoAncestorDeclaresKeys() {
    setUpStore()
    File(root, "work").mkdirs()
    assertNull(backend.resolve("work").findGpgId(backend.root))
  }

  @Test
  fun resolveNormalisesRelativeSegments() {
    setUpStore()
    assertEquals("work/example.org", backend.resolve("./work//example.org").path)
    assertEquals("work", backend.resolve("work/example.org/..").path)
  }

  @Test
  fun walkDoesNotFollowSymlinks() {
    setUpStore()
    File(root, "work").mkdirs()
    File(root, "work/example.org").mkdirs()
    // A store is a git repository: the user may have committed a link pointing at an ancestor.
    // Files.walk, which this replaced, did not descend into it and neither may we.
    val loop = File(root, "work/loop")
    try {
      Files.createSymbolicLink(loop.toPath(), File(root, "work").toPath())
    } catch (e: IOException) {
      Assume.assumeNoException("symlink creation unavailable", e)
    } catch (e: UnsupportedOperationException) {
      Assume.assumeNoException("symlink creation unavailable", e)
    }

    assertEquals(
      setOf("", "work", "work/example.org", "work/loop"),
      backend.root.walk { true }.map { it.path }.toSet(),
    )
  }
}
