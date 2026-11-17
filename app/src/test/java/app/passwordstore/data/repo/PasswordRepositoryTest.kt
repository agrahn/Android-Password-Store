/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo

import android.net.Uri
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26], application = android.app.Application::class)
class PasswordRepositoryTest {
  @get:Rule val tmp = TemporaryFolder()
  private val root = File("/storage/emulated/0")

  @Test
  fun primaryVolumeResolved() {
    assertEquals(
      File("/storage/emulated/0/Sync/.password-store"),
      PasswordRepository.pathFromTreeDocumentId("primary:Sync/.password-store", root),
    )
  }

  @Test
  fun volumeRootRejected() {
    assertNull(PasswordRepository.pathFromTreeDocumentId("primary:", root))
  }

  @Test
  fun secondaryVolumeResolved() {
    assertEquals(
      File("/storage/1A2B-3C4D/pass"),
      PasswordRepository.pathFromTreeDocumentId("1A2B-3C4D:pass", root),
    )
  }

  @Test
  fun homeVolumeResolvedToDocuments() {
    assertEquals(
      File("/storage/emulated/0/Documents/pass"),
      PasswordRepository.pathFromTreeDocumentId("home:pass", root),
    )
  }

  @Test
  fun noColonRejected() {
    assertNull(PasswordRepository.pathFromTreeDocumentId("pass", root))
  }

  @Test
  fun parentSegmentsRejected() {
    assertNull(PasswordRepository.pathFromTreeDocumentId("primary:../../data", root))
  }

  @Test
  fun slashOnlyPathRejected() {
    assertNull(PasswordRepository.pathFromTreeDocumentId("primary:/", root))
  }

  @Test
  fun dotSegmentRejected() {
    assertNull(PasswordRepository.pathFromTreeDocumentId("primary:.", root))
  }

  @Test
  fun invalidVolumeRejected() {
    assertNull(PasswordRepository.pathFromTreeDocumentId("../x:pass", root))
    assertNull(PasswordRepository.pathFromTreeDocumentId("..:pass", root))
    assertNull(PasswordRepository.pathFromTreeDocumentId(".:pass", root))
    assertNull(PasswordRepository.pathFromTreeDocumentId(":pass", root))
  }

  @Test
  fun foreignProviderRejected() {
    assertFalse(
      PasswordRepository.setSharedRepoFromTreeUri(
        Uri.parse("content://com.android.providers.downloads.documents/tree/msf%3A123")
      )
    )
  }

  @Test
  fun createRepositoryInitsEmptyFolder() {
    val dir = tmp.newFolder()
    PasswordRepository.createRepository(dir)
    assertTrue(File(dir, ".git").isDirectory)
  }

  @Test
  fun createRepositoryInitsMissingFolder() {
    val dir = File(tmp.newFolder(), "store")
    PasswordRepository.createRepository(dir)
    assertTrue(File(dir, ".git").isDirectory)
  }

  @Test
  fun createRepositoryLeavesNonEmptyFolderAlone() {
    val dir = tmp.newFolder()
    File(dir, "a.gpg").writeText("x")
    PasswordRepository.createRepository(dir)
    assertFalse(File(dir, ".git").exists())
    assertEquals("x", File(dir, "a.gpg").readText())
  }
}
