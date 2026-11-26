/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.extensions

import android.net.Uri
import android.os.Environment
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26], application = android.app.Application::class)
class TreeUriToFilePathTest {

  private val storageRoot = Environment.getExternalStorageDirectory().absolutePath

  @Test
  fun primaryVolumeTreeUriConvertsToExternalStoragePath() {
    val uri =
      Uri.parse(
        "content://com.android.externalstorage.documents/tree/primary%3Agit%2Fsync%2Fdotfiles"
      )
    assertEquals("$storageRoot/git/sync/dotfiles", uri.treeUriToFilePath())
  }

  @Test
  fun primaryVolumeRootTreeUriConvertsToStorageRoot() {
    val uri = Uri.parse("content://com.android.externalstorage.documents/tree/primary%3A")
    assertEquals(storageRoot, uri.treeUriToFilePath())
  }

  @Test
  fun secondaryVolumeTreeUriConvertsToStorageVolumePath() {
    val uri =
      Uri.parse("content://com.android.externalstorage.documents/tree/1234-ABCD%3Apasswords")
    assertEquals("/storage/1234-ABCD/passwords", uri.treeUriToFilePath())
  }

  @Test
  fun foreignAuthorityReturnsNull() {
    val uri = Uri.parse("content://com.google.android.drive.documents/tree/root%3Apasswords")
    assertNull(uri.treeUriToFilePath())
  }

  @Test
  fun documentUriWithoutTreeSegmentReturnsNull() {
    val uri =
      Uri.parse("content://com.android.externalstorage.documents/document/primary%3Afile.txt")
    assertNull(uri.treeUriToFilePath())
  }
}
