/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo.store

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.Before
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

private const val AUTHORITY = "app.passwordstore.saftest"
private const val TREE_ID = "root"
private const val CHILDREN_SEGMENT = "children"

// DocumentsContract.METHOD_CREATE_DOCUMENT and its EXTRA_URI are hidden from the SDK; these are the
// wire values the framework inlines into the create and rename calls.
private const val METHOD_CREATE_DOCUMENT = "android:createDocument"
private const val EXTRA_URI = "uri"

private val TREE_URI: Uri = Uri.parse("content://$AUTHORITY/tree/$TREE_ID")

private val COLUMNS =
  arrayOf(
    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
    DocumentsContract.Document.COLUMN_MIME_TYPE,
  )

/**
 * Stands in for a `DocumentsProvider`.
 *
 * It answers the child-documents query this backend makes, in the shape the provider contract
 * prescribes, and counts every query: the counts are what the assertions are about, and a stub that
 * answered the wrong thing would show up as a wrong count or a failed parse.
 */
class StubDocumentsProvider : ContentProvider() {

  var queryCount = 0
    private set

  private val names = mutableMapOf<String, String>()
  private val types = mutableMapOf<String, String>()
  private val children = mutableMapOf<String, MutableList<String>>()

  fun addDocument(parentId: String?, id: String, name: String, isDirectory: Boolean = false) {
    names[id] = name
    types[id] =
      if (isDirectory) DocumentsContract.Document.MIME_TYPE_DIR else "application/octet-stream"
    if (parentId != null) children.getOrPut(parentId) { mutableListOf() }.add(id)
  }

  fun resetQueryCount() {
    queryCount = 0
  }

  override fun onCreate(): Boolean = true

  override fun query(
    uri: Uri,
    projection: Array<out String>?,
    selection: String?,
    selectionArgs: Array<out String>?,
    sortOrder: String?,
  ): Cursor {
    queryCount++
    // The cursor answers in the order of the requested projection: callers read columns by index.
    val columns = projection ?: COLUMNS
    val cursor = MatrixCursor(columns)
    val segments = uri.pathSegments
    if (segments.lastOrNull() == CHILDREN_SEGMENT) {
      children[segments[segments.size - 2]]?.forEach { id -> cursor.addRow(row(columns, id)) }
      return cursor
    }
    val id = documentIdOf(uri)
    if (names.containsKey(id)) cursor.addRow(row(columns, id))
    return cursor
  }

  @Suppress("DEPRECATION")
  override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
    if (method != METHOD_CREATE_DOCUMENT || extras == null) return null
    val parentUri = extras.getParcelable<Uri>(EXTRA_URI) ?: return null
    val name = extras.getString(DocumentsContract.Document.COLUMN_DISPLAY_NAME) ?: return null
    val isDirectory =
      extras.getString(DocumentsContract.Document.COLUMN_MIME_TYPE) ==
        DocumentsContract.Document.MIME_TYPE_DIR
    val id = "created-${names.size}"
    addDocument(documentIdOf(parentUri), id, name, isDirectory)
    return Bundle().apply {
      putParcelable(EXTRA_URI, Uri.parse("content://$AUTHORITY/tree/$TREE_ID/document/$id"))
    }
  }

  override fun insert(uri: Uri, values: ContentValues?): Uri? = null

  override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

  override fun update(
    uri: Uri,
    values: ContentValues?,
    selection: String?,
    selectionArgs: Array<out String>?,
  ): Int = 0

  override fun getType(uri: Uri): String? = null

  private fun row(columns: Array<out String>, id: String): Array<Any?> =
    columns
      .map { column ->
        when (column) {
          DocumentsContract.Document.COLUMN_DOCUMENT_ID -> id
          DocumentsContract.Document.COLUMN_DISPLAY_NAME -> names[id]
          DocumentsContract.Document.COLUMN_MIME_TYPE -> types[id]
          else -> null
        }
      }
      .toTypedArray()

  private fun documentIdOf(uri: Uri): String {
    val segments = uri.pathSegments
    return if (segments.size > 3 && segments[2] == "document") segments[3] else segments[1]
  }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [23])
class SafStoreBackendQueryCountTest {

  private lateinit var provider: StubDocumentsProvider
  private lateinit var backend: SafStoreBackend

  @Before
  fun setUp() {
    provider =
      Robolectric.buildContentProvider(StubDocumentsProvider::class.java).create(AUTHORITY).get()
    provider.addDocument(parentId = null, TREE_ID, "store", isDirectory = true)
    repeat(FOLDERS) { index -> addFolder("folder$index") }
    backend = SafStoreBackend(TREE_URI, RuntimeEnvironment.getApplication())
    provider.resetQueryCount()
  }

  @Test
  fun listingADirectoryCostsOneQueryAndRepeatsForFree() {
    val (children, queries) = countingQueries { backend.root.children() }
    assertEquals(1, queries, "a listing is one child-documents query")
    assertEquals(FOLDERS, children.size)
    assertEquals("folder0", children.first().name)
    assertTrue(children.first().isDirectory)
    assertEquals("folder0/secret0.gpg", children.first().children().first().path)

    val (again, repeated) = countingQueries { backend.root.children() }
    assertEquals(0, repeated, "a rebuild of the same screen must not query the provider")
    assertEquals(children.map { it.path }, again.map { it.path })
  }

  @Test
  fun folderRowsCostNothingAfterTheirFirstListing() {
    val folders = backend.root.children()
    val (_, firstPass) = countingQueries { folders.forEach { folder -> folder.children() } }
    assertEquals(FOLDERS, firstPass, "every folder is listed once, on the first pass")

    val (_, secondPass) =
      countingQueries {
        folders.forEach { folder ->
          folder.children().count { child -> child.isDirectory || child.extension == "gpg" }
        }
      }
    assertEquals(0, secondPass, "binding the same rows again must not list anything again")
  }

  @Test
  fun navigatingIntoAFolderAndBackStaysUnderFiveQueries() {
    provider.resetQueryCount()

    val folder = backend.resolve("folder0")
    assertTrue(folder.exists())
    assertTrue(folder.isDirectory)
    assertEquals(FILES_PER_FOLDER, folder.children().size)
    assertEquals("", folder.parent()?.path)

    assertTrue(
      provider.queryCount <= 5,
      "navigation took ${provider.queryCount} provider queries, expected at most 5",
    )
  }

  @Test
  fun resolvingAPathListsEachDirectoryOnce() {
    backend.root.children()
    provider.resetQueryCount()

    val node = backend.resolve("folder0/secret0.gpg")

    assertEquals("folder0/secret0.gpg", node.path)
    assertEquals(1, provider.queryCount, "only the directory on the way down needs a query")
  }

  @Test
  fun aWriteDropsTheListingCache() {
    val folder = backend.resolve("folder0")
    folder.children()
    provider.resetQueryCount()

    val created = folder.createFile("new.gpg")
    assertEquals("folder0/new.gpg", created.path)
    assertTrue(created.exists(), "the created document is addressable right away")

    val (children, queries) = countingQueries { folder.children() }
    assertTrue(queries >= 1, "a write invalidates the listing, so the next screen reads it again")
    assertEquals(FILES_PER_FOLDER + 1, children.size)
  }

  @Test
  fun invalidateDropsTheListingAndTheNextOneAsksAgain() {
    val (children, _) = countingQueries { backend.root.children() }
    backend.invalidate()

    val (again, queries) = countingQueries { backend.root.children() }

    assertEquals(1, queries, "an invalidated listing is read from the provider again")
    assertEquals(children.map { it.path }, again.map { it.path })
  }

  @Test
  fun aFileWrittenByAnotherProgramAppearsOnlyAfterInvalidate() {
    val folder = backend.resolve("folder0")
    val (before, _) = countingQueries { folder.children() }
    assertFalse(before.any { it.name == EXTERNAL_FILE })

    provider.addDocument("folder0", "external", EXTERNAL_FILE)

    val (cached, _) = countingQueries { folder.children() }
    assertFalse(cached.any { it.name == EXTERNAL_FILE }, "a cached listing cannot see it")

    backend.invalidate()

    val (fresh, _) = countingQueries { folder.children() }
    assertTrue(fresh.any { it.name == EXTERNAL_FILE }, "a refresh reads the folder again")
  }

  private fun addFolder(id: String) {
    provider.addDocument(TREE_ID, id, id, isDirectory = true)
    repeat(FILES_PER_FOLDER) { index ->
      provider.addDocument(id, "$id-secret$index", "secret$index.gpg")
    }
  }

  private fun <T> countingQueries(block: () -> T): Pair<T, Int> {
    provider.resetQueryCount()
    val result = block()
    return result to provider.queryCount
  }

  private companion object {

    const val FOLDERS = 20

    const val FILES_PER_FOLDER = 20

    const val EXTERNAL_FILE = "copied-from-the-desktop.gpg"
  }
}
