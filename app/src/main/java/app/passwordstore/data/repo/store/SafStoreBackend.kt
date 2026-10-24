/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo.store

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document
import androidx.documentfile.provider.DocumentFile
import app.passwordstore.Application
import java.io.IOException

/**
 * [StoreBackend] for a store living in a folder the user picked with the Storage Access Framework.
 *
 * jgit cannot open such a folder: it needs a filesystem path, and a tree URI is not one. This
 * backend is therefore never git-backed, and a `.git` directory inside the picked folder is never
 * read or written. It exists to give read and write access to a store that is synchronised
 * elsewhere, typically by desktop `pass`.
 *
 * A [DocumentFile] is only a handle, and `name`, `isDirectory` and `isFile` on it are provider
 * round trips of their own, so a listing read through those handles costs one round trip per entry
 * and per screen rebind. Listings therefore come from the provider's child-documents cursor, which
 * returns the name and the mime type of every entry along with its document id in a single query,
 * and they are cached per directory. The write path talks to [DocumentsContract] on the document
 * URI.
 *
 * Any write drops the whole listing cache: writes are rare, reads are not, and a stale listing
 * after a write would be a correctness bug rather than a performance problem. A store written by
 * another program — which is the point of a folder store — is seen after [invalidate] and not
 * before, because the framework reports no changes to a tree.
 *
 * [context] is a parameter rather than a lookup of [Application] so that the provider queries a
 * screen costs can be counted in a test.
 */
class SafStoreBackend(
  private val treeUri: Uri,
  private val context: Context = Application.instance,
) : StoreBackend {

  override val gitCapable: Boolean = false

  internal val contentResolver: ContentResolver = context.contentResolver

  private val rootDocument =
    DocumentFile.fromTreeUri(context, treeUri)
      ?: throw IOException("The selected folder could not be opened")

  private val childrenCache = mutableMapOf<String, List<SafStoreNode>>()

  private val rootNode =
    SafStoreNode(
      this,
      "",
      SafStoreChild(
        DocumentsContract.getTreeDocumentId(treeUri),
        rootDocument.name ?: "",
        isDirectory = true,
      ),
    )

  override val root: StoreNode
    get() = rootNode

  override fun resolve(path: String): StoreNode = resolveNode(path)

  internal fun resolveNode(path: String): SafStoreNode {
    var node = rootNode
    for (segment in path.split('/')) {
      when {
        segment.isEmpty() || segment == "." -> Unit
        segment == ".." -> node = node.parentNode() ?: node
        else -> node = node.findChildNode(segment) ?: node.childOf(segment)
      }
    }
    return node
  }

  /**
   * Read straight from the provider rather than from the cache. This decides whether the user is
   * warned before saving, so a `.git` created or removed since the last listing has to be seen.
   */
  override fun hasGitDir(): Boolean = rootDocument.findFile(GIT_DIR)?.isDirectory == true

  /** The entries of [parent]: one query, or none at all if this directory was listed before. */
  internal fun childNodesOf(parent: SafStoreNode): List<SafStoreNode> =
    childrenCache.getOrPut(parent.path) { queryChildren(parent) }

  /**
   * The entries of [parent], from the provider's child-documents cursor.
   *
   * A query that fails or returns nothing leaves the directory empty, the way
   * [DocumentFile.listFiles] does, rather than failing the screen that asked for it.
   */
  private fun queryChildren(parent: SafStoreNode): List<SafStoreNode> {
    val parentId = parent.documentId ?: return emptyList()
    val projection =
      arrayOf(Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME, Document.COLUMN_MIME_TYPE)
    val children = mutableListOf<SafStoreNode>()
    try {
      contentResolver
        .query(
          DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentId),
          projection,
          null,
          null,
          null,
        )
        ?.use { cursor ->
          val idColumn = cursor.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID)
          val nameColumn = cursor.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME)
          val mimeColumn = cursor.getColumnIndexOrThrow(Document.COLUMN_MIME_TYPE)
          while (cursor.moveToNext()) {
            val name = cursor.getString(nameColumn) ?: continue
            val entry =
              SafStoreChild(
                cursor.getString(idColumn),
                name,
                cursor.getString(mimeColumn) == Document.MIME_TYPE_DIR,
              )
            children.add(SafStoreNode(this, childPath(parent.path, name), entry))
          }
        }
    } catch (_: Exception) {
      return emptyList()
    }
    return children
  }

  /** The URI of the document with this id, in the tree-scoped shape a provider expects. */
  internal fun documentUri(documentId: String): Uri =
    DocumentsContract.buildDocumentUriUsingTree(treeUri, documentId)

  /** The id of a document a provider just returned, for the record this backend keeps of it. */
  internal fun documentIdOf(uri: Uri): String {
    val segments = uri.pathSegments
    return if (segments.size > 3 && segments[2] == DOCUMENT_SEGMENT) segments[3]
    else DocumentsContract.getDocumentId(uri)
  }

  /**
   * The directory at store-relative [path], creating it and any missing directory above it.
   *
   * [DocumentFile] has no `mkdirs()` and a provider creates one child at a time, so the missing
   * levels are created from the root down. [SafStoreNode.writeBytes] needs this to do what
   * [FileStoreNode.writeBytes] does: create the file it writes, and its parent directories.
   */
  internal fun directoryAt(path: String): SafStoreNode? {
    var node = rootNode
    for (segment in path.split('/')) {
      if (segment.isEmpty() || segment == ".") continue
      val child = node.findChildNode(segment) ?: node.createDirectory(segment) as? SafStoreNode
      if (child == null || !child.isDirectory) return null
      node = child
    }
    return node
  }

  /**
   * Creates a document named [name] in [parentUri] and returns its document URI.
   *
   * [DocumentFile.createFile] and [DocumentFile.createDirectory] make the same call internally. It
   * is made directly because a handle for a listed entry can only be built from its document URI,
   * and [DocumentFile.fromTreeUri] turns any URI built that way back into the tree root.
   */
  internal fun createDocument(parentUri: Uri, name: String, mimeType: String): Uri =
    DocumentsContract.createDocument(contentResolver, parentUri, mimeType, name)
      ?: throw IOException("Failed to create $name")

  /** The display name the provider keeps for the document at [uri]. Write path only. */
  internal fun documentName(uri: Uri): String? = DocumentFile.fromSingleUri(context, uri)?.name

  /** Whether the provider still knows the document at [uri]. */
  internal fun documentExists(uri: Uri): Boolean =
    DocumentFile.fromSingleUri(context, uri)?.exists() == true

  /** Renames the document at [uri], reporting whether the provider accepted the new name. */
  internal fun renameDocument(uri: Uri, name: String): Boolean =
    DocumentsContract.renameDocument(contentResolver, uri, name) != null

  /** Deletes the document at [uri], and its children if it is a directory. */
  internal fun deleteDocument(uri: Uri): Boolean =
    DocumentsContract.deleteDocument(contentResolver, uri)

  /**
   * Drops every remembered listing, and the write path calls this on itself.
   *
   * The framework reports no change to a tree, so what another program wrote into the folder is
   * only seen once this has run: the app's own writes forget what they changed, an outside writer
   * has to be answered with a refresh.
   */
  override fun invalidate() {
    childrenCache.clear()
  }
}

private fun childPath(parentPath: String, name: String): String =
  if (parentPath.isEmpty()) name else "$parentPath/$name"

/** Path segment that a tree-scoped document URI carries its document id behind. */
private const val DOCUMENT_SEGMENT = "document"

/**
 * One entry of a directory listing.
 *
 * A [DocumentFile] is a handle only, and reading `name`, `isDirectory` or `isFile` off one is a
 * provider round trip. The child-documents cursor carries the name and the mime type along with the
 * document id, so they are recorded once, at listing time, and every later read is free.
 *
 * The document id is the entry's identity on the provider side, and the only thing that can be
 * turned into both a document URI and a child-listing URI. A document URI does not hand its own id
 * back, so the id from the cursor row is what is kept.
 */
internal class SafStoreChild(val documentId: String, val name: String, val isDirectory: Boolean) {

  val isFile: Boolean
    get() = !isDirectory
}

/**
 * [StoreNode] for one document of a Storage Access Framework tree.
 *
 * [child] is the entry this node was built from, and is absent for a path that no listing ever
 * returned. Identity is [path] alone, exactly like [FileStoreNode]: two nodes are equal when they
 * address the same store entry, regardless of which backend produced them.
 */
class SafStoreNode
internal constructor(
  private val backend: SafStoreBackend,
  override val path: String,
  private val child: SafStoreChild?,
) : StoreNode {

  /** The document this node addresses, `null` for a path that was never in a listing. */
  internal val documentId: String?
    get() = child?.documentId

  private val documentUri: Uri?
    get() = documentId?.let { backend.documentUri(it) }

  override val name: String
    get() = child?.name ?: path.substringAfterLast('/')

  override val isDirectory: Boolean
    get() = child?.isDirectory == true

  override val isFile: Boolean
    get() = child?.isFile == true

  /**
   * Always a provider round trip: a cached listing can be older than what another app did to the
   * folder, and this is asked before a save.
   */
  override fun exists(): Boolean = documentUri?.let { backend.documentExists(it) } ?: false

  override fun children(): List<StoreNode> = childNodes()

  override fun parent(): StoreNode? = parentNode()

  /**
   * The parent directory, from the path alone: the `parentFile` field of a handle would be null for
   * an entry that came out of a listing cursor rather than out of a [DocumentFile].
   */
  internal fun parentNode(): SafStoreNode? =
    if (path.isEmpty()) null else backend.resolveNode(path.substringBeforeLast('/', ""))

  override fun findChild(name: String): StoreNode? = findChildNode(name)

  internal fun findChildNode(name: String): SafStoreNode? =
    if (!isDirectory) null else backend.childNodesOf(this).firstOrNull { it.name == name }

  override fun readLines(): List<String> =
    if (child == null) emptyList() else String(readBytes()).lines()

  override fun readBytes(): ByteArray {
    val source = documentUri ?: throw IOException("$path no longer exists")
    return backend.contentResolver.openInputStream(source)?.use { it.readBytes() }
      ?: throw IOException("Failed to read $name")
  }

  override fun writeBytes(bytes: ByteArray) {
    val target = documentUri ?: createMissingFile()
    backend.contentResolver.openOutputStream(target, "wt")?.use { it.write(bytes) }
      ?: throw IOException("Failed to write $name")
  }

  /**
   * Creates this file, and any missing directory above it. A write reaches a path that is not there
   * yet whenever a new password or passkey is saved, and the node it arrives on carries no entry.
   */
  private fun createMissingFile(): Uri {
    val parentPath = path.substringBeforeLast('/', "")
    val parent = backend.directoryAt(parentPath) ?: throw IOException("Failed to open $parentPath")
    val created = parent.createFile(name) as? SafStoreNode
    return created?.documentUri ?: throw IOException("Failed to create $name")
  }

  override fun writeText(text: String) = writeBytes(text.toByteArray())

  override fun createFile(name: String): StoreNode {
    val parentUri = documentUri ?: throw IOException("Failed to create $name in $path")
    val created = backend.createDocument(parentUri, name, "application/octet-stream")
    // Some providers append an extension of their own. The import worker has the same problem and
    // renames afterwards with renameFilesInDirectoryTree, which needs a real path and so cannot
    // help here.
    val createdName = backend.documentName(created)
    if (createdName != null && createdName != name) {
      check(backend.renameDocument(created, name)) { "Failed to name the new file $name" }
    }
    backend.invalidate()
    return SafStoreNode(
      backend,
      childPath(path, name),
      SafStoreChild(backend.documentIdOf(created), name, isDirectory = false),
    )
  }

  override fun createDirectory(name: String): StoreNode {
    val parentUri = documentUri ?: throw IOException("Failed to create directory $name")
    val created = backend.createDocument(parentUri, name, Document.MIME_TYPE_DIR)
    backend.invalidate()
    return SafStoreNode(
      backend,
      childPath(path, name),
      SafStoreChild(backend.documentIdOf(created), name, isDirectory = true),
    )
  }

  override fun rename(newName: String) {
    val target = documentUri ?: throw IOException("$path no longer exists")
    check(backend.renameDocument(target, newName)) { "Failed to rename $name to $newName" }
    backend.invalidate()
  }

  override fun deleteRecursively() {
    val target = documentUri ?: return
    check(backend.deleteDocument(target)) { "Failed to delete $name" }
    backend.invalidate()
  }

  override fun walk(include: (StoreNode) -> Boolean): List<StoreNode> {
    val result = mutableListOf<StoreNode>()
    fun visit(node: SafStoreNode) {
      if (include(node)) result.add(node)
      // Never descend into git metadata. Search filters it out already
      // (SearchableRepositoryViewModel.shouldTake), but the credential and autofill lookups walk
      // the whole store, and every descent here costs an IPC.
      if (!node.isDirectory || node.name == GIT_DIR) return
      node.childNodes().forEach(::visit)
    }
    visit(this)
    return result
  }

  internal fun childOf(name: String): SafStoreNode =
    SafStoreNode(backend, childPath(path, name), null)

  private fun childNodes(): List<SafStoreNode> =
    if (!isDirectory) emptyList() else backend.childNodesOf(this)

  override fun equals(other: Any?): Boolean = other is SafStoreNode && other.path == path

  override fun hashCode(): Int = path.hashCode()

  override fun toString(): String = "SafStoreNode(path=$path)"
}
