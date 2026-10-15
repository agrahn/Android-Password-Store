/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo.store

import java.io.File
import java.io.IOException
import java.nio.file.Files

/**
 * [StoreBackend] for a store living at a plain filesystem path, which is what the app-private store
 * directory is.
 */
class FileStoreBackend(val rootPath: File) : StoreBackend {

  override val root: StoreNode = FileStoreNode(rootPath, "")

  override fun resolve(path: String): StoreNode {
    val normalized = normalizePath(path)
    return FileStoreNode(File(rootPath, normalized), normalized)
  }

  private fun normalizePath(path: String): String {
    val segments = mutableListOf<String>()
    for (segment in path.split('/')) {
      when {
        segment.isEmpty() || segment == "." -> Unit
        segment == ".." -> segments.removeLastOrNull()
        else -> segments.add(segment)
      }
    }
    return segments.joinToString("/")
  }
}

/**
 * [StoreNode] backed by a [File].
 *
 * Identity is [path] alone, not the underlying [File]: two nodes are equal when they address the
 * same store entry, regardless of which backend instance produced them. Nodes are cheap, immutable
 * views — do not cache them across a store relocation.
 */
class FileStoreNode(val file: File, override val path: String) : StoreNode {

  override val name: String
    get() = file.name

  override val isDirectory: Boolean
    get() = file.isDirectory

  override val isFile: Boolean
    get() = file.isFile

  override fun exists(): Boolean = file.exists()

  override fun children(): List<StoreNode> = childNodes()

  override fun parent(): StoreNode? {
    if (path.isEmpty()) return null
    val parentFile = file.parentFile ?: return null
    return FileStoreNode(parentFile, path.substringBeforeLast('/', ""))
  }

  override fun findChild(name: String): StoreNode? =
    if (!isDirectory) null else child(name).takeIf { it.exists() }

  override fun readLines(): List<String> = file.readLines()

  override fun writeText(text: String) {
    file.parentFile?.mkdirs()
    file.writeText(text)
  }

  override fun createFile(name: String): StoreNode = child(name).also { it.file.createNewFile() }

  override fun walk(include: (StoreNode) -> Boolean): List<StoreNode> {
    val result = mutableListOf<StoreNode>()
    fun visit(node: FileStoreNode) {
      if (include(node)) result.add(node)
      // Never descend into a symbolic link. [File.isDirectory] and [File.listFiles] both follow
      // links, so a link pointing at an ancestor would recurse forever. The store is a git
      // repository whose contents come from `pass` on another machine, so such a link is ordinary
      // user data rather than an attack. This matches the `Files.walk` and `walkTopDown`
      // traversals this replaced, neither of which followed links either.
      if (!node.isDirectory || node.file.isSymbolicLink()) return
      node.childNodes().forEach(::visit)
    }
    visit(this)
    return result
  }

  private fun child(name: String): FileStoreNode =
    FileStoreNode(File(file, name), if (path.isEmpty()) name else "$path/$name")

  private fun childNodes(): List<FileStoreNode> =
    if (!isDirectory) emptyList() else file.listFiles()?.map { child(it.name) } ?: emptyList()

  override fun equals(other: Any?): Boolean = other is FileStoreNode && other.path == path

  private fun File.isSymbolicLink(): Boolean =
    try {
      Files.isSymbolicLink(toPath())
    } catch (_: IOException) {
      false
    } catch (_: SecurityException) {
      false
    }

  override fun hashCode(): Int = path.hashCode()

  override fun toString(): String = "FileStoreNode(path=$path)"
}

/**
 * The [File] backing this node.
 *
 * @throws IllegalStateException if the active backend is not file-backed.
 */
fun StoreNode.requireFile(): File =
  (this as? FileStoreNode)?.file
    ?: error("The active store backend is not backed by the filesystem")
