/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo

import android.net.Uri
import androidx.core.content.edit
import androidx.core.net.toUri
import app.passwordstore.Application
import app.passwordstore.data.password.PasswordItem
import app.passwordstore.data.repo.store.FileStoreBackend
import app.passwordstore.data.repo.store.GPG_ID
import app.passwordstore.data.repo.store.SafStoreBackend
import app.passwordstore.data.repo.store.StoreBackend
import app.passwordstore.data.repo.store.StoreMode
import app.passwordstore.data.repo.store.StoreNode
import app.passwordstore.data.repo.store.requireFile
import app.passwordstore.util.extensions.isInsideRepository
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.settings.PasswordSortOrder
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import java.io.File
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.lib.BranchTrackingStatus
import org.eclipse.jgit.lib.Constants
import org.eclipse.jgit.lib.Repository
import org.eclipse.jgit.storage.file.FileRepositoryBuilder
import org.eclipse.jgit.transport.RefSpec
import org.eclipse.jgit.transport.RemoteConfig
import org.eclipse.jgit.transport.URIish

object PasswordRepository {

  val TYPE_FILE: Int = 1
  val TYPE_DIR: Int = 2

  var repository: Repository? = null
  private val settings by unsafeLazy { Application.instance.sharedPrefs }
  private val filesDir
    get() = Application.instance.filesDir

  val isInitialized: Boolean
    get() = if (isSafStore) backend.root.exists() else repository != null

  fun isGitRepo(): Boolean {
    val repo = repository ?: return false
    // A folder store is never git-backed. `repository` can still hold the app-private repository
    // after a mode switch, so the mode has to be part of the answer.
    return !isSafStore && repo.objectDatabase.exists()
  }

  /**
   * Takes in a [repositoryDir] to initialize a Git repository with, and assigns it to [repository]
   * as static state.
   */
  private fun initializeRepository(repositoryDir: File) {
    val builder = FileRepositoryBuilder()
    repository =
      runCatching { builder.setGitDir(repositoryDir).build() }
        .getOrElse { e ->
          e.printStackTrace()
          null
        }
  }

  fun createRepository(repositoryDir: File) {
    repositoryDir.delete()
    repository = Git.init().setDirectory(repositoryDir).call().repository
  }

  // TODO add multiple remotes support for pull/push
  fun addRemote(name: String, url: String, replace: Boolean = false) {
    val storedConfig = repository?.config ?: throw NullPointerException()
    val remotes = storedConfig.getSubsections("remote")

    if (!remotes.contains(name)) {
      runCatching {
        val uri = URIish(url)
        val refSpec = RefSpec("+refs/head/*:refs/remotes/$name/*")

        val remoteConfig = RemoteConfig(storedConfig, name)
        remoteConfig.addFetchRefSpec(refSpec)
        remoteConfig.addPushRefSpec(refSpec)
        remoteConfig.addURI(uri)
        remoteConfig.addPushURI(uri)

        remoteConfig.update(storedConfig)

        storedConfig.save()
      }
        .onErr { e -> e.printStackTrace() }
    } else if (replace) {
      runCatching {
        val uri = URIish(url)

        val remoteConfig = RemoteConfig(storedConfig, name)
        // remove the first and eventually the only uri
        if (remoteConfig.urIs.size > 0) {
          remoteConfig.removeURI(remoteConfig.urIs[0])
        }
        if (remoteConfig.pushURIs.size > 0) {
          remoteConfig.removePushURI(remoteConfig.pushURIs[0])
        }

        remoteConfig.addURI(uri)
        remoteConfig.addPushURI(uri)

        remoteConfig.update(storedConfig)

        storedConfig.save()
      }
        .onErr { e -> e.printStackTrace() }
    }
  }

  fun closeRepository() {
    repository?.close()
    repository = null
  }

  private var cachedBackend: StoreBackend? = null

  /**
   * The backend that provides access to the password store.
   *
   * This is the single place where the store's location is decided; callers must not derive the
   * store location themselves. It is built on first use because [Application.instance] is
   * unavailable until `Application.onCreate` has begun, and then reused, because a backend caches
   * its directory listings. [resetBackend] drops that cache when the location changes.
   */
  val backend: StoreBackend
    get() = cachedBackend ?: newBackend().also { cachedBackend = it }

  /** Whether the store lives in a folder picked with the Storage Access Framework. */
  val isSafStore: Boolean
    get() = backend is SafStoreBackend

  /** The mode the store is currently served from. */
  val storeMode: StoreMode
    get() = if (isSafStore) StoreMode.SAF else StoreMode.INTERNAL

  /**
   * Whether the picked folder contains a `.git` directory, which the app cannot use but which makes
   * a user expect a commit on save. Always false for the app-private store unless it holds a repo.
   */
  fun hasGitDir(): Boolean = backend.hasGitDir()

  /** The tree URI of the folder store, or `null` when the store is the app-private one. */
  val storeUri: Uri?
    get() = if (isSafStore) settings.getString(PreferenceKeys.STORE_URI, null)?.toUri() else null

  /** Forgets the cached backend so the next access picks up a changed store location. */
  fun resetBackend() {
    cachedBackend = null
  }

  /**
   * Forgets the backend's cached views of the store, so the next read comes from the store itself.
   *
   * Asking for a re-read is the only way to see a folder store that another program wrote into: the
   * framework reports no change to a tree.
   */
  fun invalidateStoreCache() {
    backend.invalidate()
  }

  private fun newBackend(): StoreBackend {
    val uri = settings.getString(PreferenceKeys.STORE_URI, null)
    if (
      StoreMode.from(settings.getString(PreferenceKeys.STORE_MODE, null)) == StoreMode.SAF &&
        uri != null
    ) {
      return SafStoreBackend(uri.toUri())
    }
    return FileStoreBackend(File(filesDir.toString(), "/store"))
  }

  /**
   * The store root as a plain [File].
   *
   * @throws IllegalStateException if the active backend is not file-backed, which is the case for a
   *   SAF store. This is the marker that a call site has to move to [storeRoot] or [nodeAt].
   */
  fun getRepositoryDirectory(): File = backend.root.requireFile()

  /** The store root as a [StoreNode]. */
  val storeRoot: StoreNode
    get() = backend.root

  /** The store node at the store-relative [path]. */
  fun nodeAt(path: String): StoreNode = backend.resolve(path)

  /** The store node at the filesystem [file], which must lie inside the store. */
  fun nodeAtFile(file: File): StoreNode {
    require(file.isInsideRepository()) { "Trying to access target outside the repository" }
    val root = getRepositoryDirectory().canonicalFile.toPath()
    return backend.resolve(root.relativize(file.canonicalFile.toPath()).toString())
  }

  /**
   * Normalises a store path to the form [StoreNode.path] uses: `/`-separated, store-relative, no
   * leading or trailing separator, `""` for the store root.
   */
  fun getRelativePath(path: String): String =
    path.replace("/+".toRegex(), "/").trim('/').takeIf { it.isNotEmpty() && it != "." } ?: ""

  /** `a/b/c.gpg` -> `a/b/c`, i.e. the store-relative path without the `.gpg` extension. */
  fun getLongName(path: String): String = getRelativePath(path).removeSuffix(".gpg")

  /** `a/b/c.gpg` -> `a/b/`, an entry at the store root -> `""`. */
  fun getParentPath(path: String): String {
    val relative = getRelativePath(path)
    val index = relative.lastIndexOf("/")
    return if (index < 0) "" else relative.substring(0, index + 1)
  }

  fun initialize(): Repository? {
    // A store is set up once it holds something. An empty directory — or an empty picked folder —
    // is one that setup has not finished, so the password list must not open on it.
    settings.edit { putBoolean(PreferenceKeys.REPOSITORY_INITIALIZED, !isEmpty()) }
    // A SAF store has no git repository and none can be created for it, so there is nothing to
    // open here. isGitRepo() is what gates every git operation, and it stays false.
    if (isSafStore) return repository
    // Create the `repository` static variable in PasswordRepository
    initializeRepository(getRepositoryDirectory().resolve(".git"))

    return repository
  }

  /** Whether the store contains no entries at all. */
  fun isEmpty(): Boolean = backend.root.children().isEmpty()

  /** Get the currently checked out branch. */
  fun getCurrentBranch(): String? {
    val repository = repository ?: return null
    val headRef = repository.findRef(Constants.HEAD) ?: return null
    return if (headRef.isSymbolic) {
      val branchName = headRef.target.name
      Repository.shortenRefName(branchName)
    } else {
      null
    }
  }

  /** If repo is tracking a remote branch, return commit count to be pushed, zero otherwise */
  fun getAheadCount(): Int = runCatching {
    repository?.let { repo ->
      getCurrentBranch()?.let { branch ->
        BranchTrackingStatus.of(repo, branch)?.getAheadCount()
      }
    } ?: 0
  }
    .getOrElse { e ->
      e.printStackTrace()
      0
    }

  /**
   * Gets the .gpg files in a directory
   *
   * @param path the directory path
   * @return the list of gpg files in that directory
   */
  private fun getFilesList(path: File): ArrayList<File> {
    if (!path.exists()) return ArrayList()
    val files =
      (path.listFiles { file -> file.isDirectory || file.extension == "gpg" } ?: emptyArray())
        .toList()
    val items = ArrayList<File>()
    items.addAll(files)
    return items
  }

  /**
   * Gets the passwords (PasswordItem) in a directory
   *
   * @param path the directory path
   * @return a list of password items
   */
  fun getPasswords(
    path: File,
    rootDir: File,
    sortOrder: PasswordSortOrder,
  ): ArrayList<PasswordItem> {
    // We need to recover the passwords then parse the files
    val passList = getFilesList(path).also { it.sortBy { f -> f.name } }
    val passwordList = ArrayList<PasswordItem>()
    val showHidden = settings.getBoolean(PreferenceKeys.SHOW_HIDDEN_CONTENTS, false)

    if (passList.size == 0) return passwordList
    if (!showHidden) {
      passList.filter { !it.isHidden }.toCollection(passList.apply { clear() })
    }
    passList.forEach { file ->
      val node = nodeAtFile(file)
      passwordList.add(
        if (file.isFile) {
          if (file.name == GPG_ID) PasswordItem.newGpgIdItem(file.name, node)
          else if (file.extension == "gpg") PasswordItem.newPassword(file.name, node)
          else PasswordItem.newOtherItem(file.name, node)
        } else {
          PasswordItem.newCategory(file.name, node)
        }
      )
    }
    passwordList.sortWith(sortOrder.comparator)
    return passwordList
  }

  /**
   * Every entry of the subtree rooted at [startPath] whose own name matches [name].
   *
   * @param startPath store-relative path to search from
   * @param name entry name to look for
   * @param type [TYPE_FILE], [TYPE_DIR], or both to accept either
   */
  fun findByName(
    startPath: String,
    name: String,
    type: Int = TYPE_DIR or TYPE_FILE,
    ignoreCase: Boolean = false,
  ): List<StoreNode> =
    findInSubtree(startPath, type) { it.name.equals(name, ignoreCase = ignoreCase) }

  /**
   * Every entry of the subtree rooted at [startPath] whose *parent directory* is named [name].
   *
   * The store root has no parent within the store and therefore never matches.
   */
  fun findByParentName(
    startPath: String,
    name: String,
    type: Int = TYPE_DIR or TYPE_FILE,
    ignoreCase: Boolean = false,
  ): List<StoreNode> =
    findInSubtree(startPath, type) {
      it.parent()?.name?.equals(name, ignoreCase = ignoreCase) == true
    }

  private fun findInSubtree(
    startPath: String,
    type: Int,
    matches: (StoreNode) -> Boolean,
  ): List<StoreNode> = nodeAt(startPath).walk { it.matchesType(type) && matches(it) }
}

private fun StoreNode.matchesType(type: Int): Boolean =
  when (type) {
    PasswordRepository.TYPE_FILE -> isFile
    PasswordRepository.TYPE_DIR -> isDirectory
    else -> true
  }
