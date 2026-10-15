/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.data.repo

import androidx.core.content.edit
import app.passwordstore.Application
import app.passwordstore.data.password.PasswordItem
import app.passwordstore.data.repo.store.FileStoreBackend
import app.passwordstore.data.repo.store.StoreBackend
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
import java.nio.file.Path
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
    get() = repository != null

  fun isGitRepo(): Boolean {
    return repository?.objectDatabase?.exists() ?: false
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

  /**
   * The backend that provides access to the password store.
   *
   * This is the single place where the store's location is decided; callers must not derive the
   * store location themselves. It is resolved lazily because [Application.instance] is unavailable
   * until `Application.onCreate` has begun.
   */
  val backend: StoreBackend by unsafeLazy { FileStoreBackend(File(filesDir.toString(), "/store")) }

  /** The store root as a plain [File]. Throws if the active backend is not file-backed. */
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

  /* referencePath: /a/b/c
   * /a/b/c/d/e/dir -> /d/e/dir
   * /a/b/c/d/e/file.ext -> /d/e/file.ext
   */
  fun getRelativePath(fullPath: String, referencePath: String): String {
    return fullPath.replace(referencePath, "").replace("/+".toRegex(), "/")
  }

  /* referencePath=/a/b/c
   * fullPath=/a/b/c/d/e
   * basename=file
   * -> d/e/file
   */
  fun getLongName(fullPath: String, referencePath: String, basename: String): String {
    var relativePath = getRelativePath(fullPath, referencePath)
    return if (relativePath.isNotEmpty() && relativePath != "/") {
      // remove preceding '/'
      relativePath = relativePath.substring(1)
      if (relativePath.endsWith('/')) {
        relativePath + basename
      } else {
        "$relativePath/$basename"
      }
    } else {
      basename
    }
  }

  /* referencePath: /a/b/c
   * /a/b/c/d/e/file.ext -> /d/e/
   */
  fun getParentPath(fullPath: String, referencePath: String): String {
    val relativePath = getRelativePath(fullPath, referencePath)
    val index = relativePath.lastIndexOf("/")
    return "/${relativePath.substring(startIndex = 0, endIndex = index + 1)}/"
      .replace("/+".toRegex(), "/")
  }

  fun initialize(): Repository? {
    // Un-initialize the repo if the dir does not exist or is absolutely empty
    settings.edit { putBoolean(PreferenceKeys.REPOSITORY_INITIALIZED, !isEmpty()) }
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
      passwordList.add(
        if (file.isFile) {
          if (file.name == ".gpg-id") PasswordItem.newGpgIdItem(file.name, file, rootDir)
          else if (file.extension == "gpg") PasswordItem.newPassword(file.name, file, rootDir)
          else PasswordItem.newOtherItem(file.name, file, rootDir)
        } else {
          PasswordItem.newCategory(file.name, file, rootDir)
        }
      )
    }
    passwordList.sortWith(sortOrder.comparator)
    return passwordList
  }

  /**
   * Every entry of the subtree rooted at [startPath] whose own name matches [name].
   *
   * @param startPath absolute path inside the store to search from
   * @param name entry name to look for
   * @param type [TYPE_FILE], [TYPE_DIR], or both to accept either
   */
  fun findByName(
    startPath: String,
    name: String,
    type: Int = TYPE_DIR or TYPE_FILE,
    ignoreCase: Boolean = false,
  ): List<Path> = findInSubtree(startPath, type) { it.name.equals(name, ignoreCase = ignoreCase) }

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
  ): List<Path> =
    findInSubtree(startPath, type) {
      it.parent()?.name?.equals(name, ignoreCase = ignoreCase) == true
    }

  private fun findInSubtree(
    startPath: String,
    type: Int,
    matches: (StoreNode) -> Boolean,
  ): List<Path> =
    nodeAtFile(File(startPath))
      .walk { it.matchesType(type) && matches(it) }
      .map { it.requireFile().toPath() }
}

private fun StoreNode.matchesType(type: Int): Boolean =
  when (type) {
    PasswordRepository.TYPE_FILE -> isFile
    PasswordRepository.TYPE_DIR -> isDirectory
    else -> true
  }
