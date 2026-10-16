/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.passwords

import android.content.ComponentName
import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.view.KeyEvent
import android.view.Menu
import android.view.MenuItem
import android.view.MenuItem.OnActionExpandListener
import android.view.WindowManager
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SearchView
import androidx.appcompat.widget.SearchView.OnQueryTextListener
import androidx.core.content.edit
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.commit
import androidx.lifecycle.flowWithLifecycle
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.data.password.PasswordItem
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.data.repo.store.StoreNode
import app.passwordstore.data.repo.store.requireFile
import app.passwordstore.data.repo.store.writeGpgId
import app.passwordstore.databinding.ActivityPwdstoreBinding
import app.passwordstore.injection.prefs.CredentialUsernames
import app.passwordstore.injection.prefs.PasswordHistory
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.ui.crypto.DecryptActivity
import app.passwordstore.ui.crypto.PasswordCreationActivity
import app.passwordstore.ui.dialogs.FolderCreationDialogFragment
import app.passwordstore.ui.folderselect.SelectFolderActivity
import app.passwordstore.ui.git.base.BaseGitActivity
import app.passwordstore.ui.onboarding.activity.OnboardingActivity
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.ui.settings.SettingsActivity
import app.passwordstore.util.autofill.AutofillMatcher
import app.passwordstore.util.extensions.base64
import app.passwordstore.util.extensions.commitChange
import app.passwordstore.util.extensions.enableEdgeToEdgeView
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.launchActivity
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.settings.AuthMode
import app.passwordstore.util.settings.PreferenceKeys
import app.passwordstore.util.shortcuts.ShortcutHandler
import app.passwordstore.util.viewmodel.FilterMode
import app.passwordstore.util.viewmodel.SearchableRepositoryViewModel
import com.github.michaelbull.result.fold
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import dagger.hilt.android.AndroidEntryPoint
import java.lang.Character.UnicodeBlock
import javax.inject.Inject
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.LogPriority.INFO
import logcat.logcat

const val PASSWORD_FRAGMENT_TAG = "PasswordsList"

@AndroidEntryPoint
class PasswordStore : BaseGitActivity() {

  @Inject @PasswordHistory lateinit var passwordHistory: SharedPreferences
  @Inject @CredentialUsernames lateinit var credentialUsernames: SharedPreferences
  @Inject lateinit var shortcutHandler: ShortcutHandler
  private lateinit var searchItem: MenuItem
  private val settings by lazy { sharedPrefs }

  private val binding by viewBinding(ActivityPwdstoreBinding::inflate)
  private val model: SearchableRepositoryViewModel by viewModels()

  private val gpgKeySelectAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == AppCompatActivity.RESULT_OK) {
        val data = result.data ?: return@registerForActivityResult
        val selectedKeyId =
          data.getStringExtra(PGPKeyListActivity.EXTRA_SELECTED_KEY)
            ?: return@registerForActivityResult
        currentDir.writeGpgId(selectedKeyId)
        runBlocking {
          commitChange(getString(R.string.git_commit_gpg_id, getString(R.string.app_name)))
        }
        refreshPasswordList()
      }
    }

  private val listRefreshAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == RESULT_OK) {
        refreshPasswordList()
      }
    }

  private val passwordMoveAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      val intentData = result.data ?: return@registerForActivityResult
      val filesToMove =
        requireNotNull(intentData.getStringArrayExtra("Files")) {
          "'Files' intent extra must be set"
        }
      val target =
        PasswordRepository.nodeAt(
          requireNotNull(intentData.getStringExtra(SelectFolderActivity.SELECTED_FOLDER_PATH)) {
            "'SELECTED_FOLDER_PATH' intent extra must be set"
          }
        )
      if (!target.isDirectory) {
        logcat(ERROR) { "Tried moving passwords to a non-existing folder." }
        return@registerForActivityResult
      }

      logcat { "Moving passwords to ${intentData.getStringExtra("SELECTED_FOLDER_PATH")}" }
      logcat { filesToMove.joinToString(", ") }

      lifecycleScope.launch(dispatcherProvider.io()) {
        for (file in filesToMove) {
          val source = PasswordRepository.nodeAt(file)
          if (!source.exists()) {
            logcat(ERROR) { "Tried moving something that appears non-existent." }
            continue
          }
          val destination = PasswordRepository.nodeAt("${target.path}/${source.name}")
          val sourceLongName = PasswordRepository.getLongName(source.path)
          val destinationLongName = PasswordRepository.getLongName(destination.path)
          if (destination.exists()) {
            logcat(ERROR) { "Trying to move a file that already exists." }
            withContext(dispatcherProvider.main()) {
              MaterialAlertDialogBuilder(this@PasswordStore)
                .setTitle(R.string.password_exists_title)
                .setMessage(
                  getString(
                    R.string.password_exists_message,
                    destinationLongName,
                    sourceLongName,
                  )
                )
                .setPositiveButton(R.string.dialog_ok) { _, _ ->
                  launch(dispatcherProvider.io()) { moveFile(source, destination) }
                }
                .setNegativeButton(R.string.dialog_cancel, null)
                .show()
            }
          } else {
            launch(dispatcherProvider.io()) { moveFile(source, destination) }
          }
        }
        when (filesToMove.size) {
          1 -> {
            val source = PasswordRepository.nodeAt(filesToMove[0])
            val destination = PasswordRepository.nodeAt("${target.path}/${source.name}")
            val sourceLongName = PasswordRepository.getLongName(source.path)
            val destinationLongName = PasswordRepository.getLongName(destination.path)
            withContext(dispatcherProvider.main()) {
              commitChange(
                getString(
                  R.string.git_commit_move_text,
                  sourceLongName,
                  destinationLongName,
                )
              )
              updateFabSync()
            }
          }
          else -> {
            val relativePath = PasswordRepository.getRelativePath("${target.path}/")
            withContext(dispatcherProvider.main()) {
              commitChange(getString(R.string.git_commit_move_multiple_text, relativePath))
              updateFabSync()
            }
          }
        }
      }
      getPasswordFragment()?.dismissActionMode()
      val firstMoved =
        PasswordRepository.nodeAt(filesToMove[0]).let {
          PasswordRepository.nodeAt("${target.path}/${it.name}")
        }
      getPasswordFragment()?.scrollToOnNextRefresh(firstMoved)
      refreshPasswordList(target)
    }

  override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
    // open search view on search key, or Ctr+F
    if (
      (keyCode == KeyEvent.KEYCODE_SEARCH ||
        keyCode == KeyEvent.KEYCODE_F && event.isCtrlPressed) && !searchItem.isActionViewExpanded
    ) {
      searchItem.expandActionView()
      return true
    }

    // open search view on any printable character and query for it
    val c = event.unicodeChar.toChar()
    val printable = isPrintable(c)
    if (printable && !searchItem.isActionViewExpanded) {
      searchItem.expandActionView()
      (searchItem.actionView as SearchView).setQuery(c.toString(), true)
      return true
    }
    return super.onKeyDown(keyCode, event)
  }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    enableEdgeToEdgeView(binding.root)
    setContentView(binding.root)

    onBackPressedDispatcher.addCallback(
      this,
      object : OnBackPressedCallback(true) {
        override fun handleOnBackPressed() {
          if (getPasswordFragment()?.onBackPressedInActivity() != true) {
            finishAndRemoveTask()
          }
        }
      },
    )

    lifecycleScope.launch {
      model.currentDir.flowWithLifecycle(lifecycle).collect { dir ->
        val basePath = PasswordRepository.storeRoot
        supportActionBar?.apply {
          if (dir != basePath) title = dir.name else setTitle(R.string.app_name)
        }
      }
    }
  }

  override fun onStart() {
    super.onStart()
    refreshPasswordList()
  }

  override fun onResume() {
    super.onResume()
    checkLocalRepository()
    refreshPasswordList()
    if (settings.getBoolean(PreferenceKeys.SEARCH_ON_START, false) && ::searchItem.isInitialized) {
      if (!searchItem.isActionViewExpanded) {
        searchItem.expandActionView()
      }
    }
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    val menuRes =
      when {
        gitSettings.authMode == AuthMode.None -> R.menu.main_menu_no_auth
        PasswordRepository.isGitRepo() -> R.menu.main_menu_git
        else -> R.menu.main_menu_non_git
      }
    menuInflater.inflate(menuRes, menu)
    return super.onCreateOptionsMenu(menu)
  }

  override fun onPrepareOptionsMenu(menu: Menu): Boolean {
    // Invalidation forces onCreateOptionsMenu to be called again. This is cheap and quick so
    // we can get by without any noticeable difference in performance.
    invalidateOptionsMenu()
    searchItem = menu.findItem(R.id.action_search)
    val searchView = searchItem.actionView as SearchView
    searchView.setOnQueryTextListener(
      object : OnQueryTextListener {
        override fun onQueryTextSubmit(s: String): Boolean {
          searchView.clearFocus()
          return true
        }

        override fun onQueryTextChange(s: String): Boolean {
          val filter = s.trim()
          val filterMode =
            if (settings.getString(PreferenceKeys.SEARCH_FILTER_MODE, "exact") == "fuzzy")
              FilterMode.Fuzzy
            else FilterMode.Exact
          // List the contents of the current directory if the user enters a blank
          // search term.
          if (filter.isEmpty())
            model.navigateTo(newDirectory = model.currentDir.value, pushPreviousLocation = false)
          else model.search(filter, filterMode = filterMode)
          return true
        }
      }
    )

    // When using the support library, the setOnActionExpandListener() method is
    // static and accepts the MenuItem object as an argument
    searchItem.setOnActionExpandListener(
      object : OnActionExpandListener {
        override fun onMenuItemActionCollapse(item: MenuItem): Boolean {
          refreshPasswordList()
          return true
        }

        override fun onMenuItemActionExpand(item: MenuItem): Boolean {
          return true
        }
      }
    )
    if (
      settings.getBoolean(PreferenceKeys.SEARCH_ON_START, false) ||
        intent.action == Intent.ACTION_SEARCH
    ) {
      searchItem.expandActionView()
    }
    return super.onPrepareOptionsMenu(menu)
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    val id = item.itemId
    val initBefore =
      MaterialAlertDialogBuilder(this)
        .setCancelable(false)
        .setTitle(R.string.error)
        .setIcon(R.drawable.ic_crossmark_red_24dp)
        .setMessage(R.string.creation_dialog_text)
        .setPositiveButton(R.string.dialog_ok, null)
    when (id) {
      R.id.user_pref -> {
        runCatching { launchActivity(SettingsActivity::class.java) }
          .onErr { e -> e.printStackTrace() }
      }
      R.id.git_push -> {
        if (!PasswordRepository.isInitialized) {
          initBefore.show()
        } else {
          runGitOperation(GitOp.PUSH)
        }
      }
      R.id.git_pull -> {
        if (!PasswordRepository.isInitialized) {
          initBefore.show()
        } else {
          runGitOperation(GitOp.PULL)
        }
      }
      R.id.git_sync -> {
        if (!PasswordRepository.isInitialized) {
          initBefore.show()
        } else {
          runGitOperation(GitOp.SYNC)
        }
      }
      R.id.refresh -> refreshPasswordList()
      android.R.id.home -> {
        onBackPressedDispatcher.onBackPressed()
      }
      else -> return super.onOptionsItemSelected(item)
    }
    return true
  }

  private fun getPasswordFragment(): PasswordFragment? {
    return supportFragmentManager.findFragmentByTag(PASSWORD_FRAGMENT_TAG) as? PasswordFragment
  }

  fun clearSearch() {
    if (searchItem.isActionViewExpanded) searchItem.collapseActionView()
  }

  fun runGitOperation(operation: GitOp) = lifecycleScope.launch {
    launchGitOperation(operation)
      .fold(success = { refreshPasswordList() }, failure = { promptOnErrorHandler(it) })
  }

  private fun checkLocalRepository() {
    PasswordRepository.initialize()
    checkLocalRepository(PasswordRepository.storeRoot)
  }

  private fun checkLocalRepository(localRoot: StoreNode?) {
    if (localRoot != null && settings.getBoolean(PreferenceKeys.REPOSITORY_INITIALIZED, false)) {
      // do not push the fragment if we already have it
      if (
        getPasswordFragment() == null || settings.getBoolean(PreferenceKeys.REPO_CHANGED, false)
      ) {
        settings.edit { putBoolean(PreferenceKeys.REPO_CHANGED, false) }
        val args = Bundle()
        args.putString(REQUEST_ARG_PATH, PasswordRepository.storeRoot.path)

        // if the activity was started from the autofill settings, the
        // intent is to match a clicked pwd with app. pass this to fragment
        if (intent.getBooleanExtra("matchWith", false)) {
          args.putBoolean("matchWith", true)
        }
        supportActionBar?.apply {
          show()
          setDisplayHomeAsUpEnabled(false)
        }
        supportFragmentManager.popBackStack(null, FragmentManager.POP_BACK_STACK_INCLUSIVE)
        supportFragmentManager.commit {
          replace(R.id.main_layout, PasswordFragment.newInstance(args), PASSWORD_FRAGMENT_TAG)
        }
      }
    } else {
      launchActivity(OnboardingActivity::class.java)
    }
  }

  fun decryptPassword(item: PasswordItem) {
    val authDecryptIntent = item.createAuthEnabledIntent(this)
    val decryptIntent =
      Intent(authDecryptIntent).setComponent(ComponentName(this, DecryptActivity::class.java))

    startActivity(decryptIntent)

    // Adds shortcut
    shortcutHandler.addDynamicShortcut(item, authDecryptIntent)
  }

  private fun validateState(): Boolean {
    if (!PasswordRepository.isInitialized) {
      MaterialAlertDialogBuilder(this)
        .setCancelable(false)
        .setTitle(R.string.error)
        .setIcon(R.drawable.ic_crossmark_red_24dp)
        .setMessage(R.string.creation_dialog_text)
        .setPositiveButton(R.string.dialog_ok, null)
        .show()
      return false
    }
    return true
  }

  fun createPassword() {
    if (!validateState()) return
    val currentDir = currentDir
    logcat(INFO) { "Adding file to : ${currentDir.path}" }
    val intent = Intent(this, PasswordCreationActivity::class.java)
    intent.putExtra(BasePGPActivity.EXTRA_FILE_PATH, currentDir.path)
    intent.putExtra(BasePGPActivity.EXTRA_REPO_PATH, currentDir.path)
    listRefreshAction.launch(intent)
  }

  fun createFolder() {
    if (!validateState()) return
    FolderCreationDialogFragment.newInstance(currentDir.path, setGpgKey = true)
      .show(supportFragmentManager, null)
  }

  fun deletePasswords(selectedItems: List<PasswordItem>) {
    var size = 0
    selectedItems.forEach {
      if (it.node.isFile) size++ else size += it.node.walk { node -> node.isFile }.size
    }
    if (size == 0) { // delete empty directory trees without confirmation
      selectedItems.map { item -> item.node.deleteRecursively() }
      refreshPasswordList()
      return
    }
    MaterialAlertDialogBuilder(this)
      .setTitle(R.string.delete_dialog_title)
      .setMessage(resources.getQuantityString(R.plurals.delete_dialog_text, size, size))
      .setPositiveButton(R.string.dialog_yes) { _, _ ->
        val nodesToDelete = arrayListOf<StoreNode>()
        selectedItems.forEach { item ->
          if (item.node.isDirectory) nodesToDelete.addAll(item.node.walk { node -> node.isFile })
          else nodesToDelete.add(item.node)
        }
        // remove to-be-deleted files from history
        passwordHistory.edit {
          nodesToDelete.forEach { node ->
            remove(node.path.base64())
          }
        }
        // remove cached passkey hex ID (filename without extension) <--> webauthn username
        // associations
        credentialUsernames.edit {
          nodesToDelete.forEach { node ->
            val fileBasename = node.name.substringBeforeLast('.', node.name)
            if (fileBasename.matches("[a-fA-F0-9]{64}".toRegex())) remove(fileBasename)
          }
        }
        selectedItems.map { item -> item.node.deleteRecursively() }
        refreshPasswordList()
        AutofillMatcher.updateMatches(applicationContext, delete = nodesToDelete.map { it.path })
        val fmt = selectedItems.joinToString(separator = ", ") { item -> item.node.path }
        lifecycleScope.launch {
          commitChange(getString(R.string.git_commit_remove_text, fmt))
          updateFabSync()
        }
      }
      .setNegativeButton(R.string.dialog_no, null)
      .show()
  }

  fun movePasswords(values: List<PasswordItem>) {
    val intent = Intent(this, SelectFolderActivity::class.java)
    val fileLocations = values.map { it.node.path }.toTypedArray()
    intent.putExtra("Files", fileLocations)
    val relPath = currentDir.path
    if (!relPath.isEmpty()) intent.putExtra(PasswordStore.REQUEST_ARG_PATH, relPath)
    passwordMoveAction.launch(intent)
  }

  enum class CategoryRenameError(val resource: Int) {
    None(0),
    EmptyField(R.string.message_category_error_empty_field),
    CategoryExists(R.string.message_category_error_category_exists),
    DestinationOutsideRepo(R.string.message_error_destination_outside_repo),
  }

  /**
   * Prompt the user with a new category name to assign, if the new category forms/leads a path
   * (i.e. contains "/"), intermediate directories will be created and new category will be placed
   * inside.
   *
   * @param oldCategory The category to change its name
   * @param error Determines whether to show an error to the user in the alert dialog, this error
   *   may be due to the new category the user entered already exists or the field was empty or the
   *   destination path is outside the repository
   * @see [CategoryRenameError]
   * @see [isInsideRepository]
   */
  private fun renameCategory(
    oldCategory: PasswordItem,
    error: CategoryRenameError = CategoryRenameError.None,
  ) {
    val view = layoutInflater.inflate(R.layout.folder_dialog_fragment, null)
    val newCategoryEditText = view.findViewById<TextInputEditText>(R.id.folder_name_text)
    val folderNameViewContainer = view.findViewById<TextInputLayout>(R.id.folder_name_container)

    if (error != CategoryRenameError.None) {
      folderNameViewContainer.error = getString(error.resource)
    }

    val dialog =
      MaterialAlertDialogBuilder(this)
        .setTitle(R.string.title_rename_folder)
        .setView(view)
        .setMessage(getString(R.string.message_rename_folder, oldCategory.name))
        .setPositiveButton(R.string.dialog_ok) { _, _ ->
          val parent = oldCategory.node.parent() ?: PasswordRepository.storeRoot
          val newName =
            PasswordRepository.getRelativePath(newCategoryEditText.text?.toString().orEmpty())
          val newCategory = PasswordRepository.nodeAt("${parent.path}/$newName")
          when {
            // A backend clamps a path that climbs out of the store; tell the user instead of
            // silently moving the category somewhere else.
            newName.split('/').any { it == ".." } ->
              renameCategory(oldCategory, CategoryRenameError.DestinationOutsideRepo)
            newCategoryEditText.text.isNullOrBlank() ->
              renameCategory(oldCategory, CategoryRenameError.EmptyField)
            newCategory.exists() -> renameCategory(oldCategory, CategoryRenameError.CategoryExists)
            else ->
              lifecycleScope.launch(dispatcherProvider.io()) {
                moveFile(oldCategory.node, newCategory)

                // associate the new category with the last category's timestamp in
                // history
                val timestamp = passwordHistory.getString(oldCategory.node.path.base64())
                if (timestamp != null) {
                  passwordHistory.edit {
                    remove(oldCategory.node.path.base64())
                    putString(newCategory.path.base64(), timestamp)
                  }
                }

                withContext(dispatcherProvider.main()) {
                  commitChange(
                    getString(
                      R.string.git_commit_move_text,
                      oldCategory.name,
                      newCategory.name,
                    )
                  )
                  updateFabSync()
                }

                refreshPasswordList()
              }
          }
        }
        .setNegativeButton(R.string.dialog_cancel, null)
        .create()

    dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)
    dialog.show()
  }

  fun renameCategory(categories: List<PasswordItem>) {
    for (oldCategory in categories) {
      renameCategory(oldCategory)
    }
  }

  private fun updateFabSync() {
    runOnUiThread { getPasswordFragment()?.updateFabSync() }
  }

  /**
   * Refreshes the password list by re-executing the last navigation or search action, preserving
   * the navigation stack and scroll position. If the current directory no longer exists, navigation
   * is reset to the repository root. If the optional [target] argument is provided, it will be
   * entered if it is a directory or scrolled into view if it is a file.
   */
  fun refreshPasswordList(target: StoreNode? = null) {
    val relativeTargetPath = target?.path
    if (relativeTargetPath != null) {
      model.reset()
      model.navigateTo(PasswordRepository.storeRoot, pushPreviousLocation = false)
      relativeTargetPath.trim('/').split('/').forEach { item ->
        val node = PasswordRepository.nodeAt("${model.currentDir.value.path}/$item")
        if (node.isDirectory) {
          if (node.equals(model.currentDir.value)) model.forceRefresh()
          else model.navigateTo(node, pushPreviousLocation = true)
        } else getPasswordFragment()?.scrollToOnNextRefresh(node)
      }
    } else if (model.currentDir.value.isDirectory) {
      model.forceRefresh()
    } else {
      model.reset()
    }
    supportActionBar?.setDisplayHomeAsUpEnabled(model.canNavigateBack)
    updateFabSync()
  }

  private val currentDir: StoreNode
    get() = getPasswordFragment()?.currentDir ?: PasswordRepository.storeRoot

  /**
   * Moves [source] onto [destination], which must not exist yet.
   *
   * Within one directory a move is a rename, which every backend supports. Across directories the
   * entry has to be copied and the source removed, and a store entry carries bytes rather than text
   * — `.gpg` payloads are binary unless the user asked for ASCII armor — which [StoreNode] cannot
   * write yet. Until it can, that half of the move stays on the filesystem backend and a store that
   * has no filesystem path reports the failure through the existing dialog instead of crashing.
   */
  private suspend fun moveFile(source: StoreNode, destination: StoreNode) {
    val sourceDestinationMap =
      if (source.isDirectory) {
        // Recursively list all files (not directories) below `source`, then
        // obtain the corresponding target file by resolving the relative path
        // starting at the destination folder.
        source
          .walk { node -> node.isFile }
          .associateWith { node ->
            PasswordRepository.nodeAt(
              "${destination.path}/${node.path.removePrefix("${source.path}/")}"
            )
          }
      } else {
        mapOf(source to destination)
      }
    val moved = runCatching {
      if (source.parent()?.path == destination.parent()?.path) {
        source.rename(destination.name)
        true
      } else {
        val sourceFile = source.requireFile()
        val destinationFile = destination.requireFile()
        if (source.isDirectory) destinationFile.mkdirs()
        sourceFile.renameTo(destinationFile)
      }
    }
      .onErr { e -> e.printStackTrace() }
      .getOrElse { false }
    if (!moved) {
      logcat(ERROR) { "Something went wrong while moving $source to $destination." }
      withContext(dispatcherProvider.main()) {
        MaterialAlertDialogBuilder(this@PasswordStore)
          .setTitle(R.string.password_move_error_title)
          .setMessage(getString(R.string.password_move_error_message, source, destination))
          .setCancelable(true)
          .setPositiveButton(android.R.string.ok, null)
          .show()
      }
    } else {
      // update timestamp cache with the new file locations
      passwordHistory.edit {
        sourceDestinationMap.forEach { (src, dest) ->
          val srcPathHash = src.path.base64()
          val timestamp = passwordHistory.getString(srcPathHash)
          remove(srcPathHash)
          putString(dest.path.base64(), timestamp)
        }
      }
      AutofillMatcher.updateMatches(
        this,
        moveFromTo = sourceDestinationMap.mapKeys { it.key.path }.mapValues { it.value.path },
      )
    }
  }

  fun matchPasswordWithApp(item: PasswordItem) {
    val path = item.longName
    val data = Intent()
    data.putExtra("path", path)
    setResult(RESULT_OK, data)
    finish()
  }

  companion object {

    const val REQUEST_ARG_PATH = "PATH"

    private fun isPrintable(c: Char): Boolean {
      val block = UnicodeBlock.of(c)
      return (!Character.isISOControl(c) && block != null && block !== UnicodeBlock.SPECIALS)
    }
  }
}
