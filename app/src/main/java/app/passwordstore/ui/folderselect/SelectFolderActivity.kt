/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.folderselect

import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import androidx.activity.OnBackPressedCallback
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.commit
import androidx.lifecycle.flowWithLifecycle
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.data.repo.store.StoreNode
import app.passwordstore.ui.dialogs.FolderCreationDialogFragment
import app.passwordstore.ui.passwords.PASSWORD_FRAGMENT_TAG
import app.passwordstore.ui.passwords.PasswordStore
import app.passwordstore.util.extensions.contains
import app.passwordstore.util.viewmodel.SearchableRepositoryViewModel
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class SelectFolderActivity : AppCompatActivity(R.layout.select_folder_layout) {

  private lateinit var passwordList: SelectFolderFragment
  private val model: SearchableRepositoryViewModel by viewModels()

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)

    passwordList = SelectFolderFragment()
    intent.getStringExtra(PasswordStore.REQUEST_ARG_PATH)?.let { relPath ->
      val args = Bundle()
      args.putString(PasswordStore.REQUEST_ARG_PATH, relPath)
      passwordList.arguments = args
    }

    onBackPressedDispatcher.addCallback(
      this,
      object : OnBackPressedCallback(true) {
        override fun handleOnBackPressed() {
          if (passwordList?.onBackPressedInActivity() != true) {
            finishAndRemoveTask()
          }
        }
      },
    )

    supportFragmentManager.popBackStack(null, FragmentManager.POP_BACK_STACK_INCLUSIVE)

    supportFragmentManager.commit {
      replace(R.id.pgp_handler_linearlayout, passwordList, PASSWORD_FRAGMENT_TAG)
    }

    supportActionBar?.show()

    lifecycleScope.launch { // Update action bar title with current dir name
      model.currentDir.flowWithLifecycle(lifecycle).collect { dir ->
        val basePath = PasswordRepository.storeRoot
        supportActionBar?.apply {
          if (dir != basePath) title = dir.name else setTitle(R.string.app_name)
        }
      }
    }
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.pgp_handler_select_folder, menu)
    return true
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    when (item.itemId) {
      android.R.id.home -> {
        onBackPressedDispatcher.onBackPressed()
      }
      R.id.crypto_cancel -> {
        setResult(RESULT_CANCELED)
        finish()
      }
      R.id.crypto_select -> selectFolder()
      else -> return super.onOptionsItemSelected(item)
    }
    return true
  }

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
        }
      }
    } else if (model.currentDir.value.isDirectory) {
      model.forceRefresh()
    } else {
      model.reset()
    }
    supportActionBar?.setDisplayHomeAsUpEnabled(model.canNavigateBack)
  }

  private fun selectFolder() {
    intent.putExtra(SELECTED_FOLDER_PATH, passwordList.currentDir.path)
    setResult(RESULT_OK, intent)
    finish()
  }

  fun createFolder() {
    if (PasswordRepository.isEmpty()) return
    FolderCreationDialogFragment.newInstance(passwordList.currentDir.path, setGpgKey = true)
      .show(supportFragmentManager, null)
  }

  companion object {

    const val SELECTED_FOLDER_PATH = "SELECTED_FOLDER_PATH"
  }
}
