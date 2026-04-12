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
import app.passwordstore.ui.passwords.PASSWORD_FRAGMENT_TAG
import app.passwordstore.ui.passwords.PasswordStore
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
    val args = Bundle()
    args.putString(
      PasswordStore.REQUEST_ARG_PATH,
      PasswordRepository.getRepositoryDirectory().absolutePath,
    )

    passwordList.arguments = args

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

    supportActionBar?.apply {
      show()
      setDisplayHomeAsUpEnabled(false) // Back arrow in the upper left corner
    }

    supportFragmentManager.popBackStack(null, FragmentManager.POP_BACK_STACK_INCLUSIVE)

    supportFragmentManager.commit {
      replace(R.id.pgp_handler_linearlayout, passwordList, PASSWORD_FRAGMENT_TAG)
    }

    lifecycleScope.launch { // Update action bar title with current dir name
      model.currentDir.flowWithLifecycle(lifecycle).collect { dir ->
        val basePath = PasswordRepository.getRepositoryDirectory().absoluteFile
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

  private fun selectFolder() {
    intent.putExtra("SELECTED_FOLDER_PATH", passwordList.currentDir.absolutePath)
    setResult(RESULT_OK, intent)
    finish()
  }
}
