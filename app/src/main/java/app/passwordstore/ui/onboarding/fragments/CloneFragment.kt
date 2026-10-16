/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.onboarding.fragments

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import androidx.core.view.ViewCompat
import androidx.fragment.app.Fragment
import app.passwordstore.R
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.data.repo.store.GPG_ID
import app.passwordstore.data.repo.store.SafStoreBackend
import app.passwordstore.data.repo.store.StoreMode
import app.passwordstore.databinding.FragmentCloneBinding
import app.passwordstore.ui.git.config.GitServerConfigActivity
import app.passwordstore.util.extensions.finish
import app.passwordstore.util.extensions.performTransactionWithBackStack
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.windowInsetsLambda
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.get
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

class CloneFragment : Fragment(R.layout.fragment_clone) {

  private val binding by viewBinding(FragmentCloneBinding::bind)

  private val settings by unsafeLazy { requireActivity().applicationContext.sharedPrefs }

  private val cloneAction =
    registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
      if (result.resultCode == AppCompatActivity.RESULT_OK) {
        if (PasswordRepository.storeRoot.findChild(GPG_ID)?.isFile == true) {
          settings.edit { putBoolean(PreferenceKeys.REPOSITORY_INITIALIZED, true) }
          finish()
        } else {
          // non-pass repository --> go to key selection
          runCatching {
            parentFragmentManager.performTransactionWithBackStack(
              KeySelectionFragment.newInstance()
            )
          }
            .onErr { e -> logcat(ERROR) { e.asLog() } }
        }
      }
    }

  private val useLocalFolderAction =
    registerForActivityResult(
      object : ActivityResultContracts.OpenDocumentTree() {
        override fun createIntent(context: Context, input: Uri?): Intent {
          return super.createIntent(context, input).apply {
            flags =
              Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
          }
        }
      }
    ) { uri: Uri? ->
      if (uri != null) useLocalFolder(uri)
    }

  override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
    super.onViewCreated(view, savedInstanceState)
    ViewCompat.setOnApplyWindowInsetsListener(view, windowInsetsLambda)

    binding.cloneRemote.setOnClickListener { cloneToHiddenDir() }
    binding.createLocal.setOnClickListener { createRepository() }
    binding.useLocalFolder.setOnClickListener { useLocalFolderAction.launch(null) }
  }

  /**
   * Keeps the store in the folder the user picked.
   *
   * The grant is persisted, so the folder stays reachable across restarts and reboots. Unlike a
   * clone into app-private storage, this folder is never git-backed: jgit cannot open a Storage
   * Access Framework tree.
   *
   * An empty folder is a store that has not been initialised yet, exactly like the app-private one:
   * key selection writes the first `.gpg-id` into it.
   */
  private fun useLocalFolder(uri: Uri) {
    val root =
      runCatching { SafStoreBackend(uri).root }
        .onErr { e ->
          logcat(ERROR) { e.asLog() }
          MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.saf_store_invalid_folder_title)
            .setMessage(R.string.saf_store_invalid_folder_message)
            .setPositiveButton(R.string.dialog_ok) { dialog, _ -> dialog.dismiss() }
            .show()
        }
        .get() ?: return

    val resolver = requireContext().contentResolver
    runCatching {
      resolver.takePersistableUriPermission(
        uri,
        Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
      )
    }
      .onErr { e -> logcat(ERROR) { e.asLog() } }

    settings.edit {
      putString(PreferenceKeys.STORE_MODE, StoreMode.SAF.name)
      putString(PreferenceKeys.STORE_URI, uri.toString())
    }
    PasswordRepository.resetBackend()

    if (root.findChild(GPG_ID) == null) {
      // Not a pass store yet: let the user pick the keys that will encrypt it.
      parentFragmentManager.performTransactionWithBackStack(KeySelectionFragment.newInstance())
    } else {
      finish()
    }
  }

  /** Clones a remote Git repository to the app's private directory */
  private fun cloneToHiddenDir() {
    cloneAction.launch(GitServerConfigActivity.createCloneIntent(requireContext()))
  }

  private fun createRepository() {
    val localDir = PasswordRepository.getRepositoryDirectory()
    runCatching {
      check(localDir.exists() || localDir.mkdir()) { "Failed to create directory!" }
      PasswordRepository.createRepository(localDir)
      if (!PasswordRepository.isInitialized) {
        PasswordRepository.initialize()
      }
      parentFragmentManager.performTransactionWithBackStack(KeySelectionFragment.newInstance())
    }
      .onErr { e ->
        logcat(ERROR) { e.asLog() }
        if (!localDir.delete()) {
          logcat { "Failed to delete local repository: $localDir" }
        }
        finish()
      }
  }

  companion object {

    fun newInstance(): CloneFragment = CloneFragment()
  }
}
