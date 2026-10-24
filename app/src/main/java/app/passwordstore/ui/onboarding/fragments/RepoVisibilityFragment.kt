/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.onboarding.fragments

import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import androidx.core.view.ViewCompat
import androidx.fragment.app.Fragment
import app.passwordstore.R
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.databinding.FragmentRepoVisibilityBinding
import app.passwordstore.ui.git.config.GitServerConfigActivity
import app.passwordstore.util.extensions.finish
import app.passwordstore.util.extensions.performTransactionWithBackStack
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.windowInsetsLambda
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import java.io.File
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

class RepoVisibilityFragment : Fragment(R.layout.fragment_repo_visibility) {

  private val binding by viewBinding(FragmentRepoVisibilityBinding::bind)

  private val settings by unsafeLazy { requireActivity().applicationContext.sharedPrefs }

  private val cloneAction =
    registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
      if (result.resultCode == AppCompatActivity.RESULT_OK) {
        if (File(PasswordRepository.getRepositoryDirectory(), ".gpg-id").isFile()) {
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

  override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
    super.onViewCreated(view, savedInstanceState)
    ViewCompat.setOnApplyWindowInsetsListener(view, windowInsetsLambda)

    with(binding) {
      if (requireArguments().getBoolean(SHOULD_CLONE_EXTRA))
        repoVisibilityText.setText(R.string.select_repo_visibility_clone_text)
      else repoVisibilityText.setText(R.string.select_repo_visibility_create_text)

      internalRepo.setOnCheckedChangeListener { _, isChecked ->
        if (isChecked) {
          settings.edit { putBoolean(PreferenceKeys.PREF_SHARED_REPO, false) }
          repoSharedParent.visibility = View.INVISIBLE
        }
      }

      sharedRepo.setOnCheckedChangeListener { _, isChecked ->
        if (isChecked) {
          settings.edit { putBoolean(PreferenceKeys.PREF_SHARED_REPO, true) }
          repoSharedParent.text = getString(R.string.shared_repo_path, android.os.Build.MODEL)
          repoSharedParent.visibility = View.VISIBLE
        }
      }

      continueButton.setOnClickListener {
        if (requireArguments().getBoolean(SHOULD_CLONE_EXTRA)) cloneRepository()
        else createRepository()
      }
    }
  }

  /** Clones a remote Git repository */
  private fun cloneRepository() {
    cloneAction.launch(GitServerConfigActivity.createCloneIntent(requireContext()))
  }

  /** Fresh Git repository */
  private fun createRepository() {
    val localDir = PasswordRepository.getRepositoryDirectory()
    runCatching {
      check(localDir.exists() || localDir.mkdirs()) { "Failed to create directory!" }
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

    private const val SHOULD_CLONE_EXTRA = "SHOULD_CLONE"

    fun newInstance(shouldClone: Boolean = true): RepoVisibilityFragment {
      val extras =
        Bundle().also {
          it.apply {
            putBoolean(SHOULD_CLONE_EXTRA, shouldClone)
          }
        }
      val fragment = RepoVisibilityFragment()
      fragment.arguments = extras
      return fragment
    }
  }
}
