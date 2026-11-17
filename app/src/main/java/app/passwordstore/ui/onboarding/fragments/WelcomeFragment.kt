/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.onboarding.fragments

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.annotation.Keep
import androidx.core.content.edit
import androidx.core.view.ViewCompat
import androidx.fragment.app.Fragment
import app.passwordstore.R
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.databinding.FragmentWelcomeBinding
import app.passwordstore.ui.settings.SettingsActivity
import app.passwordstore.util.extensions.finish
import app.passwordstore.util.extensions.performTransactionWithBackStack
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.windowInsetsLambda
import app.passwordstore.util.settings.PreferenceKeys
import java.io.File

@Keep
class WelcomeFragment : Fragment(R.layout.fragment_welcome) {

  private val binding by viewBinding(FragmentWelcomeBinding::bind)

  private val settingsAction =
    registerForActivityResult(StartActivityForResult()) { _ -> finishIfStoreExists() }

  override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
    super.onViewCreated(view, savedInstanceState)

    ViewCompat.setOnApplyWindowInsetsListener(view, windowInsetsLambda)

    with(binding) {
      letsGo.setOnClickListener {
        parentFragmentManager.performTransactionWithBackStack(CloneFragment.newInstance())
      }
      settingsButton.setOnClickListener {
        settingsAction.launch(
          Intent(requireContext(), SettingsActivity::class.java).setAction(Intent.ACTION_VIEW)
        )
      }
    }
  }

  private fun finishIfStoreExists() {
    if (File(PasswordRepository.getRepositoryDirectory(), ".gpg-id").isFile()) {
      requireActivity().applicationContext.sharedPrefs.edit {
        putBoolean(PreferenceKeys.REPOSITORY_INITIALIZED, true)
      }
      finish()
    }
  }
}
