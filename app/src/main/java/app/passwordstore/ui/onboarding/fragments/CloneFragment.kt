/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.onboarding.fragments

import android.os.Bundle
import android.view.View
import androidx.core.view.ViewCompat
import androidx.fragment.app.Fragment
import app.passwordstore.R
import app.passwordstore.databinding.FragmentCloneBinding
import app.passwordstore.util.extensions.performTransactionWithBackStack
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.windowInsetsLambda

class CloneFragment : Fragment(R.layout.fragment_clone) {

  private val binding by viewBinding(FragmentCloneBinding::bind)

  override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
    super.onViewCreated(view, savedInstanceState)
    ViewCompat.setOnApplyWindowInsetsListener(view, windowInsetsLambda)

    binding.cloneRemote.setOnClickListener {
      parentFragmentManager.performTransactionWithBackStack(RepoVisibilityFragment.newInstance())
    }

    binding.createLocal.setOnClickListener {
      parentFragmentManager.performTransactionWithBackStack(
        RepoVisibilityFragment.newInstance(shouldClone = false)
      )
    }
  }

  companion object {

    fun newInstance(): CloneFragment = CloneFragment()
  }
}
