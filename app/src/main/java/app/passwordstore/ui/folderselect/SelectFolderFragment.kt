/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.folderselect

import android.content.Context
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.flowWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import app.passwordstore.R
import app.passwordstore.data.password.PasswordItem
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.databinding.PasswordRecyclerViewBinding
import app.passwordstore.ui.adapters.PasswordItemRecyclerAdapter
import app.passwordstore.ui.passwords.PasswordStore
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.windowInsetsLambda
import app.passwordstore.util.viewmodel.ListMode
import app.passwordstore.util.viewmodel.SearchableRepositoryViewModel
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import dagger.hilt.android.AndroidEntryPoint
import java.io.File
import javax.inject.Inject
import kotlinx.coroutines.launch
import me.zhanghai.android.fastscroll.FastScrollerBuilder

@AndroidEntryPoint
class SelectFolderFragment : Fragment(R.layout.password_recycler_view) {

  @Inject lateinit var dispatcherProvider: DispatcherProvider
  private val binding by viewBinding(PasswordRecyclerViewBinding::bind)
  private lateinit var recyclerAdapter: PasswordItemRecyclerAdapter
  private lateinit var listener: OnFragmentInteractionListener

  private val model: SearchableRepositoryViewModel by activityViewModels()

  override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
    super.onViewCreated(view, savedInstanceState)

    ViewCompat.setOnApplyWindowInsetsListener(view, windowInsetsLambda)

    binding.fab.setMaxImageSize(64)
    binding.fab.setImageResource(R.drawable.ic_new_folder_48dp)
    binding.fab.setOnClickListener { (requireActivity() as SelectFolderActivity).createFolder() }

    recyclerAdapter =
      PasswordItemRecyclerAdapter(lifecycleScope, dispatcherProvider).onItemClicked { _, item ->
        listener.onFragmentInteraction(item)
      }
    binding.passRecycler.apply {
      layoutManager = LinearLayoutManager(requireContext())
      itemAnimator = null
      adapter = recyclerAdapter
    }

    FastScrollerBuilder(binding.passRecycler).build()
    registerForContextMenu(binding.passRecycler)

    model.navigateTo(
      PasswordRepository.getRepositoryDirectory(),
      listMode = ListMode.DirectoriesOnly,
      pushPreviousLocation = false,
    )
    getArguments()?.getString(PasswordStore.REQUEST_ARG_PATH)?.let { relPath ->
      relPath.trim('/').split('/').forEach { dir ->
        model.navigateTo(
          File(currentDir, dir),
          pushPreviousLocation = true,
          listMode = ListMode.DirectoriesOnly,
        )
      }
    }
    (requireActivity() as AppCompatActivity)
      .supportActionBar
      ?.setDisplayHomeAsUpEnabled(model.canNavigateBack)

    lifecycleScope.launch {
      model.searchResult.flowWithLifecycle(lifecycle).collect { result ->
        recyclerAdapter.submitList(result.passwordItems)
      }
    }
  }

  fun navigateTo(file: File) {
    model.navigateTo(
      file,
      listMode = ListMode.DirectoriesOnly,
      recyclerViewState =
        binding.passRecycler.layoutManager?.onSaveInstanceState() ?: throw NullPointerException(),
    )
  }

  override fun onAttach(context: Context) {
    super.onAttach(context)
    runCatching {
      listener =
        object : OnFragmentInteractionListener {
          override fun onFragmentInteraction(item: PasswordItem) {
            if (item.type == PasswordItem.TYPE_CATEGORY) {
              model.navigateTo(item.file, listMode = ListMode.DirectoriesOnly)
              (requireActivity() as AppCompatActivity)
                .supportActionBar
                ?.setDisplayHomeAsUpEnabled(true)
            }
          }
        }
    }
      .onErr { throw ClassCastException("$context must implement OnFragmentInteractionListener") }
  }

  /** Returns true if the back press was handled by the [Fragment]. */
  fun onBackPressedInActivity(): Boolean {
    if (!model.canNavigateBack) return false
    model.navigateBack(listMode = ListMode.DirectoriesOnly)
    if (!model.canNavigateBack)
      (requireActivity() as AppCompatActivity).supportActionBar?.setDisplayHomeAsUpEnabled(false)
    return true
  }

  val currentDir: File
    get() = model.currentDir.value

  interface OnFragmentInteractionListener {

    fun onFragmentInteraction(item: PasswordItem)
  }
}
