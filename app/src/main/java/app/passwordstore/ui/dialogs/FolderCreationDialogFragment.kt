/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.dialogs

import android.app.Dialog
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.os.bundleOf
import androidx.core.view.isVisible
import androidx.fragment.app.DialogFragment
import app.passwordstore.R
import app.passwordstore.databinding.FolderDialogFragmentBinding
import app.passwordstore.ui.passwords.PasswordStore
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.util.extensions.commitChange
import app.passwordstore.util.extensions.unsafeLazy
import com.google.android.material.checkbox.MaterialCheckBox
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import java.io.File
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class FolderCreationDialogFragment : DialogFragment() {

  private val binding by unsafeLazy { FolderDialogFragmentBinding.inflate(layoutInflater) }
  private lateinit var newFolder: File

  private val gpgKeySelectAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == AppCompatActivity.RESULT_OK) {
        val data = result.data ?: return@registerForActivityResult
        val selectedKeyId =
          data.getStringExtra(PGPKeyListActivity.EXTRA_SELECTED_KEY)
            ?: return@registerForActivityResult
        val gpgIdentifierFile = File(newFolder, ".gpg-id")
        gpgIdentifierFile.writeText(selectedKeyId)
        runBlocking {
          requireActivity()
            .commitChange(getString(R.string.git_commit_gpg_id, getString(R.string.app_name)))
        }
        (requireActivity() as PasswordStore).refreshPasswordList(newFolder)
      }
      dismiss()
    }

  override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
    val alertDialogBuilder = MaterialAlertDialogBuilder(requireContext())
    alertDialogBuilder.setTitle(R.string.title_create_folder)
    alertDialogBuilder.setView(binding.root)
    alertDialogBuilder.setPositiveButton(getString(R.string.button_create), null)
    alertDialogBuilder.setNegativeButton(getString(android.R.string.cancel)) { _, _ -> dismiss() }
    binding.setGpgKey.isVisible = requireArguments().getBoolean(SET_GPG_KEY_EXTRA)
    val dialog = alertDialogBuilder.create()
    dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)
    dialog.setOnShowListener {
      dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
        createDirectory(
          requireArguments().getString(CURRENT_DIR_EXTRA) ?: throw NullPointerException()
        )
      }
    }
    return dialog
  }

  private fun createDirectory(currentDir: String) {
    val dialog = requireDialog()
    val folderNameView = dialog.findViewById<TextInputEditText>(R.id.folder_name_text)
    val folderNameViewContainer = dialog.findViewById<TextInputLayout>(R.id.folder_name_container)
    newFolder = File("$currentDir/${folderNameView.text}")
    folderNameViewContainer.error =
      when {
        newFolder.isFile -> getString(R.string.folder_creation_err_file_exists)
        newFolder.isDirectory -> getString(R.string.folder_creation_err_folder_exists)
        else -> null
      }
    if (folderNameViewContainer.error != null) return
    newFolder.mkdirs()
    if (dialog.findViewById<MaterialCheckBox>(R.id.set_gpg_key).isChecked) {
      val intent = PGPKeyListActivity.newSelectionActivity(requireContext())
      gpgKeySelectAction.launch(intent)
      return
    }
    (requireActivity() as PasswordStore).refreshPasswordList(newFolder)
    dismiss()
  }

  companion object {

    private const val CURRENT_DIR_EXTRA = "CURRENT_DIRECTORY"
    private const val SET_GPG_KEY_EXTRA = "SET_GPG_KEY"

    fun newInstance(
      startingDirectory: String,
      setGpgKey: Boolean = false,
    ): FolderCreationDialogFragment {
      val extras = bundleOf(CURRENT_DIR_EXTRA to startingDirectory, SET_GPG_KEY_EXTRA to setGpgKey)
      val fragment = FolderCreationDialogFragment()
      fragment.arguments = extras
      return fragment
    }
  }
}
