/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.dialogs

import android.app.Dialog
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.isVisible
import androidx.core.widget.doOnTextChanged
import androidx.fragment.app.DialogFragment
import app.passwordstore.R
import app.passwordstore.databinding.FolderDialogFragmentBinding
import app.passwordstore.ui.folderselect.SelectFolderActivity
import app.passwordstore.ui.passwords.PasswordStore
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.util.extensions.commitChange
import app.passwordstore.util.extensions.isInsideRepository
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

  override fun onCreateDialog(savedInstanceState: Bundle?): Dialog {
    val builder = MaterialAlertDialogBuilder(requireContext())
    builder.setTitle(R.string.title_create_folder)
    builder.setView(binding.root)
    builder.setPositiveButton(getString(R.string.button_create), null)
    builder.setNegativeButton(getString(android.R.string.cancel)) { _, _ -> dismiss() }
    binding.setGpgKey.isVisible = requireArguments().getBoolean(SET_GPG_KEY_EXTRA)
    val dialog = builder.create()
    dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_VISIBLE)
    dialog.setOnShowListener {
      dialog.getButton(AlertDialog.BUTTON_POSITIVE).apply {
        isEnabled = false
        setOnClickListener {
          createDirectory(
            requireArguments().getString(CURRENT_DIR_EXTRA) ?: throw NullPointerException()
          )
        }
      }
      binding.folderNameText.doOnTextChanged { s, _, _, _ ->
        s?.let { dialog.getButton(AlertDialog.BUTTON_POSITIVE).isEnabled = it.length > 0 }
      }
    }
    return dialog
  }

  private val gpgKeySelectAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == AppCompatActivity.RESULT_OK) {
        val data = result.data ?: return@registerForActivityResult
        val selectedKeyId =
          data.getStringExtra(PGPKeyListActivity.EXTRA_SELECTED_KEY)
            ?: return@registerForActivityResult
        val gpgIdentifierFile = File(newFolder, ".gpg-id")
        gpgIdentifierFile.writeText(selectedKeyId + "\n")
        runBlocking {
          requireActivity()
            .commitChange(getString(R.string.git_commit_gpg_id, getString(R.string.app_name)))
        }
        requireActivity().let {
          if (it is PasswordStore) (it as PasswordStore).refreshPasswordList(newFolder)
          else (it as SelectFolderActivity).refreshPasswordList(newFolder)
        }
      }
      dismiss()
    }

  private fun createDirectory(currentDir: String) {
    val dialog = requireDialog()
    val folderNameView = dialog.findViewById<TextInputEditText>(R.id.folder_name_text)
    val folderNameViewContainer = dialog.findViewById<TextInputLayout>(R.id.folder_name_container)
    newFolder = File("$currentDir/${folderNameView.text}")
    folderNameViewContainer.error =
      when {
        !newFolder.isInsideRepository() ->
          getString(R.string.message_error_destination_outside_repo)
        newFolder.isFile -> getString(R.string.folder_creation_err_file_exists)
        newFolder.isDirectory -> getString(R.string.folder_creation_err_folder_exists)
        else -> null
      }
    if (folderNameViewContainer.error != null) return
    newFolder.mkdirs()
    if (dialog.findViewById<MaterialCheckBox>(R.id.set_gpg_key).isChecked) {
      gpgKeySelectAction.launch(PGPKeyListActivity.newIntent(requireContext(), keySelection = true))
      return
    }
    requireActivity().let {
      if (it is PasswordStore) (it as PasswordStore).refreshPasswordList(newFolder)
      else (it as SelectFolderActivity).refreshPasswordList(newFolder)
    }
    dismiss()
  }

  companion object {

    private const val CURRENT_DIR_EXTRA = "CURRENT_DIRECTORY"
    private const val SET_GPG_KEY_EXTRA = "SET_GPG_KEY"

    fun newInstance(
      startingDirectory: String,
      setGpgKey: Boolean = false,
    ): FolderCreationDialogFragment {
      val extras =
        Bundle().also {
          it.apply {
            putString(CURRENT_DIR_EXTRA, startingDirectory)
            putBoolean(SET_GPG_KEY_EXTRA, setGpgKey)
          }
        }
      val fragment = FolderCreationDialogFragment()
      fragment.arguments = extras
      return fragment
    }
  }
}
