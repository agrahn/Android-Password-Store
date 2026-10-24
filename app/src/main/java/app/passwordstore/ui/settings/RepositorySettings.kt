/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.settings

import android.content.Context
import android.content.Intent
import android.content.pm.ShortcutManager
import android.net.Uri
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.edit
import androidx.core.content.getSystemService
import androidx.core.net.toUri
import androidx.documentfile.provider.DocumentFile
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import app.passwordstore.R
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.data.repo.store.GPG_ID
import app.passwordstore.data.repo.store.StoreMode
import app.passwordstore.data.repo.store.writeGpgId
import app.passwordstore.ui.git.config.GitConfigActivity
import app.passwordstore.ui.git.config.GitServerConfigActivity
import app.passwordstore.ui.pgp.PGPKeyListActivity
import app.passwordstore.ui.proxy.ProxySelectorActivity
import app.passwordstore.ui.sshkeygen.PgpAuthKeySelectionActivity
import app.passwordstore.ui.sshkeygen.ShowSshKeyFragment
import app.passwordstore.ui.sshkeygen.SshKeyGenActivity
import app.passwordstore.ui.sshkeygen.SshKeyImportActivity
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.credentialUsernames
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.gitSecrets
import app.passwordstore.util.extensions.launchActivity
import app.passwordstore.util.extensions.passwordHistory
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.git.sshj.SshKey
import app.passwordstore.util.services.copyDirToDir
import app.passwordstore.util.settings.GitSettings
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.fold
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent
import de.Maxr1998.modernpreferences.Preference
import de.Maxr1998.modernpreferences.PreferenceScreen
import de.Maxr1998.modernpreferences.helpers.onClick
import de.Maxr1998.modernpreferences.helpers.pref
import de.Maxr1998.modernpreferences.helpers.subScreen
import de.Maxr1998.modernpreferences.helpers.switch
import de.Maxr1998.modernpreferences.preferences.SwitchPreference
import java.io.IOException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat

class RepositorySettings(private val activity: FragmentActivity) : SettingsProvider {

  private val hiltEntryPoint by unsafeLazy {
    EntryPointAccessors.fromApplication(
      activity.applicationContext,
      RepositorySettingsEntryPoint::class.java,
    )
  }

  private val storeExportAction =
    activity.registerForActivityResult(
      object : ActivityResultContracts.OpenDocumentTree() {
        override fun createIntent(context: Context, input: Uri?): Intent {
          return super.createIntent(context, input).apply {
            flags =
              Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
          }
        }
      }
    ) { uri: Uri? ->
      if (uri == null) return@registerForActivityResult

      val exportWork =
        OneTimeWorkRequestBuilder<ExportPasswordsWorker>()
          .setInputData(workDataOf("uri" to uri.toString()))
          .build()

      val workId = exportWork.id

      val workManager = WorkManager.getInstance(activity.applicationContext)

      val progressDialog =
        MaterialAlertDialogBuilder(activity)
          .setTitle(R.string.prefs_export_passwords_dialog_title)
          .setMessage(R.string.prefs_export_passwords_dialog_message)
          .setCancelable(false)
          .create()

      workManager.getWorkInfoByIdLiveData(workId).observe(activity) { workInfo ->
        logcat { "Repository export: ${workInfo?.state}" }
        when (workInfo?.state) {
          WorkInfo.State.RUNNING -> progressDialog.show()
          WorkInfo.State.SUCCEEDED,
          WorkInfo.State.FAILED,
          WorkInfo.State.CANCELLED -> progressDialog.dismiss()
          else -> {} // ENQUEUED, BLOCKED states - keep current state
        }
      }

      workManager.enqueueUniqueWork("EXPORT_STORE", ExistingWorkPolicy.REPLACE, exportWork)
    }

  private val storeImportAction =
    activity.registerForActivityResult(
      object : ActivityResultContracts.OpenDocumentTree() {
        override fun createIntent(context: Context, input: Uri?): Intent {
          return super.createIntent(context, input).apply {
            flags =
              Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
          }
        }
      }
    ) { uri: Uri? ->
      if (uri == null) return@registerForActivityResult

      // Minimal check to see if the source directory is a git repo
      val sourceDirectory =
        DocumentFile.fromTreeUri(activity.applicationContext, uri)
          ?: return@registerForActivityResult
      if (!(sourceDirectory.findFile(".git")?.isDirectory() ?: false)) {
        MaterialAlertDialogBuilder(activity)
          .setTitle(R.string.prefs_repo_invalid_source_dialog_title)
          .setIcon(R.drawable.ic_crossmark_red_24dp)
          .setMessage(R.string.prefs_repo_invalid_source_dialog_summary)
          .setPositiveButton(R.string.dialog_ok) { dialog, _ -> dialog.dismiss() }
          .show()
      } else {
        val importWork =
          OneTimeWorkRequestBuilder<ImportPasswordsWorker>()
            .setInputData(workDataOf("uri" to uri.toString()))
            .build()

        val workId = importWork.id

        val workManager = WorkManager.getInstance(activity.applicationContext)

        val progressDialog =
          MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.prefs_import_passwords_dialog_title)
            .setMessage(R.string.prefs_export_passwords_dialog_message)
            .setCancelable(false)
            .create()

        workManager.getWorkInfoByIdLiveData(workId).observe(activity) { workInfo ->
          logcat { "Repository import: ${workInfo?.state}" }
          when (workInfo?.state) {
            WorkInfo.State.RUNNING -> progressDialog.show()
            WorkInfo.State.SUCCEEDED,
            WorkInfo.State.FAILED,
            WorkInfo.State.CANCELLED -> progressDialog.dismiss()
            else -> {} // ENQUEUED, BLOCKED states - keep current state
          }
        }

        workManager.enqueueUniqueWork("IMPORT_STORE", ExistingWorkPolicy.REPLACE, importWork)
      }
    }

  private val storeFolderAction =
    activity.registerForActivityResult(
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
      val pending = folderModePending
      folderModePending = false
      if (uri == null) return@registerForActivityResult
      runCatching {
        activity.contentResolver.takePersistableUriPermission(
          uri,
          Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
        )
      }
      activity.sharedPrefs.edit { putString(PreferenceKeys.STORE_URI, uri.toString()) }
      if (pending) {
        // The switch asked for this folder, so it turns itself on instead of waiting for a second
        // tap.
        storeModePref?.checked = true
        setFolderMode(true, uri)
      } else {
        // Picking a folder from the row does not switch the store; the switch is for that.
        PasswordRepository.resetBackend()
        PasswordRepository.initialize()
        storeFolderPref?.updateStoreFolderPref()
        requestStoreKeyIfMissing()
      }
    }

  private val storeKeyAction =
    activity.registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode != AppCompatActivity.RESULT_OK) {
        activity.snackbar(message = activity.getString(R.string.gpg_key_select_mandatory))
        return@registerForActivityResult
      }
      val keyId =
        result.data?.getStringExtra(PGPKeyListActivity.EXTRA_SELECTED_KEY)
          ?: return@registerForActivityResult
      activity.lifecycleScope.launch {
        // A folder store is never git-backed, so the new `.gpg-id` has nothing to be committed to.
        PasswordRepository.storeRoot.writeGpgId(keyId)
        activity.sharedPrefs.edit { putBoolean(PreferenceKeys.REPOSITORY_INITIALIZED, true) }
      }
    }

  private var storeModePref: SwitchPreference? = null

  /** True while the picker is open because the store mode switch asked for a folder. */
  private var folderModePending = false

  private var storeFolderPref: Preference? = null

  /** The folder the user picked, whether or not the store currently uses it. */
  private fun pickedFolderUri(): Uri? =
    activity.sharedPrefs.getString(PreferenceKeys.STORE_URI, null)?.toUri()

  private fun Preference.updateStoreFolderPref() {
    titleRes = R.string.pref_select_store_folder_title
    summary =
      pickedFolderUri()?.let { uri ->
        DocumentFile.fromTreeUri(activity.applicationContext, uri)?.name
      }
    requestRebind()
  }

  /**
   * Folder mode needs a key before the store can hold anything. Onboarding asks for it right after
   * the folder is picked, so settings does the same instead of leaving an empty store behind.
   */
  private fun requestStoreKeyIfMissing() {
    if (!PasswordRepository.isSafStore) return
    if (PasswordRepository.storeRoot.findChild(GPG_ID) != null) return
    storeKeyAction.launch(PGPKeyListActivity.newIntent(activity, keySelection = true))
  }

  /**
   * Settings that only mean something for the git-backed app-private store.
   *
   * A folder store is never git-backed, so these rows stay visible but are disabled there instead
   * of disappearing, which keeps the two store modes distinguishable at a glance.
   */
  private fun Preference.gitOnly() {
    enabled = !PasswordRepository.isSafStore
    gitOnlyPrefs += this
  }

  /** Settings that only mean something for a folder store. */
  private fun Preference.folderOnly() {
    enabled = PasswordRepository.isSafStore
    folderOnlyPrefs += this
  }

  private fun applyStoreMode() {
    gitOnlyPrefs.forEach {
      it.enabled = !PasswordRepository.isSafStore
      it.requestRebind()
    }
    folderOnlyPrefs.forEach {
      it.enabled = PasswordRepository.isSafStore
      it.requestRebind()
    }
  }

  /**
   * Writes the store mode, hands the picked folder back when turning off, then re-applies the rows.
   *
   * Both the mode switch and the folder picker land here, so a folder chosen while the switch waits
   * for one cannot end up in a different state than the same folder chosen from the row.
   */
  private fun setFolderMode(turningOn: Boolean, folder: Uri?) {
    // Writing the folder mode without a folder would leave the switch claiming a store the app
    // cannot open, because the backend falls back to the app-private one.
    if (turningOn && folder == null) return
    activity.sharedPrefs.edit {
      putString(
        PreferenceKeys.STORE_MODE,
        if (turningOn) StoreMode.SAF.name else StoreMode.INTERNAL.name,
      )
      if (turningOn) putString(PreferenceKeys.STORE_URI, folder.toString())
      else remove(PreferenceKeys.STORE_URI)
    }
    if (!turningOn) {
      // Turning the switch off gives the picked folder up for good, so hand the grant back.
      folder?.let { uri ->
        runCatching {
          activity.contentResolver.releasePersistableUriPermission(
            uri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
          )
        }
          .onErr { e -> logcat(ERROR) { "Could not release the store folder grant: ${e.asLog()}" } }
      }
    }
    PasswordRepository.resetBackend()
    PasswordRepository.initialize()
    applyStoreMode()
    storeFolderPref?.updateStoreFolderPref()
    // Turning the mode off cannot leave an unfinished store behind, so only switching it on asks.
    if (turningOn) requestStoreKeyIfMissing()
  }

  private val gitOnlyPrefs = mutableListOf<Preference>()
  private val folderOnlyPrefs = mutableListOf<Preference>()

  private fun Preference.updateProxyPref() {
    titleRes = R.string.pref_edit_proxy_settings
    visible =
      hiltEntryPoint.gitSettings().url?.startsWith("http") == true && PasswordRepository.isGitRepo()
    requestRebind()
  }

  private var proxySettingsPref: Preference? = null

  private val configureGitServer =
    activity.registerForActivityResult(StartActivityForResult()) {
      proxySettingsPref?.updateProxyPref()
      clearSavedPassPref?.updateClearSavedPassPref()
    }

  private fun Preference.updateShowSshKeyPref() {
    visible = SshKey.canShowSshPublicKey
    requestRebind()
  }

  private var showSshKeyPref: Preference? = null

  private fun Preference.updateClearSavedPassPref() {
    val sshPass = activity.gitSecrets.getString(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE)
    val httpsPass = activity.gitSecrets.getString(PreferenceKeys.HTTPS_PASSWORD)
    if (sshPass == null && httpsPass == null) {
      visible = false
    } else {
      titleRes =
        when {
          httpsPass != null -> R.string.clear_saved_passphrase_https
          else -> R.string.clear_saved_passphrase_ssh
        }
      visible = true
    }
    requestRebind()
  }

  private var clearSavedPassPref: Preference? = null

  val sshKeyAction =
    activity.registerForActivityResult(StartActivityForResult()) {
      showSshKeyPref?.updateShowSshKeyPref()
      clearSavedPassPref?.updateClearSavedPassPref()
    }

  override fun provideSettings(builder: PreferenceScreen.Builder) {
    builder.apply {
      storeModePref =
        switch(PreferenceKeys.STORE_MODE_EXTERNAL) {
          // STORE_MODE is the single source of truth, so this switch owns no persisted state.
          persistent = false
          titleRes = R.string.pref_external_folder_store_title
          summaryRes = R.string.pref_external_folder_store_summary
          summaryOnRes = R.string.pref_external_folder_store_summary_on
          // setChecked() throws before the row is attached; defaultValue is read at attach time.
          defaultValue = PasswordRepository.isSafStore
          onClick {
            // The library has already toggled and committed when this runs, so revert by hand.
            val turningOn = checked
            val folder = pickedFolderUri()
            if (turningOn && folder == null) {
              checked = false
              requestRebind()
              activity.snackbar(
                message = activity.getString(R.string.pref_folder_store_needs_folder)
              )
              folderModePending = true
              storeFolderAction.launch(null)
            } else {
              setFolderMode(turningOn, folder)
            }
            false
          }
        }
      storeFolderPref =
        pref(PreferenceKeys.SAF_STORE_FOLDER) {
          folderOnly()
          onClick {
            storeFolderAction.launch(null)
            true
          }
          updateStoreFolderPref()
        }
      switch(PreferenceKeys.SAF_WARN_NO_COMMIT) {
        titleRes = R.string.pref_saf_warn_no_commit_title
        summaryRes = R.string.pref_saf_warn_no_commit_summary
        defaultValue = true
        folderOnly()
      }
      pref(PreferenceKeys.GIT_SERVER_INFO) {
        titleRes = R.string.title_activity_git_remote
        gitOnly()
        onClick {
          configureGitServer.launch(Intent(activity, GitServerConfigActivity::class.java))
          true
        }
      }
      subScreen {
        collapseIcon = true
        titleRes = R.string.pref_git_server_auth_key

        pref(PreferenceKeys.SSH_USE_PGP_KEY) {
          titleRes = R.string.pref_ssh_use_pgp_key_title
          gitOnly()
          onClick {
            sshKeyAction.launch(Intent(activity, PgpAuthKeySelectionActivity::class.java))
            true
          }
        }
        pref(PreferenceKeys.SSH_KEYGEN) {
          titleRes = R.string.pref_ssh_keygen_title
          gitOnly()
          onClick {
            sshKeyAction.launch(Intent(activity, SshKeyGenActivity::class.java))
            true
          }
        }
        pref(PreferenceKeys.SSH_KEY) {
          titleRes = R.string.pref_import_ssh_key_title
          gitOnly()
          onClick {
            sshKeyAction.launch(Intent(activity, SshKeyImportActivity::class.java))
            true
          }
        }
        showSshKeyPref =
          pref(PreferenceKeys.SSH_SEE_KEY) {
            titleRes = R.string.pref_ssh_see_key_title
            gitOnly()
            onClick {
              ShowSshKeyFragment().show(activity.supportFragmentManager, "public_key")
              true
            }
            updateShowSshKeyPref()
          }
      }
        .gitOnly()
      pref(PreferenceKeys.GIT_CONFIG) {
        titleRes = R.string.pref_edit_git_config
        gitOnly()
        onClick {
          activity.launchActivity(GitConfigActivity::class.java)
          true
        }
      }
      switch(PreferenceKeys.REBASE_ON_PULL) {
        gitOnly()
        titleRes = R.string.pref_rebase_on_pull_title
        summaryRes = R.string.pref_rebase_on_pull_summary
        summaryOnRes = R.string.pref_rebase_on_pull_summary_on
        defaultValue = true
      }
      pref(PreferenceKeys.IMPORT_PASSWORDS) {
        titleRes = R.string.prefs_import_passwords_title
        summaryRes = R.string.prefs_import_passwords_summary
        gitOnly()
        onClick {
          if (PasswordRepository.isEmpty()) {
            storeImportAction.launch(null)
            true
          } else {
            MaterialAlertDialogBuilder(activity)
              .setTitle(R.string.prefs_repo_not_empty_dialog_title)
              .setMessage(R.string.prefs_repo_not_empty_dialog_summary)
              .setPositiveButton(R.string.dialog_ok) { dialog, _ -> dialog.dismiss() }
              .show()
            false
          }
        }
      }
      clearSavedPassPref =
        pref(PreferenceKeys.CLEAR_SAVED_PASS) {
          gitOnly()
          onClick {
            activity.gitSecrets.edit {
              remove(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE)
              remove(PreferenceKeys.HTTPS_PASSWORD)
            }
            updateClearSavedPassPref()
            true
          }
          updateClearSavedPassPref()
        }
      proxySettingsPref =
        pref(PreferenceKeys.PROXY_SETTINGS) {
          gitOnly()
          onClick {
            activity.launchActivity(ProxySelectorActivity::class.java)
            true
          }
          updateProxyPref()
        }
      pref(PreferenceKeys.EXPORT_PASSWORDS) {
        titleRes = R.string.prefs_export_passwords_title
        summaryRes = R.string.prefs_export_passwords_summary
        onClick {
          storeExportAction.launch(null)
          true
        }
      }
      pref(PreferenceKeys.GIT_DELETE_REPO) {
        titleRes = R.string.pref_git_delete_repo_title
        summaryRes = R.string.pref_git_delete_repo_summary
        gitOnly()
        onClick {
          val repoDir = PasswordRepository.getRepositoryDirectory()
          MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.pref_dialog_delete_title)
            .setMessage(activity.getString(R.string.dialog_delete_msg, repoDir))
            .setCancelable(false)
            .setPositiveButton(R.string.dialog_delete) { dialogInterface, _ ->
              runCatching {
                PasswordRepository.closeRepository()
                PasswordRepository.getRepositoryDirectory().let { dir ->
                  dir.deleteRecursively()
                  dir.mkdirs()
                }
              }
                .onErr { it.message?.let { message -> activity.snackbar(message = message) } }

              activity.getSystemService<ShortcutManager>()?.apply {
                removeDynamicShortcuts(dynamicShortcuts.map { it.id }.toMutableList())
              }
              activity.sharedPrefs.edit {
                putBoolean(PreferenceKeys.REPOSITORY_INITIALIZED, false)
              }
              activity.passwordHistory.edit { clear() }
              activity.credentialUsernames.edit { clear() }
              dialogInterface.cancel()
              activity.finish()
            }
            .setNegativeButton(R.string.dialog_do_not_delete) { dialogInterface, _ ->
              run { dialogInterface.cancel() }
            }
            .show()
          true
        }
      }
    }
  }

  @EntryPoint
  @InstallIn(SingletonComponent::class)
  interface RepositorySettingsEntryPoint {
    fun gitSettings(): GitSettings
  }
}

class ExportPasswordsWorker(context: Context, params: WorkerParameters) :
  CoroutineWorker(context, params) {

  private val hiltEntryPoint by unsafeLazy {
    EntryPointAccessors.fromApplication(
      applicationContext,
      ExportPasswordsWorkerEntryPoint::class.java,
    )
  }

  override suspend fun doWork(): Result = runCatching {
    val uriString =
      inputData.getString("uri")
        ?: throw IllegalArgumentException("No URI passed to ImportPasswordsWorker")
    val uri = uriString.toUri()

    val targetDirectory = DocumentFile.fromTreeUri(applicationContext, uri)
    val dateString = LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME).replace(':', '_')
    val passDir =
      targetDirectory?.createDirectory("password_store_$dateString")
        ?: throw IllegalArgumentException(
          "Failed to create target directory ${targetDirectory?.uri?.path}/password_store_$dateString"
        )

    val sourceDirectory =
      if (PasswordRepository.isSafStore) {
        val storeUri =
          PasswordRepository.storeUri
            ?: throw IllegalArgumentException("No folder store is configured for export")
        DocumentFile.fromTreeUri(applicationContext, storeUri)
          ?: throw IllegalArgumentException("The folder store could not be opened for export")
      } else {
        DocumentFile.fromFile(PasswordRepository.getRepositoryDirectory())
      }

    withContext(hiltEntryPoint.dispatcherProvider().io()) {
      logcat { "Exporting the store to ${passDir.uri.path}" }
      copyDirToDir(applicationContext, sourceDirectory, passDir)
      logcat { "Done with exporting the store to ${passDir.uri.path}" }
    }
    Result.success()
  }
    .fold(
      success = { Result.success() },
      failure = {
        logcat { it.asLog() }
        Result.failure()
      },
    )

  @EntryPoint
  @InstallIn(SingletonComponent::class)
  interface ExportPasswordsWorkerEntryPoint {
    fun dispatcherProvider(): DispatcherProvider
  }
}

class ImportPasswordsWorker(context: Context, params: WorkerParameters) :
  CoroutineWorker(context, params) {

  private val hiltEntryPoint by unsafeLazy {
    EntryPointAccessors.fromApplication(
      applicationContext,
      ImportPasswordsWorkerEntryPoint::class.java,
    )
  }

  override suspend fun doWork(): Result = runCatching {
    val uriString =
      inputData.getString("uri")
        ?: throw IllegalArgumentException("No URI passed to ImportPasswordsWorker")
    val uri = uriString.toUri()

    val sourceDirectory =
      DocumentFile.fromTreeUri(applicationContext, uri)
        ?: throw IllegalArgumentException("Invalid URI passed to ImportPasswordsWorker")

    val repositoryDirectory =
      requireNotNull(PasswordRepository.getRepositoryDirectory()) {
        "Password target directory must be set for import"
      }
    if (!repositoryDirectory.exists()) repositoryDirectory.mkdirs()
    val internalRepository = DocumentFile.fromFile(repositoryDirectory)

    withContext(hiltEntryPoint.dispatcherProvider().io()) {
      logcat { "Importing ${sourceDirectory?.uri?.path} to ${repositoryDirectory.path}" }
      copyDirToDir(applicationContext, sourceDirectory, internalRepository)
      /**
       * When importing an external repo, the .bin extension is appended to the files copied; we
       * walk through the internal repo directory once more and remove the .bin ending from all
       * files we find.
       */
      renameFilesInDirectoryTree(repositoryDirectory.getAbsolutePath(), ".bin", "")
      logcat {
        "Done with importing ${sourceDirectory?.uri?.path} to ${repositoryDirectory.path}"
      }
    }
    Result.success()
  }
    .fold(
      success = { Result.success() },
      failure = {
        logcat { it.asLog() }
        Result.failure()
      },
    )

  @EntryPoint
  @InstallIn(SingletonComponent::class)
  interface ImportPasswordsWorkerEntryPoint {
    fun dispatcherProvider(): DispatcherProvider
  }
}

private fun renameFilesInDirectoryTree(
  rootDir: String,
  oldExtension: String,
  newExtension: String,
) {
  val startPath = Paths.get(rootDir)
  Files.walkFileTree(
    startPath,
    object : SimpleFileVisitor<Path>() {
      override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult {
        val fileName = file.fileName.toString()
        if (fileName.endsWith(oldExtension)) {
          val newFileName = fileName.replace(oldExtension, newExtension)
          val newFile = file.resolveSibling(newFileName)
          Files.move(file, newFile)
        }
        return FileVisitResult.CONTINUE
      }

      override fun visitFileFailed(file: Path, exc: IOException): FileVisitResult {
        logcat { "Failed to access file: $file" }
        exc.printStackTrace()
        return FileVisitResult.CONTINUE
      }
    },
  )
}
