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
import androidx.core.content.edit
import androidx.core.content.getSystemService
import androidx.core.net.toUri
import androidx.documentfile.provider.DocumentFile
import androidx.fragment.app.FragmentActivity
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import app.passwordstore.R
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.ui.git.config.GitConfigActivity
import app.passwordstore.ui.git.config.GitServerConfigActivity
import app.passwordstore.ui.proxy.ProxySelectorActivity
import app.passwordstore.ui.sshkeygen.PgpAuthKeySelectionActivity
import app.passwordstore.ui.sshkeygen.ShowSshKeyFragment
import app.passwordstore.ui.sshkeygen.SshKeyGenActivity
import app.passwordstore.ui.sshkeygen.SshKeyImportActivity
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.gitSecrets
import app.passwordstore.util.extensions.launchActivity
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.git.sshj.SshKey
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
import java.io.IOException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.withContext
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
      pref(PreferenceKeys.GIT_SERVER_INFO) {
        titleRes = R.string.pref_edit_git_server_settings
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
          onClick {
            sshKeyAction.launch(Intent(activity, PgpAuthKeySelectionActivity::class.java))
            true
          }
        }
        pref(PreferenceKeys.SSH_KEYGEN) {
          titleRes = R.string.pref_ssh_keygen_title
          onClick {
            sshKeyAction.launch(Intent(activity, SshKeyGenActivity::class.java))
            true
          }
        }
        pref(PreferenceKeys.SSH_KEY) {
          titleRes = R.string.pref_import_ssh_key_title
          onClick {
            sshKeyAction.launch(Intent(activity, SshKeyImportActivity::class.java))
            true
          }
        }
        showSshKeyPref =
          pref(PreferenceKeys.SSH_SEE_KEY) {
            titleRes = R.string.pref_ssh_see_key_title
            onClick {
              ShowSshKeyFragment().show(activity.supportFragmentManager, "public_key")
              true
            }
            updateShowSshKeyPref()
          }
      }
      clearSavedPassPref =
        pref(PreferenceKeys.CLEAR_SAVED_PASS) {
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
          onClick {
            activity.launchActivity(ProxySelectorActivity::class.java)
            true
          }
          updateProxyPref()
        }
      pref(PreferenceKeys.GIT_CONFIG) {
        titleRes = R.string.pref_edit_git_config
        onClick {
          activity.launchActivity(GitConfigActivity::class.java)
          true
        }
      }
      switch(PreferenceKeys.REBASE_ON_PULL) {
        titleRes = R.string.pref_rebase_on_pull_title
        summaryRes = R.string.pref_rebase_on_pull_summary
        summaryOnRes = R.string.pref_rebase_on_pull_summary_on
        defaultValue = true
      }
      pref(PreferenceKeys.EXPORT_PASSWORDS) {
        titleRes = R.string.prefs_export_passwords_title
        summaryRes = R.string.prefs_export_passwords_summary
        onClick {
          storeExportAction.launch(null)
          true
        }
      }
      pref(PreferenceKeys.IMPORT_PASSWORDS) {
        titleRes = R.string.prefs_import_passwords_title
        summaryRes = R.string.prefs_import_passwords_summary
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
      pref(PreferenceKeys.GIT_DELETE_REPO) {
        titleRes = R.string.pref_git_delete_repo_title
        summaryRes = R.string.pref_git_delete_repo_summary
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
              activity.sharedPrefs.edit { putBoolean(PreferenceKeys.REPOSITORY_INITIALIZED, false) }
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

    val repositoryDirectory = PasswordRepository.getRepositoryDirectory()
    val internalRepository = DocumentFile.fromFile(repositoryDirectory)

    withContext(hiltEntryPoint.dispatcherProvider().io()) {
      logcat { "Exporting ${repositoryDirectory.path} to ${passDir.uri.path}" }
      copyDirToDir(applicationContext, internalRepository, passDir)
      logcat { "Done with exporting ${repositoryDirectory.path} to ${passDir.uri.path}" }
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

/**
 * Recursively copies a directory to a destination.
 *
 * @param sourceDirectory directory to copy from.
 * @param targetDirectory directory to copy to.
 */
private fun copyDirToDir(
  context: Context,
  sourceDirectory: DocumentFile,
  targetDirectory: DocumentFile,
) {
  sourceDirectory.listFiles().forEach { file ->
    if (file.isDirectory()) {
      // Create new directory and recurse
      val newDir = targetDirectory.createDirectory(file.name ?: throw NullPointerException())
      copyDirToDir(context, file, newDir ?: throw NullPointerException())
    } else {
      copyFileToDir(context, file, targetDirectory)
    }
  }
}

/**
 * Copies a password file to a given directory.
 *
 * Note: this does not preserve last modified time.
 *
 * @param passwordFile password file to copy.
 * @param targetDirectory target directory to copy password.
 */
private fun copyFileToDir(
  context: Context,
  passwordFile: DocumentFile,
  targetDirectory: DocumentFile,
) {
  val sourceInputStream = context.contentResolver.openInputStream(passwordFile.uri)
  val name = passwordFile.name
  val targetPasswordFile =
    targetDirectory.createFile("application/octet-stream", name ?: throw NullPointerException())
  if (targetPasswordFile?.exists() == true) {
    val destOutputStream = context.contentResolver.openOutputStream(targetPasswordFile.uri)

    if (destOutputStream != null && sourceInputStream != null) {
      sourceInputStream.use { source -> destOutputStream.use { dest -> source.copyTo(dest) } }
    }
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
