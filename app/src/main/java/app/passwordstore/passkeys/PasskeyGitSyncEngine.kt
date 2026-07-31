/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys

import android.content.SharedPreferences
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.injection.context.FilesDirPath
import app.passwordstore.injection.prefs.GitSecrets
import app.passwordstore.passkeys.storage.GitSyncResult
import app.passwordstore.passkeys.storage.PasskeyRemoteRefresher
import app.passwordstore.passkeys.storage.PasskeyRepositoryState
import app.passwordstore.passkeys.storage.RepositoryGenerationProvider
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.git.GitOperationCoordinator
import app.passwordstore.util.git.sshj.SshKey
import app.passwordstore.util.git.sshj.SshjConfig
import app.passwordstore.util.git.sshj.setUpBouncyCastleForSshj
import app.passwordstore.util.settings.AuthMode
import app.passwordstore.util.settings.GitSettings
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.transport.verification.FingerprintVerifier
import net.schmizz.sshj.userauth.method.AuthPassword
import net.schmizz.sshj.userauth.method.AuthPublickey
import net.schmizz.sshj.userauth.password.PasswordFinder
import net.schmizz.sshj.userauth.password.Resource
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.api.TransportCommand
import org.eclipse.jgit.diff.DiffEntry
import org.eclipse.jgit.diff.DiffFormatter
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.revwalk.RevWalk
import org.eclipse.jgit.transport.CredentialItem
import org.eclipse.jgit.transport.CredentialsProvider
import org.eclipse.jgit.transport.RemoteRefUpdate
import org.eclipse.jgit.transport.SshTransport
import org.eclipse.jgit.transport.Transport
import org.eclipse.jgit.transport.URIish
import org.eclipse.jgit.util.FS
import org.eclipse.jgit.util.io.DisabledOutputStream

internal class PasskeySyncException(
  message: String,
  cause: Throwable? = null,
  val retryable: Boolean,
) : Exception(message, cause)

/** Headless, serialized Git sync used by durable passkey background work and miss recovery. */
@Singleton
class PasskeyGitSyncEngine
@Inject
constructor(
  private val gitSettings: GitSettings,
  @GitSecrets private val gitSecrets: SharedPreferences,
  @FilesDirPath private val filesDirPath: String,
  private val dispatcherProvider: DispatcherProvider,
  private val passkeyRepositoryState: PasskeyRepositoryState,
  private val generationProvider: RepositoryGenerationProvider,
) : PasskeyRemoteRefresher {

  suspend fun sync(): Result<Unit, Throwable> = executeGitOperation(::executeSync)

  /** Pull-only refresh used when Credential Manager has no matching local candidate. */
  override suspend fun refresh(): Result<Unit, Throwable> = executeGitOperation(::executeRefresh)

  private suspend fun executeGitOperation(
    operation: suspend (Git) -> Unit
  ): Result<Unit, Throwable> {
    if (gitSettings.url == null) {
      return Err(PasskeySyncException("Git remote is not configured", retryable = false))
    }
    if (PasswordRepository.repository == null) {
      PasswordRepository.initialize()
    }
    val repository =
      PasswordRepository.repository
        ?: return Err(
          PasskeySyncException("Password repository is not initialized", retryable = false)
        )

    return withContext(dispatcherProvider.io()) {
      GitOperationCoordinator.withLock {
        try {
          operation(Git(repository))
          Ok(Unit)
        } catch (e: CancellationException) {
          throw e
        } catch (e: PasskeySyncException) {
          Err(e)
        } catch (e: Exception) {
          Err(
            PasskeySyncException(
              "Passkey Git operation failed: ${e.message}",
              cause = e,
              retryable = e.isRetryableTransportFailure(),
            )
          )
        }
      }
    }
  }

  private suspend fun executeSync(git: Git) {
    try {
      val oldHead = generationProvider.currentGitHead()
      stageAndCommit(git)
      pull(git, BACKGROUND_SYNC_TIMEOUT_SECONDS)
      push(git)
      completeRepositoryUpdate(git, oldHead)
    } finally {
      git.close()
    }
  }

  private suspend fun executeRefresh(git: Git) {
    try {
      val oldHead = generationProvider.currentGitHead()
      pull(git, REMOTE_REFRESH_TIMEOUT_SECONDS)
      completeRepositoryUpdate(git, oldHead)
    } finally {
      git.close()
    }
  }

  private suspend fun completeRepositoryUpdate(git: Git, oldHead: String?) {
    val conflicts = git.status().call().conflicting.toList()
    val newHead = generationProvider.currentGitHead()
    val changedPaths = changedPaths(git, oldHead, newHead)
    if (oldHead != newHead) {
      generationProvider.bumpWorktreeGeneration()
    }
    val syncResult =
      GitSyncResult(
        oldHead = oldHead,
        newHead = newHead,
        worktreeChanged = oldHead != newHead,
        conflicts = conflicts,
        changedPaths = changedPaths,
      )
    passkeyRepositoryState.onGitSyncCompleted(syncResult)
  }

  private fun changedPaths(git: Git, oldHead: String?, newHead: String?): Set<String> {
    if (oldHead == null || newHead == null || oldHead == newHead) return emptySet()
    val repository = git.repository
    val oldId = repository.resolve(oldHead) ?: return emptySet()
    val newId = repository.resolve(newHead) ?: return emptySet()
    val paths = linkedSetOf<String>()

    RevWalk(repository).use { walk ->
      val oldTree = walk.parseCommit(oldId).tree
      val newTree = walk.parseCommit(newId).tree
      DiffFormatter(DisabledOutputStream.INSTANCE).use { formatter ->
        formatter.setRepository(repository)
        formatter.setDetectRenames(true)
        formatter.scan(oldTree, newTree).forEach { entry ->
          if (entry.oldPath != DiffEntry.DEV_NULL) paths.add(entry.oldPath)
          if (entry.newPath != DiffEntry.DEV_NULL) paths.add(entry.newPath)
        }
      }
    }
    return paths
  }

  private fun stageAndCommit(git: Git) {
    git.add().addFilepattern(".").call()
    val status = git.status().call()
    if (status.uncommittedChanges.isEmpty()) return

    val name = gitSettings.authorName.ifEmpty { "root" }
    val email = gitSettings.authorEmail.ifEmpty { "localhost" }
    val identity = PersonIdent(name, email)
    git
      .commit()
      .setAll(true)
      .setMessage("[Android Password Store] Sync")
      .setAuthor(identity)
      .setCommitter(identity)
      .call()
  }

  private fun pull(git: Git, timeoutSeconds: Int) {
    val command = git.pull().setRemote("origin").setRebase(gitSettings.rebaseOnPull)
    val cleanup = configureTransport(command, timeoutSeconds)
    try {
      val result = command.call()
      if (!result.isSuccessful) {
        val detail =
          result.rebaseResult?.status?.name
            ?: result.mergeResult?.mergeStatus?.name
            ?: "unknown status"
        throw PasskeySyncException("Git pull failed: $detail", retryable = false)
      }
    } finally {
      cleanup()
    }
  }

  private fun push(git: Git) {
    val command = git.push().setPushAll().setRemote("origin")
    val cleanup = configureTransport(command, BACKGROUND_SYNC_TIMEOUT_SECONDS)
    try {
      command.call().forEach { pushResult ->
        pushResult.remoteUpdates.forEach { update ->
          when (update.status) {
            RemoteRefUpdate.Status.OK,
            RemoteRefUpdate.Status.UP_TO_DATE -> {}
            RemoteRefUpdate.Status.REJECTED_NONFASTFORWARD,
            RemoteRefUpdate.Status.REJECTED_REMOTE_CHANGED,
            RemoteRefUpdate.Status.NOT_ATTEMPTED ->
              throw PasskeySyncException(
                "Git push failed: ${update.status}${update.message?.let { ": $it" } ?: ""}",
                retryable = true,
              )
            else ->
              throw PasskeySyncException(
                "Git push failed: ${update.status}${update.message?.let { ": $it" } ?: ""}",
                retryable = false,
              )
          }
        }
      }
    } finally {
      cleanup()
    }
  }

  private fun configureTransport(
    command: TransportCommand<*, *>,
    timeoutSeconds: Int,
  ): () -> Unit {
    var sshFactory: HeadlessSshSessionFactory? = null
    var credentialsProvider: WipingCredentialsProvider? = null
    command.setTimeout(timeoutSeconds)
    command.setTransportConfigCallback { transport: Transport ->
      when (transport) {
        is SshTransport -> {
          sshFactory =
            HeadlessSshSessionFactory(
              authMode = gitSettings.authMode,
              hostKeyFile = File(filesDirPath, ".host_key"),
              passwordLoader = { requireStoredPassword(PreferenceKeys.HTTPS_PASSWORD) },
              sshPassphraseLoader = {
                loadStoredPassword(PreferenceKeys.SSH_KEY_LOCAL_PASSPHRASE)
              },
            )
          transport.sshSessionFactory = sshFactory
        }
        else -> {
          if (gitSettings.authMode == AuthMode.Password) {
            credentialsProvider =
              WipingCredentialsProvider(requireStoredPassword(PreferenceKeys.HTTPS_PASSWORD))
            transport.credentialsProvider = credentialsProvider
          }
        }
      }
    }
    return {
      sshFactory?.close()
      credentialsProvider?.close()
    }
  }

  private fun requireStoredPassword(key: String): CharArray {
    return loadStoredPassword(key)
      ?: throw PasskeySyncException(
        "Stored Git credential is unavailable; interactive sync is required",
        retryable = false,
      )
  }

  private fun loadStoredPassword(key: String): CharArray? {
    val encrypted = gitSecrets.getString(key, null)?.toCharArray() ?: return null
    return try {
      AESEncryption.decrypt(encrypted, keyType = AESEncryption.KeyType.PERSISTENT)
    } finally {
      encrypted.fill('\u0000')
    }
  }

  private fun Throwable.isRetryableTransportFailure(): Boolean {
    var current: Throwable? = this
    while (current != null) {
      if (
        current is IOException ||
          current is org.eclipse.jgit.api.errors.TransportException ||
          current is org.eclipse.jgit.errors.TransportException
      ) {
        return true
      }
      current = current.cause
    }
    return false
  }

  private companion object {
    const val BACKGROUND_SYNC_TIMEOUT_SECONDS = 10
    const val REMOTE_REFRESH_TIMEOUT_SECONDS = 3
  }
}

private class WipingCredentialsProvider(private val password: CharArray) : CredentialsProvider() {
  override fun isInteractive(): Boolean = false

  override fun supports(vararg items: CredentialItem): Boolean = items.all {
    it is CredentialItem.Username || it is CredentialItem.Password
  }

  override fun get(uri: URIish?, vararg items: CredentialItem): Boolean {
    items.forEach { item ->
      when (item) {
        is CredentialItem.Username -> item.value = uri?.user
        is CredentialItem.Password -> item.value = password.copyOf()
        else -> return false
      }
    }
    return true
  }

  override fun reset(uri: URIish?) {}

  fun close() {
    password.fill('\u0000')
  }
}

private class HeadlessSshSessionFactory(
  private val authMode: AuthMode,
  private val hostKeyFile: File,
  private val passwordLoader: () -> CharArray,
  private val sshPassphraseLoader: () -> CharArray?,
) : org.eclipse.jgit.transport.SshSessionFactory() {

  private var currentSession: HeadlessSshSession? = null

  override fun getSession(
    uri: URIish,
    credentialsProvider: CredentialsProvider?,
    fs: FS?,
    tms: Int,
  ): org.eclipse.jgit.transport.RemoteSession {
    return currentSession
      ?: HeadlessSshSession(
          uri = uri,
          authMode = authMode,
          hostKeyFile = hostKeyFile,
          passwordLoader = passwordLoader,
          sshPassphraseLoader = sshPassphraseLoader,
        )
        .connect()
        .also { currentSession = it }
  }

  override fun getType(): String = "HeadlessSshSessionFactory"

  fun close() {
    currentSession?.close()
    currentSession = null
  }
}

private class HeadlessSshSession(
  uri: URIish,
  private val authMode: AuthMode,
  private val hostKeyFile: File,
  private val passwordLoader: () -> CharArray,
  private val sshPassphraseLoader: () -> CharArray?,
) : org.eclipse.jgit.transport.RemoteSession {

  private val uri = normalizeUri(uri)
  private lateinit var ssh: SSHClient
  private var currentSession: Session? = null

  fun connect(): HeadlessSshSession {
    if (!hostKeyFile.exists()) {
      throw PasskeySyncException(
        "SSH host key is not trusted yet; interactive sync is required",
        retryable = false,
      )
    }

    setUpBouncyCastleForSshj()
    ssh = SSHClient(SshjConfig())
    try {
      ssh.addHostKeyVerifier(FingerprintVerifier.getInstance(hostKeyFile.readText()))
      ssh.connect(uri.host, uri.port.takeUnless { it == -1 } ?: 22)
      if (!ssh.isConnected) throw IOException("SSH connection failed")
      val user = uri.user ?: "git"

      when (authMode) {
        AuthMode.Password -> {
          val password = passwordLoader()
          try {
            ssh.auth(user, AuthPassword(StaticPasswordFinder(password)))
          } finally {
            password.fill('\u0000')
          }
        }
        AuthMode.SshKey -> authenticateWithSshKey(user)
        AuthMode.None ->
          throw PasskeySyncException(
            "Headless SSH requires a configured authentication mode",
            retryable = false,
          )
      }
      return this
    } catch (e: Exception) {
      ssh.close()
      throw e
    }
  }

  private fun authenticateWithSshKey(user: String) {
    if (!SshKey.exists) {
      throw PasskeySyncException("SSH key is not configured", retryable = false)
    }
    if (SshKey.mustAuthenticate || SshKey.type == SshKey.Type.ImportedPGP) {
      throw PasskeySyncException(
        "SSH key requires interactive authentication",
        retryable = false,
      )
    }

    val passphrase = sshPassphraseLoader() ?: charArrayOf()
    try {
      val keyProvider =
        try {
          SshKey.provide(ssh, StaticPasswordFinder(passphrase))
        } catch (e: Exception) {
          throw PasskeySyncException(
            "SSH key cannot be unlocked non-interactively",
            cause = e,
            retryable = false,
          )
        } ?: throw PasskeySyncException("SSH key is not configured", retryable = false)
      try {
        ssh.auth(user, AuthPublickey(keyProvider))
      } catch (e: Exception) {
        throw PasskeySyncException(
          "SSH authentication failed; interactive sync may be required",
          cause = e,
          retryable = false,
        )
      }
    } finally {
      passphrase.fill('\u0000')
    }
  }

  override fun exec(commandName: String?, timeout: Int): Process {
    currentSession?.close()
    val session = ssh.startSession()
    currentSession = session
    return HeadlessSshProcess(session.exec(commandName), timeout.toLong())
  }

  override fun disconnect() {
    currentSession?.close()
    currentSession = null
  }

  fun close() {
    disconnect()
    if (::ssh.isInitialized) ssh.close()
  }

  private companion object {
    fun normalizeUri(uri: URIish): URIish {
      if (!uri.host.contains('@')) return uri
      val userPlusHost = "${uri.user}@${uri.host}"
      return uri
        .setUser(userPlusHost.substringBeforeLast('@'))
        .setHost(userPlusHost.substringAfterLast('@'))
    }
  }
}

private class StaticPasswordFinder(private val password: CharArray) : PasswordFinder {
  override fun reqPassword(resource: Resource<*>?): CharArray = password.copyOf()

  override fun shouldRetry(resource: Resource<*>?): Boolean = false
}

private class HeadlessSshProcess(
  private val command: Session.Command,
  private val timeout: Long,
) : Process() {
  override fun waitFor(): Int {
    command.join(timeout, TimeUnit.SECONDS)
    command.close()
    return exitValue()
  }

  override fun destroy() = command.close()

  override fun getOutputStream(): OutputStream = command.outputStream

  override fun getErrorStream(): InputStream = command.errorStream

  override fun exitValue(): Int = command.exitStatus

  override fun getInputStream(): InputStream = command.inputStream
}
