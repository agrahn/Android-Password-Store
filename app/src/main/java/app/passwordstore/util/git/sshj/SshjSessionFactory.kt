/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.git.sshj

import android.util.Base64
import androidx.appcompat.app.AppCompatActivity
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.git.operation.CredentialFinder
import app.passwordstore.util.settings.AuthMode
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.runCatching
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.PublicKey
import java.util.Collections
import java.util.concurrent.TimeUnit
import logcat.LogPriority.WARN
import logcat.logcat
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.Buffer.PlainBuffer
import net.schmizz.sshj.common.SSHRuntimeException
import net.schmizz.sshj.common.SecurityUtils
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.transport.verification.FingerprintVerifier
import net.schmizz.sshj.transport.verification.HostKeyVerifier
import net.schmizz.sshj.userauth.method.AuthPassword
import net.schmizz.sshj.userauth.method.AuthPublickey
import org.eclipse.jgit.transport.CredentialsProvider
import org.eclipse.jgit.transport.RemoteSession
import org.eclipse.jgit.transport.SshSessionFactory
import org.eclipse.jgit.transport.URIish
import org.eclipse.jgit.util.FS

sealed class SshAuthMethod(val activity: AppCompatActivity) {
  class Password(activity: AppCompatActivity) : SshAuthMethod(activity)

  class SshKey(activity: AppCompatActivity) : SshAuthMethod(activity)
}

class SshjSessionFactory(
  private val authMethod: SshAuthMethod,
  private val hostKeyFile: File,
  private val dispatcherProvider: DispatcherProvider,
) : SshSessionFactory() {

  private var currentSession: SshjSession? = null

  override fun getSession(
    uri: URIish,
    credentialsProvider: CredentialsProvider?,
    fs: FS?,
    tms: Int,
  ): RemoteSession {
    return currentSession
      ?: SshjSession(uri, uri.user, authMethod, hostKeyFile, dispatcherProvider).connect().also {
        logcat { "New SSH connection created" }
        currentSession = it
      }
  }

  override fun getType(): String {
    return "SshjSessionFactory"
  }

  fun close() {
    currentSession?.close()
  }
}

private fun makeTofuHostKeyVerifier(hostKeyFile: File): HostKeyVerifier {
  if (!hostKeyFile.exists()) {
    return object : HostKeyVerifier {
      override fun verify(hostname: String?, port: Int, key: PublicKey?): Boolean {
        val digest =
          runCatching { SecurityUtils.getMessageDigest("SHA-256") }
            .getOrElse { e -> throw SSHRuntimeException(e) }
        digest.update(PlainBuffer().putPublicKey(key).compactData)
        val digestData = digest.digest()
        val hostKeyEntry = "SHA256:${Base64.encodeToString(digestData, Base64.NO_WRAP)}"
        logcat(SshjSessionFactory::class.java.simpleName) {
          "Trusting host key on first use: $hostKeyEntry"
        }
        hostKeyFile.writeText(hostKeyEntry)
        return true
      }

      override fun findExistingAlgorithms(hostname: String?, port: Int): MutableList<String> {
        return Collections.emptyList()
      }
    }
  } else {
    val hostKeyEntry = hostKeyFile.readText()
    logcat(SshjSessionFactory::class.java.simpleName) { "Pinned host key: $hostKeyEntry" }
    return FingerprintVerifier.getInstance(hostKeyEntry)
  }
}

private class SshjSession(
  uri: URIish,
  private val username: String,
  private val authMethod: SshAuthMethod,
  private val hostKeyFile: File,
  private val dispatcherProvider: DispatcherProvider,
) : RemoteSession {

  init {
    setUpBouncyCastleForSshj()
  }

  private lateinit var ssh: SSHClient
  private var currentCommand: Session? = null

  private val uri =
    if (uri.host.contains('@')) {
      // URIish's String constructor cannot handle '@' in the user part of the URI and the URL
      // constructor can't be used since Java's URL does not recognize the ssh scheme. We thus
      // need to patch everything up ourselves.
      logcat { "Before fixup: user=${uri.user}, host=${uri.host}" }
      val userPlusHost = "${uri.user}@${uri.host}"
      val realUser = userPlusHost.substringBeforeLast('@')
      val realHost = userPlusHost.substringAfterLast('@')
      uri.setUser(realUser).setHost(realHost).also {
        logcat { "After fixup: user=${it.user}, host=${it.host}" }
      }
    } else {
      uri
    }

  fun connect(): SshjSession {
    ssh = SSHClient(SshjConfig())
    ssh.addHostKeyVerifier(makeTofuHostKeyVerifier(hostKeyFile))
    ssh.connect(uri.host, uri.port.takeUnless { it == -1 } ?: 22)
    if (!ssh.isConnected) throw IOException()
    when (authMethod) {
      is SshAuthMethod.Password -> {
        val passwordAuth =
          AuthPassword(CredentialFinder(authMethod.activity, AuthMode.Password, dispatcherProvider))
        ssh.auth(username, passwordAuth)
      }
      is SshAuthMethod.SshKey -> {
        val pubkeyAuth =
          AuthPublickey(
            SshKey.provide(
              ssh,
              CredentialFinder(authMethod.activity, AuthMode.SshKey, dispatcherProvider),
            )
          )
        ssh.auth(username, pubkeyAuth)
      }
    }
    return this
  }

  override fun exec(commandName: String?, timeout: Int): Process {
    if (currentCommand != null) {
      logcat(WARN) { "Killing old command" }
      disconnect()
    }
    val session = ssh.startSession()
    currentCommand = session
    return SshjProcess(session.exec(commandName), timeout.toLong())
  }

  /**
   * Kills the current command if one is running and returns the session into a state where `exec`
   * can be called.
   *
   * Note that this does *not* disconnect the session. Unfortunately, the function has to be called
   * `disconnect` to override the corresponding abstract function in `RemoteSession`.
   */
  override fun disconnect() {
    currentCommand?.close()
    currentCommand = null
  }

  fun close() {
    disconnect()
    ssh.close()
  }
}

private class SshjProcess(private val command: Session.Command, private val timeout: Long) :
  Process() {

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
