/*
 * Copyright (C) 2014-2026 The Android Password Store Authors.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.crypto.PasskeyDecryptionError
import app.passwordstore.passkeys.crypto.PasskeyPgpDecryptor
import app.passwordstore.passkeys.crypto.PgpUnlockContext
import com.github.michaelbull.result.fold
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import logcat.LogPriority
import logcat.logcat

public data class PasskeyStorageDiagnosticReport(
  val totalEncryptedFiles: Int,
  val filesWithNoMatchingKey: Int,
  val filesWithLockedKeys: Int,
  val filesWithMalformedCiphertext: Int,
  val filesWithIntegrityErrors: Int,
  val filesWithIncorrectPassphrase: Int,
  val filesSuccessfullyDecrypted: Int,
  val filesOversized: Int,
  val recipientKeyIssues: Map<String, Set<String>>,
)

public class PasskeyStorageDiagnostics(
  private val repositoryRoot: File,
  private val passkeyPgpDecryptor: PasskeyPgpDecryptor,
  private val pgpUnlockContext: PgpUnlockContext,
  private val config: PasskeyStorageConfig = PasskeyStorageConfig(),
) {

  public suspend fun generateReport(): PasskeyStorageDiagnosticReport =
    withContext(Dispatchers.IO) {
      val passkeyDir = File(repositoryRoot, config.passkeyDirectory)
      if (!passkeyDir.exists() || !passkeyDir.isDirectory) {
        return@withContext PasskeyStorageDiagnosticReport(0, 0, 0, 0, 0, 0, 0, 0, emptyMap())
      }

      var totalFiles = 0
      var noMatchingKey = 0
      var lockedKeys = 0
      var malformedCiphertext = 0
      var integrityErrors = 0
      var incorrectPassphrase = 0
      var successful = 0
      var oversizedFiles = 0
      val recipientKeyIssues = mutableMapOf<String, MutableSet<String>>()

      passkeyDir
        .walkTopDown()
        .filter { it.isFile && it.extension == config.fileExtension.removePrefix(".") }
        .forEach { file ->
          totalFiles++

          try {
            val result = passkeyPgpDecryptor.decrypt(file, pgpUnlockContext)

            result.fold(
              success = {
                successful++
                it.close()
              },
              failure = { error ->
                when (error) {
                  is PasskeyDecryptionError.NoRecipientPackets -> malformedCiphertext++
                  is PasskeyDecryptionError.MissingSecretKey -> {
                    noMatchingKey++
                    error.recipientIds.forEach { recipientId ->
                      recipientKeyIssues.getOrPut(recipientId) { mutableSetOf() }.add(file.name)
                    }
                  }
                  is PasskeyDecryptionError.KeyLocked -> lockedKeys++
                  is PasskeyDecryptionError.IncorrectPassphrase -> incorrectPassphrase++
                  is PasskeyDecryptionError.IntegrityCheckFailed -> integrityErrors++
                  is PasskeyDecryptionError.MalformedCiphertext -> malformedCiphertext++
                  is PasskeyDecryptionError.UnsupportedFormat -> malformedCiphertext++
                  is PasskeyDecryptionError.CiphertextTooLarge -> oversizedFiles++
                  is PasskeyDecryptionError.PlaintextTooLarge -> oversizedFiles++
                }
              },
            )
          } catch (e: Exception) {
            logcat(LogPriority.ERROR) { "Diagnostic check failed for ${file.name}: ${e.message}" }
            malformedCiphertext++
          }
        }

      PasskeyStorageDiagnosticReport(
        totalEncryptedFiles = totalFiles,
        filesWithNoMatchingKey = noMatchingKey,
        filesWithLockedKeys = lockedKeys,
        filesWithMalformedCiphertext = malformedCiphertext,
        filesWithIntegrityErrors = integrityErrors,
        filesWithIncorrectPassphrase = incorrectPassphrase,
        filesSuccessfullyDecrypted = successful,
        filesOversized = oversizedFiles,
        recipientKeyIssues = recipientKeyIssues,
      )
    }

  public fun formatReport(report: PasskeyStorageDiagnosticReport): String {
    val sb = StringBuilder()
    sb.appendLine("=== Passkey Storage Diagnostic Report ===")
    sb.appendLine()
    sb.appendLine("Total encrypted passkey files: ${report.totalEncryptedFiles}")
    sb.appendLine("Successfully decrypted: ${report.filesSuccessfullyDecrypted}")
    sb.appendLine()

    if (report.filesWithNoMatchingKey > 0) {
      sb.appendLine("⚠ Files with no matching local secret key: ${report.filesWithNoMatchingKey}")
      if (report.recipientKeyIssues.isNotEmpty()) {
        sb.appendLine("  Missing recipient key IDs:")
        report.recipientKeyIssues.forEach { (keyId, files) ->
          sb.appendLine("    - $keyId (${files.size} file(s))")
        }
      }
      sb.appendLine()
    }

    if (report.filesWithLockedKeys > 0) {
      sb.appendLine("⚠ Files with locked matching keys: ${report.filesWithLockedKeys}")
      sb.appendLine()
    }

    if (report.filesWithIncorrectPassphrase > 0) {
      sb.appendLine("⚠ Files with incorrect passphrase: ${report.filesWithIncorrectPassphrase}")
      sb.appendLine()
    }

    if (report.filesWithIntegrityErrors > 0) {
      sb.appendLine("⚠ Files with integrity errors: ${report.filesWithIntegrityErrors}")
      sb.appendLine()
    }

    if (report.filesWithMalformedCiphertext > 0) {
      sb.appendLine("⚠ Malformed or corrupt files: ${report.filesWithMalformedCiphertext}")
      sb.appendLine()
    }

    if (
      report.filesWithNoMatchingKey == 0 &&
        report.filesWithLockedKeys == 0 &&
        report.filesWithIncorrectPassphrase == 0 &&
        report.filesWithIntegrityErrors == 0 &&
        report.filesWithMalformedCiphertext == 0
    ) {
      sb.appendLine("✓ All passkey files are accessible and properly encrypted")
    }

    return sb.toString()
  }
}
