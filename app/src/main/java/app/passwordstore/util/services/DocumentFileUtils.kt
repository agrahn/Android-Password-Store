/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.services

import android.content.Context
import androidx.documentfile.provider.DocumentFile

/**
 * Recursively copies a directory to a destination.
 *
 * @param sourceDirectory directory to copy from.
 * @param targetDirectory directory to copy to.
 */
internal fun copyDirToDir(
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
