/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.extensions

import android.util.Base64
import app.passwordstore.data.repo.PasswordRepository
import java.io.ByteArrayOutputStream
import java.io.File
import java.time.Instant
import logcat.asLog
import org.eclipse.jgit.lib.ObjectId
import org.eclipse.jgit.revwalk.RevCommit

/** Checks if this [Int] contains the given [flag] */
infix fun Int.hasFlag(flag: Int): Boolean {
  return this and flag == flag
}

/** Checks whether this [File] is a directory that contains [other] as a direct child. */
fun File.contains(other: File): Boolean {
  if (!isDirectory) return false
  if (File(getCanonicalPath(), other.getName()).getCanonicalPath() != other.getCanonicalPath())
    return false
  return other.exists()
}

/**
 * Checks if this [File] is in the password repository directory as given by
 * [PasswordRepository.getRepositoryDirectory]
 */
fun File.isInsideRepository(): Boolean {
  return canonicalPath.contains(PasswordRepository.getRepositoryDirectory().canonicalPath)
}

/** Recursively lists the files in this [File], skipping any directories it encounters. */
fun File.listFilesRecursively() = walkTopDown().filter { !it.isDirectory }.toList()

/**
 * Unique SHA-1 hash of this commit as hexadecimal string.
 *
 * @see RevCommit.getId
 */
val RevCommit.hash: String
  get() = ObjectId.toString(id)

/**
 * Time this commit was made with second precision.
 *
 * @see RevCommit.commitTime
 */
val RevCommit.time: Instant
  get() {
    val epochSeconds = commitTime.toLong()
    return Instant.ofEpochSecond(epochSeconds)
  }

/** Alias to [lazy] with thread safety mode always set to [LazyThreadSafetyMode.NONE]. */
fun <T> unsafeLazy(initializer: () -> T) = lazy(LazyThreadSafetyMode.NONE) { initializer.invoke() }

/** A convenience extension to turn a [Throwable] with a message into a loggable string. */
fun Throwable.asLog(message: String): String = "$message\n${asLog()}"

/** Convert this [String] to its [Base64] representation */
fun String.base64(): String {
  return Base64.encodeToString(encodeToByteArray(), Base64.NO_WRAP)
}

fun String.substringBefore(delimiter: Regex, missingDelimiterValue: String = this): String =
  delimiter.find(this)?.value?.let { substringBefore(it) } ?: missingDelimiterValue

fun CharArray.wipe() {
  fill('\u0000')
  drop(size)
}

fun ByteArray.wipe() {
  fill(0)
  drop(size)
}

fun ByteArrayOutputStream.wipe() {
  size().let {
    reset()
    write(ByteArray(it))
  }
  reset()
}
