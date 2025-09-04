/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.extensions

import android.util.Base64
import app.passwordstore.data.repo.PasswordRepository
import java.io.File
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
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

/** A few conversion methods */
fun CharArray.toByteArray(): ByteArray {
  val byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(this))
  val byteArray = ByteArray(byteBuffer.remaining())
  byteBuffer.get(byteArray)
  return byteArray
}

fun ByteArray.toCharArray(): CharArray {
  val charBuffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(this))
  val charArray = CharArray(charBuffer.remaining())
  charBuffer.get(charArray)
  return charArray
}

fun ByteArray.encodeToBase64CharArray(): CharArray {
  val encodedBytes = Base64.encode(this, Base64.NO_WRAP)
  return CharArray(encodedBytes.size) { i -> Char(encodedBytes[i].toUShort()) }
}

fun CharArray.decodeFromBase64ToByteArray(): ByteArray {
  val byteArray = ByteArray(this.size) { i -> this[i].code.toByte() }
  return Base64.decode(byteArray, Base64.NO_WRAP)
}
