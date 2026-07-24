/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import java.io.File
import java.io.FileDescriptor
import java.nio.channels.FileChannel
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import logcat.LogPriority
import logcat.logcat

public fun interface DirectorySyncer {

  public fun sync(dir: File)

  public companion object {
    public val PLATFORM: DirectorySyncer = PlatformDirectorySyncer()
  }
}

internal class PlatformDirectorySyncer : DirectorySyncer {

  override fun sync(dir: File) {
    val path = dir.absolutePath
    val androidOsSyncResult = tryAndroidOsSync(path)
    if (androidOsSyncResult) return
    syncViaFileChannel(path)
  }

  private fun tryAndroidOsSync(path: String): Boolean {
    return try {
      val osClass = Class.forName("android.system.Os")
      val structClass = Class.forName("android.system.OsConstants")
      val oRdonly = structClass.getField("O_RDONLY").getInt(null)
      val openMethod =
        osClass.getMethod("open", String::class.java, Int::class.java, Int::class.java)
      val fd = openMethod.invoke(null, path, oRdonly, 0) as FileDescriptor
      try {
        val fsyncMethod = osClass.getMethod("fsync", FileDescriptor::class.java)
        fsyncMethod.invoke(null, fd)
      } finally {
        try {
          val closeMethod = osClass.getMethod("close", FileDescriptor::class.java)
          closeMethod.invoke(null, fd)
        } catch (e: Exception) {
          logcat(LogPriority.WARN) { "Failed to close directory fd: ${e.message}" }
        }
      }
      true
    } catch (_: ClassNotFoundException) {
      false
    } catch (e: Exception) {
      val cause = e.cause ?: e
      throw DirectorySyncException(
        "Android Os directory fsync failed for $path: ${cause.message}",
        cause,
      )
    }
  }

  private fun syncViaFileChannel(path: String) {
    val channel =
      try {
        FileChannel.open(Path.of(path), StandardOpenOption.READ)
      } catch (e: Exception) {
        throw DirectorySyncException(
          "Failed to open directory for fsync: $path: ${e.message}",
          e,
        )
      }
    try {
      channel.force(true)
    } catch (e: Exception) {
      throw DirectorySyncException(
        "Directory fsync failed for $path: ${e.message}",
        e,
      )
    } finally {
      try {
        channel.close()
      } catch (e: Exception) {
        logcat(LogPriority.WARN) { "Failed to close directory channel: ${e.message}" }
      }
    }
  }
}

public class DirectorySyncException(
  message: String,
  cause: Throwable? = null,
) : RuntimeException(message, cause)
