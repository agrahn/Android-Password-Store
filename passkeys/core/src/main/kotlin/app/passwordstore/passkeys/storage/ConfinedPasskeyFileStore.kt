/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import com.github.michaelbull.result.Result
import java.io.InputStream
import java.io.OutputStream

public interface ConfinedPasskeyFileStore {

  public suspend fun scanMetadata(
    rpId: String?
  ): Result<List<ScannedCredentialFile>, FileStoreError>

  public suspend fun openExact(
    ref: PasskeyFileRef,
    expectedVersion: CredentialSourceVersion? = null,
  ): Result<OpenedPasskeyFile, FileStoreError>

  public suspend fun createOrReplace(
    ref: PasskeyFileRef,
    writer: suspend (OutputStream) -> Unit,
  ): Result<DurableFileVersion, FileStoreError>

  public suspend fun deleteExact(ref: PasskeyFileRef): Result<Boolean, FileStoreError>

  public suspend fun resolveVersion(
    ref: PasskeyFileRef
  ): Result<SourceVersionResult, FileStoreError>
}

public data class ScannedCredentialFile(
  val ref: PasskeyFileRef,
  val fileSize: Long,
  val lastModifiedMillis: Long,
)

public class OpenedPasskeyFile(
  public val ref: PasskeyFileRef,
  public val version: CredentialSourceVersion,
  private val contentBytes: ByteArray,
) : AutoCloseable {

  @Volatile private var closed = false

  public fun inputStream(): InputStream {
    check(!closed) { "OpenedPasskeyFile has been closed" }
    return contentBytes.inputStream()
  }

  public fun readBytes(): ByteArray {
    check(!closed) { "OpenedPasskeyFile has been closed" }
    return contentBytes.copyOf()
  }

  public fun fileSize(): Long = contentBytes.size.toLong()

  override fun close() {
    if (!closed) {
      closed = true
      contentBytes.fill(0)
    }
  }
}
