/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.passkeys

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class MetadataEntry(
  val userName: String,
  val userDisplayName: String,
  val rpId: String,
  val createdAt: Long = 0L,
)

@Singleton
class PasskeyMetadataIndex private constructor(private val file: File) {

  @Inject
  constructor(
    @ApplicationContext context: Context
  ) : this(File(context.filesDir, "passkey-metadata-index.json"))

  private val json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
  }

  private val index = ConcurrentHashMap<String, MetadataEntry>()
  private var loaded = false

  private fun encodeId(credentialId: ByteArray): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(credentialId)

  private fun decodeId(encoded: String): ByteArray = Base64.getUrlDecoder().decode(encoded)

  private fun ensureLoaded() {
    if (loaded) return
    synchronized(this) {
      if (loaded) return
      if (file.exists()) {
        val content = file.readText()
        if (content.isNotBlank()) {
          val map: Map<String, MetadataEntry> = json.decodeFromString(content)
          index.putAll(map)
        }
      }
      loaded = true
    }
  }

  private fun persist() {
    synchronized(this) {
      file.parentFile?.mkdirs()
      val tmp = File(file.parent, "${file.name}.tmp")
      tmp.writeText(json.encodeToString(index.toMap()))
      tmp.renameTo(file)
    }
  }

  fun get(credentialId: ByteArray): MetadataEntry? {
    ensureLoaded()
    return index[encodeId(credentialId)]
  }

  fun put(credentialId: ByteArray, entry: MetadataEntry) {
    ensureLoaded()
    index[encodeId(credentialId)] = entry
    persist()
  }

  fun getByRpId(rpId: String): List<Pair<ByteArray, MetadataEntry>> {
    ensureLoaded()
    return index.entries.filter { it.value.rpId == rpId }.map { decodeId(it.key) to it.value }
  }

  fun remove(credentialId: ByteArray) {
    ensureLoaded()
    index.remove(encodeId(credentialId))
    persist()
  }

  fun clear() {
    ensureLoaded()
    index.clear()
    persist()
  }

  fun hasEntriesForRpId(rpId: String): Boolean {
    ensureLoaded()
    return index.values.any { it.rpId == rpId }
  }

  internal companion object {
    fun forTesting(indexFile: File): PasskeyMetadataIndex = PasskeyMetadataIndex(indexFile)
  }
}
