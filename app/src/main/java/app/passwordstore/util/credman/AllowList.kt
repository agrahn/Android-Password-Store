/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.credman

import android.content.Context
import app.passwordstore.Application
import app.passwordstore.R
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

object Allowlist {
  private val privilegedAllowlist: String

  public fun get() = privilegedAllowlist

  init {
    val context: Context = Application.instance.applicationContext

    /* Google-maintained list of privileged (trusted) apps and browsers
    * allowed to make passkey registration and authentication requests
    *
    https://www.gstatic.com/gpm-passkeys-privileged-apps/apps.json
    */
    val privilegedAllowlistGstatic =
      context.resources.openRawResource(R.raw.apps).bufferedReader().use { it.readText() }

    /* Bitwarden-community-maintained list
    *
    https://raw.githubusercontent.com/bitwarden/android/refs/heads/main/app/src/main/assets/fido2_privileged_community.json
    */
    val privilegedAllowlistOther =
      context.resources.openRawResource(R.raw.fido2_privileged_community).bufferedReader().use {
        it.readText()
      }

    privilegedAllowlist =
      mergeJsonArrays(
        privilegedAllowlistGstatic,
        privilegedAllowlistOther,
        arrayName = "apps",
        deduplicateByIdPath = "info.package_name",
      )
  }

  private fun mergeJsonArrays(
    vararg jsonStrings: String,
    arrayName: String,
    deduplicateByIdPath: String? = null,
  ): String {
    // Parse all inputs safely into JsonObjects and extract the target arrays
    val arrays = jsonStrings.map {
      Json.parseToJsonElement(it).jsonObject[arrayName]?.jsonArray ?: JsonArray(emptyList())
    }

    // Track deduplicated elements if a path is provided
    val elementsById = deduplicateByIdPath?.let { linkedMapOf<String, JsonObject>() }
    // Track non-object elements or elements mixed in when deduplication is disabled
    val rawElements = mutableListOf<JsonElement>()

    arrays.forEach { array ->
      array.forEach { element ->
        if (elementsById != null && element is JsonObject) {
          // Find ID using the path picker, fallback to memory identity hash code if missing
          val id =
            getNestedValue(element, deduplicateByIdPath)
              ?: "auto_${System.identityHashCode(element)}"
          elementsById[id] = element
        } else {
          rawElements.add(element)
        }
      }
    }

    // Construct the immutable payload using structural builders
    val finalJson = buildJsonObject {
      put(
        arrayName,
        buildJsonArray {
          // Add raw/non-deduplicated elements first to mimic original logic behavior
          rawElements.forEach { add(it) }
          // Add your deduplicated objects
          elementsById?.values?.forEach { add(it) }
        },
      )
    }

    return finalJson.toString()
  }

  private fun getNestedValue(obj: JsonObject, path: String): String? {
    val keys = path.split(".")
    var current: JsonElement? = obj

    for (key in keys) {
      current =
        when (current) {
          is JsonObject -> current[key]
          else -> return null
        }
      if (current == null) return null
    }

    // Safely unwrap json primitives to string literal text (avoids double quotes)
    return when (current) {
      is JsonPrimitive -> current.content
      else -> current.toString()
    }
  }
}
