/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.autofill

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.res.Resources
import android.graphics.drawable.Icon
import android.os.Build
import android.service.autofill.InlinePresentation
import android.view.View
import android.widget.RemoteViews
import android.widget.inline.InlinePresentationSpec
import androidx.annotation.DrawableRes
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import app.passwordstore.R
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.ui.passwords.PasswordStore
import java.io.File

data class DatasetMetadata(
  val title: String?,
  val subtitle: String?,
  @DrawableRes val iconRes: Int,
  val suggestionCount: Int,
  val maxSuggestions: Int,
)

fun makeRemoteView(context: Context, metadata: DatasetMetadata): RemoteViews {
  return RemoteViews(context.packageName, R.layout.oreo_autofill_dataset).apply {
    if (metadata.title != null) {
      setTextViewText(R.id.title, metadata.title)
    } else {
      setViewVisibility(R.id.title, View.GONE)
    }
    if (metadata.subtitle != null) {
      setTextViewText(R.id.summary, metadata.subtitle)
    } else {
      setViewVisibility(R.id.summary, View.GONE)
    }
    if (metadata.iconRes != Resources.ID_NULL) {
      setImageViewResource(R.id.icon, metadata.iconRes)
    } else {
      setViewVisibility(R.id.icon, View.GONE)
    }
  }
}

private var requestCode = 500000

@SuppressLint("RestrictedApi")
fun makeInlinePresentation(
  context: Context,
  imeSpec: InlinePresentationSpec,
  metadata: DatasetMetadata,
): InlinePresentation? {
  if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null

  if (UiVersions.INLINE_UI_VERSION_1 !in UiVersions.getVersions(imeSpec.style)) return null

  val launchIntent =
    PendingIntent.getActivity(
      context,
      requestCode++,
      Intent(context, PasswordStore::class.java),
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        PendingIntent.FLAG_MUTABLE
      } else {
        0
      },
    )
  val slice =
    InlineSuggestionUi.newContentBuilder(launchIntent).run {
      setTitle(metadata.title?.let { it } ?: "")
      setSubtitle(metadata.subtitle?.let { it } ?: "")
      setContentDescription(
        metadata.title?.let { it }
          ?: "" +
            if (metadata.title != null && metadata.subtitle != null) " - "
            else "" + metadata.subtitle?.let { it } ?: ""
      )
      setStartIcon(Icon.createWithResource(context, metadata.iconRes))
      build().slice
    }

  return InlinePresentation(slice, imeSpec, false)
}

fun makeFillMatchMetadata(
  context: Context,
  file: File,
  suggestionCount: Int,
  maxSuggestions: Int,
): DatasetMetadata {
  val directoryStructure = AutofillPreferences.directoryStructure(context)
  val relativeFile = file.relativeTo(PasswordRepository.getRepositoryDirectory())
  val title = directoryStructure.getPathStringWithAtMostTwoParentsFor(relativeFile)

  return DatasetMetadata(
    null,
    title,
    R.drawable.ic_person_black_24dp,
    suggestionCount,
    maxSuggestions,
  )
}

fun makeSearchAndFillMetadata(context: Context, suggestionCount: Int, maxSuggestions: Int) =
  DatasetMetadata(
    null,
    context.getString(R.string.oreo_autofill_search_in_store),
    R.drawable.ic_search_black_24dp,
    suggestionCount,
    maxSuggestions,
  )

fun makeGenerateAndFillMetadata(context: Context, suggestionCount: Int, maxSuggestions: Int) =
  DatasetMetadata(
    null,
    context.getString(R.string.oreo_autofill_generate_password),
    R.drawable.ic_autofill_new_password,
    suggestionCount,
    maxSuggestions,
  )

fun makeEmptyMetadata() = DatasetMetadata("PLACEHOLDER", "PLACEHOLDER", R.mipmap.ic_launcher, 0, 0)

fun makeWarningMetadata(context: Context) =
  DatasetMetadata(
    context.getString(R.string.oreo_autofill_warning_publisher_dataset_title),
    context.getString(R.string.oreo_autofill_warning_publisher_dataset_summary),
    R.drawable.ic_warning_red_24dp,
    0,
    0,
  )

fun makeHeaderMetadata(title: String) =
  DatasetMetadata(title, null, R.drawable.ic_launcher_monochrome, 0, 0)
