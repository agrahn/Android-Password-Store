/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:Suppress("UnstableApiUsage")

package app.passwordstore.gradle

import me.tylerbwong.gradle.metalava.Documentation
import me.tylerbwong.gradle.metalava.extension.MetalavaExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.apply
import org.gradle.kotlin.dsl.configure

@Suppress("Unused")
class PublishedAndroidLibraryPlugin : Plugin<Project> {

  override fun apply(project: Project) {
    project.plugins.run {
      apply(LibraryPlugin::class)
      apply("me.tylerbwong.gradle.metalava")
    }
    project.extensions.configure<MetalavaExtension> {
      documentation.set(Documentation.PUBLIC)
      inputKotlinNulls.set(true)
      outputKotlinNulls.set(true)
      reportLintsAsErrors.set(true)
      reportWarningsAsErrors.set(true)
    }
  }
}
