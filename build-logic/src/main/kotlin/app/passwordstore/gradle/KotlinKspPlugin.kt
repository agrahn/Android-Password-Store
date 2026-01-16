/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.gradle

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.apply

@Suppress("Unused")
class KotlinKspPlugin : Plugin<Project> {

  override fun apply(project: Project) {
    // Apply the KSP plugin by id. The version can come from the version catalog's plugin alias
    // (gradle/libs.versions.toml) or pluginManagement. If you didn't add the catalog alias,
    // you can replace this by applying the plugin with a version in module build files.
    project.pluginManager.apply("com.google.devtools.ksp")
    /* project.afterEvaluate {
      javacOptions {
        if (hasDaggerCompilerDependency()) {
          ksp {
            // https://dagger.dev/dev-guide/compiler-options#fastinit-mode
            arg("dagger.fastInit", "enabled")
            // Enable the better, experimental error messages
            // https://github.com/google/dagger/commit/0d2505a727b54f47b8677f42dd4fc5c1924e37f5
            arg("dagger.experimentalDaggerErrorMessages", "enabled")
            // Share test components for when we start leveraging Hilt for tests
            // https://github.com/google/dagger/releases/tag/dagger-2.34
            arg("dagger.hilt.shareTestComponents", "true")
            // Enables per-module validation for faster error detection
            // https://github.com/google/dagger/commit/325b516ac6a53d3fc973d247b5231fafda9870a2
            arg("dagger.moduleBindingValidation", "ERROR")
          }
        }
      }
    } */

    project.tasks
      .matching { it.name.startsWith("ksp") && it.name.endsWith("UnitTestKotlin") }
      .configureEach { enabled = false }

    // Defensive: disable any legacy kapt tasks if still present.
    project.tasks.matching { it.name.startsWith("kapt") }.configureEach { enabled = false }
  }

  private fun Project.hasDaggerCompilerDependency(): Boolean {
    return configurations.any {
      it.dependencies.any { dependency -> dependency.name == "hilt-compiler" }
    }
  }
}
