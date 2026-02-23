/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.gradle

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.kotlin.dsl.register

class AssembleAliasPlugin : Plugin<Project> {
  override fun apply(project: Project) {
    val alias =
      project.tasks.register("assembleFreeRelease") {
        group = "build"
        description = "Alias for assembleRelease (registered by AssembleAliasPlugin)"
      }

    project.afterEvaluate {
      val release = project.tasks.findByName("assembleRelease")
      if (release != null) {
        alias.configure { dependsOn(release) }
      }
    }
  }
}
