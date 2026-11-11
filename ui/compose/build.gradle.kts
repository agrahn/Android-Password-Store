/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
import com.android.build.api.variant.HasUnitTestBuilder
import com.android.build.api.variant.LibraryAndroidComponentsExtension

plugins {
  id("com.github.android-password-store.android-library")
  id("com.github.android-password-store.kotlin-android")
  alias(libs.plugins.kotlin.composeCompiler)
}

extensions.configure<LibraryAndroidComponentsExtension> {
  beforeVariants(selector().withBuildType("release")) { variant ->
    (variant as HasUnitTestBuilder).enableUnitTest = true
  }
}

android {
  buildFeatures {
    compose = true
    android.androidResources.enable = true
  }
  namespace = "app.passwordstore.ui.compose"
}

dependencies {
  api(platform(libs.compose.bom))
  api(libs.compose.foundation.core)
  api(libs.compose.foundation.layout)
  api(libs.compose.material3)
  api(libs.compose.ui.core)
  implementation(libs.androidx.core.ktx)
  implementation(libs.compose.ui.tooling)
  implementation(libs.androidx.material)
}
