/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
plugins {
  id("com.github.android-password-store.kotlin-jvm-library")
  alias(libs.plugins.ksp)
}

dependencies {
  api(libs.kotlinx.coroutines.core)
  api(libs.thirdparty.kotlinResult)
  implementation(projects.coroutineUtils)
  implementation(libs.androidx.annotation)
  implementation(libs.dagger.hilt.core)
  ksp(libs.dagger.hilt.compiler)
  implementation(libs.thirdparty.commons.codec)
  implementation(libs.thirdparty.uri)
  testImplementation(libs.bundles.testDependencies)
  testImplementation(libs.kotlinx.coroutines.test)
  testImplementation(libs.testing.turbine)
  implementation(libs.thirdparty.logcat)
}
