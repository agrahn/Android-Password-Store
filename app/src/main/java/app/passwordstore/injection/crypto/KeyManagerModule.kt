/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.injection.crypto

import android.content.Context
import app.passwordstore.crypto.PGPKeyManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Qualifier

@Module
@InstallIn(SingletonComponent::class)
object KeyManagerModule {
  @Provides
  fun providePGPKeyManager(@PGPKeyDir keyDir: String): PGPKeyManager = PGPKeyManager(keyDir)

  @Provides
  @PGPKeyDir
  fun providePGPKeyDir(@ApplicationContext context: Context): String =
    context.filesDir.resolve("pgp_keys").absolutePath
}

@Qualifier @Retention(AnnotationRetention.RUNTIME) annotation class PGPKeyDir
