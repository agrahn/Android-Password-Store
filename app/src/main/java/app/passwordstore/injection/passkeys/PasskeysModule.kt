/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

@file:OptIn(kotlin.time.ExperimentalTime::class)

package app.passwordstore.injection.passkeys

import android.content.Context
import app.passwordstore.crypto.DefaultPassRecipientResolver
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.crypto.PGPainlessCryptoHandler
import app.passwordstore.crypto.PgpainlessPasskeyDecryptor
import app.passwordstore.passkeys.BiometricPasskeyAuthenticator
import app.passwordstore.passkeys.DefaultRepositoryGenerationProvider
import app.passwordstore.passkeys.DefaultWebAuthnCallerVerifier
import app.passwordstore.passkeys.KeystorePgpUnlockContext
import app.passwordstore.passkeys.PasskeyMetadataIndex
import app.passwordstore.passkeys.PasskeyPassphraseCache
import app.passwordstore.passkeys.crypto.ES256CryptoHandler
import app.passwordstore.passkeys.crypto.PasskeyCryptoHandler
import app.passwordstore.passkeys.crypto.PasskeyPgpDecryptor
import app.passwordstore.passkeys.crypto.PgpUnlockContext
import app.passwordstore.passkeys.provider.PasskeyAuthenticator
import app.passwordstore.passkeys.provider.caller.WebAuthnCallerVerifier
import app.passwordstore.passkeys.storage.FilePasskeyStorage
import app.passwordstore.passkeys.storage.IndexedPasskeyStorage
import app.passwordstore.passkeys.storage.PassRecipientResolver
import app.passwordstore.passkeys.storage.PasskeyMetadataEnricher
import app.passwordstore.passkeys.storage.PasskeyRepositoryState
import app.passwordstore.passkeys.storage.PasskeyStorage
import app.passwordstore.passkeys.storage.PasskeyStorageConfig
import app.passwordstore.passkeys.storage.RepositoryGenerationProvider
import app.passwordstore.passkeys.storage.SignatureCounterHighWaterMark
import app.passwordstore.passkeys.storage.SignatureCounterTransaction
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import java.io.File
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object PasskeysModule {

  @Provides
  @Singleton
  fun providePasskeyCryptoHandler(): PasskeyCryptoHandler = ES256CryptoHandler()

  @Provides
  @Singleton
  fun providePasskeyAuthenticator(): PasskeyAuthenticator = BiometricPasskeyAuthenticator()

  @Provides
  @Singleton
  fun provideCallerVerifier(@ApplicationContext context: Context): WebAuthnCallerVerifier =
    DefaultWebAuthnCallerVerifier(context)

  @Provides
  @Singleton
  fun providePgpUnlockContext(passphraseCache: PasskeyPassphraseCache): PgpUnlockContext =
    KeystorePgpUnlockContext(passphraseCache)

  @Provides
  @Singleton
  fun providePasskeyPgpDecryptor(
    cryptoHandler: PGPainlessCryptoHandler,
    keyManager: PGPKeyManager,
  ): PasskeyPgpDecryptor = PgpainlessPasskeyDecryptor(cryptoHandler, keyManager)

  @Provides
  @Singleton
  fun provideRepositoryGenerationProvider(
    @ApplicationContext context: Context
  ): RepositoryGenerationProvider =
    DefaultRepositoryGenerationProvider(File(context.filesDir, "store"))

  @Provides
  @Singleton
  fun providePassRecipientResolver(
    @ApplicationContext context: Context,
    keyManager: PGPKeyManager,
  ): PassRecipientResolver<PGPKey> {
    val repositoryRoot = File(context.filesDir, "store")
    return DefaultPassRecipientResolver(repositoryRoot, keyManager)
  }

  @Provides
  @Singleton
  fun providePasskeyStorage(
    @ApplicationContext context: Context,
    cryptoHandler: PGPainlessCryptoHandler,
    passkeyPgpDecryptor: PasskeyPgpDecryptor,
    pgpUnlockContext: PgpUnlockContext,
    recipientResolver: PassRecipientResolver<PGPKey>,
    generationProvider: RepositoryGenerationProvider,
    metadataIndex: PasskeyMetadataIndex,
  ): PasskeyStorage {
    val repositoryRoot = File(context.filesDir, "store")
    val passkeyConfig = PasskeyStorageConfig(passkeyDirectory = "fido2", fileExtension = ".gpg")
    val fileStorage =
      FilePasskeyStorage(
        repositoryRoot = repositoryRoot,
        cryptoHandler = cryptoHandler,
        passkeyPgpDecryptor = passkeyPgpDecryptor,
        pgpUnlockContext = pgpUnlockContext,
        recipientResolver = recipientResolver,
        encryptionOptions = app.passwordstore.crypto.PGPEncryptOptions.Builder().build(),
        config = passkeyConfig,
        generationProvider = generationProvider,
      )
    val enricher = PasskeyMetadataEnricher { metadata ->
      val entry = metadataIndex.get(metadata.credentialId)
      if (entry != null) {
        metadata.copy(userName = entry.userName, userDisplayName = entry.userDisplayName)
      } else {
        metadata
      }
    }
    return IndexedPasskeyStorage(fileStorage, generationProvider, metadataEnricher = enricher)
  }

  @Provides
  @Singleton
  fun providePasskeyRepositoryState(passkeyStorage: PasskeyStorage): PasskeyRepositoryState {
    return passkeyStorage as PasskeyRepositoryState
  }

  @Provides
  @Singleton
  fun provideSignatureCounterHighWaterMark(): SignatureCounterHighWaterMark =
    SignatureCounterHighWaterMark()

  @Provides
  @Singleton
  fun provideSignatureCounterTransaction(
    passkeyStorage: PasskeyStorage,
    highWaterMark: SignatureCounterHighWaterMark,
    repositoryState: PasskeyRepositoryState,
  ): SignatureCounterTransaction =
    SignatureCounterTransaction(passkeyStorage, highWaterMark, repositoryState)
}
