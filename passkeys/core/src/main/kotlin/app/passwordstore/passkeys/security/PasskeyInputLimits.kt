/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.security

public data class PasskeyInputLimits(
  val maxCiphertextBytes: Long = 256 * 1024L,
  val maxPlaintextBytes: Long = 64 * 1024L,
  val maxAssetLinksBytes: Long = 256 * 1024L,
  val maxAssetLinkStatements: Int = 256,
  val maxRelationsPerStatement: Int = 16,
  val maxFingerprintsPerStatement: Int = 16,
  val maxCborDepth: Int = 32,
  val maxCborCollectionItems: Int = 4096,
  val maxTextFieldBytes: Int = 16 * 1024,
  val maxBinaryFieldBytes: Int = 16 * 1024,
) {
  init {
    require(maxCiphertextBytes > 0) { "maxCiphertextBytes must be positive" }
    require(maxPlaintextBytes > 0) { "maxPlaintextBytes must be positive" }
    require(maxAssetLinksBytes > 0) { "maxAssetLinksBytes must be positive" }
    require(maxAssetLinkStatements > 0) { "maxAssetLinkStatements must be positive" }
    require(maxRelationsPerStatement > 0) { "maxRelationsPerStatement must be positive" }
    require(maxFingerprintsPerStatement > 0) { "maxFingerprintsPerStatement must be positive" }
    require(maxCborDepth > 0) { "maxCborDepth must be positive" }
    require(maxCborCollectionItems > 0) { "maxCborCollectionItems must be positive" }
    require(maxTextFieldBytes > 0) { "maxTextFieldBytes must be positive" }
    require(maxBinaryFieldBytes > 0) { "maxBinaryFieldBytes must be positive" }
  }

  public companion object {
    public val DEFAULT: PasskeyInputLimits = PasskeyInputLimits()
  }
}
