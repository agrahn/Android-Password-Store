/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.passkey

import app.passwordstore.util.extensions.b64Encode
import java.security.KeyPair
import java.time.Instant
import java.time.ZoneId

data class PasskeyCredential(
  val credentialId: ByteArray,
  val keyPair: KeyPair,
  val algorithm: Int,
  val rpId: String,
  val user: FidoUser,
  val signCount: UInt = 0u,
  val createdAt: Instant,
  val zoneId: ZoneId,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is PasskeyCredential) return false
    if (!credentialId.contentEquals(other.credentialId)) return false
    if (keyPair != other.keyPair) return false
    if (algorithm != other.algorithm) return false
    if (rpId != other.rpId) return false
    if (user != other.user) return false
    if (signCount != other.signCount) return false
    if (createdAt != other.createdAt) return false
    if (zoneId != other.zoneId) return false
    return true
  }

  override fun hashCode(): Int {
    var result = credentialId.contentHashCode()
    result = 31 * result + keyPair.hashCode()
    result = 31 * result + algorithm
    result = 31 * result + rpId.hashCode()
    result = 31 * result + user.hashCode()
    result = 31 * result + signCount.hashCode()
    result = 31 * result + createdAt.hashCode()
    result = 31 * result + zoneId.hashCode()
    return result
  }

  public fun incrementSignCount(): PasskeyCredential = copy(signCount = signCount + 1u)

  public fun credentialIdBase64(): String = credentialId.b64Encode().concatToString()

  public fun displayNameOrName(): String = user.displayName.takeIf { it.isNotBlank() } ?: user.name
}

data class FidoUser(
  val id: ByteArray,
  val name: String,
  val displayName: String,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is FidoUser) return false
    return id.contentEquals(other.id) && name == other.name && displayName == other.displayName
  }

  override fun hashCode(): Int {
    var result = id.contentHashCode()
    result = 31 * result + name.hashCode()
    result = 31 * result + displayName.hashCode()
    return result
  }
}
