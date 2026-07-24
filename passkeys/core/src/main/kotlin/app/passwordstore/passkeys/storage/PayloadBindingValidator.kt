/*
 * Copyright (C) 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.passkeys.storage

import app.passwordstore.passkeys.model.StoredCredential
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Ok
import com.github.michaelbull.result.Result

public object PayloadBindingValidator {

  public fun validate(
    requestRpId: String,
    requestCredentialId: ByteArray,
    fileRef: PasskeyFileRef,
    stored: StoredCredential,
  ): Result<Unit, FileStoreError> {
    if (requestRpId != fileRef.canonicalRpId) {
      return Err(
        FileStoreError.PayloadBindingMismatch(
          "Request RP ID '$requestRpId' does not match file ref RP ID '${fileRef.canonicalRpId}'"
        )
      )
    }

    if (requestRpId != stored.rp.id) {
      return Err(
        FileStoreError.PayloadBindingMismatch(
          "Request RP ID '$requestRpId' does not match decrypted CBOR rp.id '${stored.rp.id}'"
        )
      )
    }

    if (fileRef.canonicalRpId != stored.rp.id) {
      return Err(
        FileStoreError.PayloadBindingMismatch(
          "File ref RP ID '${fileRef.canonicalRpId}' does not match decrypted CBOR rp.id '${stored.rp.id}'"
        )
      )
    }

    if (!requestCredentialId.contentEquals(fileRef.credentialId)) {
      return Err(
        FileStoreError.PayloadBindingMismatch(
          "Request credential ID does not match file ref credential ID"
        )
      )
    }

    if (!requestCredentialId.contentEquals(stored.id)) {
      return Err(
        FileStoreError.PayloadBindingMismatch(
          "Request credential ID does not match decrypted CBOR id"
        )
      )
    }

    if (!fileRef.credentialId.contentEquals(stored.id)) {
      return Err(
        FileStoreError.PayloadBindingMismatch(
          "File ref credential ID does not match decrypted CBOR id"
        )
      )
    }

    val filenameHex = fileRef.relativePath.substringAfterLast('/').substringBeforeLast('.')
    val filenameId = hexToBytes(filenameHex)
    if (filenameId != null && !filenameId.contentEquals(stored.id)) {
      return Err(
        FileStoreError.PayloadBindingMismatch(
          "Filename credential ID does not match decrypted CBOR id"
        )
      )
    }

    if (stored.alg != StoredCredential.ALG_ES256) {
      return Err(FileStoreError.PayloadBindingMismatch("Unsupported algorithm: ${stored.alg}"))
    }

    if (stored.privateKey.size != 32) {
      return Err(
        FileStoreError.PayloadBindingMismatch(
          "Invalid private scalar size: ${stored.privateKey.size}"
        )
      )
    }

    val n =
      try {
        val curve = org.bouncycastle.crypto.ec.CustomNamedCurves.getByName("secp256r1")
        curve.n
      } catch (_: Exception) {
        return Err(FileStoreError.IoError("P-256 curve not available"))
      }

    val d = java.math.BigInteger(1, stored.privateKey)
    if (d < java.math.BigInteger.ONE || d >= n) {
      return Err(
        FileStoreError.PayloadBindingMismatch("Private key scalar out of valid P-256 range")
      )
    }

    if (stored.publicKey != null) {
      val derived =
        try {
          StoredCredential.deriveP256PublicKey(stored.privateKey)
        } catch (_: Exception) {
          return Err(
            FileStoreError.PayloadBindingMismatch("Failed to derive public key from private scalar")
          )
        }
      if (!derived.contentEquals(stored.publicKey)) {
        return Err(
          FileStoreError.PayloadBindingMismatch(
            "Stored public key does not match derived public key from private scalar"
          )
        )
      }
    }

    if (stored.id.isEmpty() || stored.id.size > 1023) {
      return Err(
        FileStoreError.PayloadBindingMismatch(
          "Credential ID length out of valid range: ${stored.id.size}"
        )
      )
    }

    return Ok(Unit)
  }
}
