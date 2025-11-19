/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Code taken from BouncyCastle-1.81 file of the same base name,
 * converted to Kotlin on https://syntha.ai/converters/java-to-kotlin
 *
 */

package app.passwordstore.crypto

import java.io.IOException
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.operator.PGPDigestCalculator

public class RFC6637KDFCalculator(private val digCalc: PGPDigestCalculator, private val keyAlgorithm: Int) {
    @Throws(PGPException::class)
    public fun createKey(secret: ByteArray, userKeyingMaterial: ByteArray): ByteArray {
        return try {
            KDF(digCalc, secret, getKeyLen(keyAlgorithm), userKeyingMaterial)
        } catch (e: IOException) {
            throw PGPException("Exception performing KDF: ${e.message}", e)
        }
    }

    private companion object {
        @Throws(IOException::class)
        private fun KDF(digCalc: PGPDigestCalculator, ZB: ByteArray, keyLen: Int, param: ByteArray): ByteArray {
            val dOut = digCalc.outputStream
            dOut.write(0x00)
            dOut.write(0x00)
            dOut.write(0x00)
            dOut.write(0x01)
            dOut.write(ZB)
            dOut.write(param)
            val digest = digCalc.digest
            val key = ByteArray(keyLen)
            System.arraycopy(digest, 0, key, 0, key.size)
            return key
        }

        @Throws(PGPException::class)
        private fun getKeyLen(algID: Int): Int {
            return when (algID) {
                SymmetricKeyAlgorithmTags.AES_128, SymmetricKeyAlgorithmTags.CAMELLIA_128 -> 16
                SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.CAMELLIA_192 -> 24
                SymmetricKeyAlgorithmTags.AES_256, SymmetricKeyAlgorithmTags.CAMELLIA_256 -> 32
                else -> throw PGPException("unknown symmetric algorithm ID: $algID")
            }
        }
    }
}
