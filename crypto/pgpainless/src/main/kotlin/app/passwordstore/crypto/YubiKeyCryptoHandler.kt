/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.errors.CryptoHandlerException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPIdentifier.UserId
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.runCatching
import com.yubico.yubikit.openpgp.OpenPgpSession
import java.io.InputStream
import java.io.OutputStream
import javax.inject.Inject
import logcat.logcat
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.pgpainless.util.ArmorUtils

public class YubiKeyCryptoHandler @Inject constructor() {

  public fun decryptSessionKey(
    userPin: CharArray?,
    ciphertextStream: InputStream,
    openPgpSession: OpenPgpSession,
  ): Result<Unit, CryptoHandlerException> =
    runCatching {
        val decoderStream = ArmorUtils.getDecoderStream(ciphertextStream)
        val bcpgStream = BCPGInputStream(decoderStream)

        while (bcpgStream.nextPacketTag() > 0) {
          var packet = bcpgStream.readPacket()
          if (packet is PublicKeyEncSessionPacket) {
            logcat { "PublicKeyEncSessionPacket ID:" + packet.getKeyID().toHexString() }
            var pubKeyAlgorithm = packet.getAlgorithm()
            var pkeskVersion = packet.getVersion()
            val encSessionKeyData = packet.getEncSessionKey()[0]
            @Suppress("DEPRECATION")
            val encSessionKey =
              if (
                pubKeyAlgorithm == PublicKeyAlgorithmTags.RSA_GENERAL ||
                  pubKeyAlgorithm == PublicKeyAlgorithmTags.RSA_SIGN ||
                  pubKeyAlgorithm == PublicKeyAlgorithmTags.RSA_ENCRYPT
              ) {
                // remove first 2 bytes that encode length
                encSessionKeyData.copyOfRange(2, encSessionKeyData.size)
              } else {
                throw NoDecryptionKeyAvailableException()
              }
            val sessionKeyRaw = openPgpSession.decrypt(encSessionKey)
          }
        }
        ciphertextStream.reset()
        // throw NoDecryptionKeyAvailableException
      }
      .mapError { error -> NoDecryptionKeyAvailableException() }

  public fun parseEncMessage(
    //    keyId: KeyId,
    ciphertextStream: InputStream
  ): Result<Unit, CryptoHandlerException> =
    runCatching {
        val decoderStream = ArmorUtils.getDecoderStream(ciphertextStream)
        val bcpgStream = BCPGInputStream(decoderStream)

        lateinit var encSessionKey: ByteArray
        var pubKeyAlgorithm: Int = -1
        var pubKeyVersion: Int = -1
        var pkeskVersion: Int = -1

        while (bcpgStream.nextPacketTag() > 0) {
          var packet = bcpgStream.readPacket()
          logcat { "Tag: " + packet.getPacketTag().toString() }
          if (packet is PublicKeyEncSessionPacket) {
            encSessionKey = packet.getEncSessionKey()[0]
            pubKeyAlgorithm = packet.getAlgorithm()
            pubKeyVersion = packet.getKeyVersion()
            pkeskVersion = packet.getVersion()
            //		  ciphertextStream.reset()
            //		  return@runCatching
            logcat {
              "+++++++++++++++++++++++++++++PublicKeyEncSessionPacket found ID:" +
                packet.getKeyID().toHexString()
            }
            logcat { "pubKeyAlgorithm:" + pubKeyAlgorithm.toString() }
            logcat { "pubKeyVersion:" + pubKeyVersion.toString() }
            logcat { "pkeskVersion:" + pkeskVersion.toString() }
          }
        }
        ciphertextStream.reset()
        // throw NoDecryptionKeyAvailableException
      }
      .mapError { error -> NoDecryptionKeyAvailableException() }

  public fun decrypt(
    userpin: CharArray,
    ciphertextStream: InputStream,
    outputStream: OutputStream,
    openPgpSession: OpenPgpSession,
  ): Result<Unit, CryptoHandlerException> =
    runCatching {}
      .mapError { error -> NoDecryptionKeyAvailableException(error.message, error.cause) }
      
  /**
   * Get the KeyId from the connected hardware key, using the encryption key fingerprint it contains
   */
  public fun getEncKeyIdFromHwKey(openPgpSession: OpenPgpSession): KeyId? {
    /* Extract the encryption key (DEC) fingerprint (20 bytes) from Application Related
     * Data (tag 0x6E) array. We use tag 0xC4 that preceedes the combined (SIG+DEC+AUT)
     * fingerprints within the app related data array to localise and then slice out the
     * DEC fingerprint.
     */
    val tag0x6EString = openPgpSession.getData(0x6E).toHexString() // Application Related Data
    val tag0xC4String = "c407" + openPgpSession.getData(0xC4).toHexString() // preceeding data
    val leadingRegex = "^6e.*${tag0xC4String}".toRegex()
    val combinedFingerprintsPlus = tag0x6EString.replaceFirst(leadingRegex, "").hexToByteArray()
    require(combinedFingerprintsPlus[0].toUByte().toInt() == 0xC5) { // tag ID of combined FPs
      "Combined fingerprint subarray (tag ID 0xC5) not found"
    }
    require( // length of combined fingerprints subarray
      combinedFingerprintsPlus[1].toUByte().toInt() >= 60
    ) {
      "Assertion error of fingerprint subarray length"
    }
    val fingerPrintBytes =
      combinedFingerprintsPlus.copyOfRange(
        2 + 20,
        2 + 40,
      ) // skip SIG fingerprint and drop trailing bytes
    return PGPIdentifier.fromString(fingerPrintBytes.toHexString()) as KeyId
  }

}

