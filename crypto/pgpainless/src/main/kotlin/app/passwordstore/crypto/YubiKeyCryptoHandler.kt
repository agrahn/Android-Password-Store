/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.RFC6637KDFCalculator
import org.bouncycastle.openpgp.operator.PGPPad
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.bcpg.PublicKeyPacket
import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.operator.RFC6637Utils
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.crypto.engines.RFC3394WrapEngine
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.CamelliaEngine
import org.bouncycastle.crypto.Wrapper
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPException
import org.pgpainless.util.SessionKey
import app.passwordstore.crypto.errors.CryptoHandlerException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.crypto.errors.UnsupportedAlgorithmException
import app.passwordstore.crypto.errors.WrongKeyException
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPIdentifier.UserId
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.runCatching
import com.yubico.yubikit.openpgp.OpenPgpSession
import com.yubico.yubikit.core.keys.PublicKeyValues
import java.io.InputStream
import java.io.OutputStream
import javax.inject.Inject
import logcat.logcat
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.pgpainless.util.ArmorUtils
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import java.util.Date

public class YubiKeyCryptoHandler @Inject constructor() {

  public fun decryptSessionKey(
    userPin: CharArray,
    ciphertextStream: InputStream,
    openPgpSession: OpenPgpSession,
    pubKey: PGPPublicKey // encryption subkey
  ): Result<PGPKey, Throwable> =
    runCatching {
        val hwKeyId = getEncKeyIdFromHwKey(openPgpSession).getOrThrow()
        val (keyId, pubKeyAlgorithm, encSessionKeyData) = getEncryptedSessionKeys(ciphertextStream).filter{ (keyId, _, _) ->
          keyId.id == hwKeyId.id 
        }.firstOrNull() ?: throw NoDecryptionKeyAvailableException("No matching decryption key found on the hardware token")
        ciphertextStream.reset()

        openPgpSession.verifyUserPin(userPin, true) // throws InvalidPinException, ApduException or IOException

        val decryptedSessionKey = when (pubKeyAlgorithm) {
          PublicKeyAlgorithmTags.RSA_GENERAL,
          @Suppress("DEPRECATION")
          PublicKeyAlgorithmTags.RSA_SIGN,
          @Suppress("DEPRECATION")
          PublicKeyAlgorithmTags.RSA_ENCRYPT  -> {
            val skLen =
                ((((encSessionKeyData[0].toInt() and 0xff) shl 8) + (encSessionKeyData[1].toInt() and 0xff)) + 7) / 8
            val encSessionKey = ByteArray(skLen)
            System.arraycopy(encSessionKeyData, 2, encSessionKey, 0, skLen)    
            openPgpSession.decrypt(encSessionKey)
          }
          PublicKeyAlgorithmTags.ECDH -> {
            if(pubKey.getKeyID() != keyId.id)
              throw WrongKeyException("Passed-in public subkey ID ${pubKey.getKeyID()} and decryption key ID ${keyId.id} on connected HW key do not match")

            /**
             * Code for decrypting ECDH-encrypted session key was taken from pgpainless, file
             * YubikeyDataDecryptorFactory.kt
             */
            
            val ecPubKey: ECDHPublicBCPGKey = pubKey.publicKeyPacket.key as ECDHPublicBCPGKey 

            // peer key
            val pkLen =
                ((((encSessionKeyData[0].toInt() and 0xff) shl 8) + (encSessionKeyData[1].toInt() and 0xff)) + 7) / 8
            val pkEnc = ByteArray(pkLen)
            System.arraycopy(encSessionKeyData, 2, pkEnc, 0, pkLen)
            
            // encrypted session key
            val keyLen = encSessionKeyData[pkLen + 2].toInt() and 0xff
            val keyEnc = ByteArray(keyLen)
            System.arraycopy(encSessionKeyData, 2 + pkLen + 1, keyEnc, 0, keyLen)

            // perform ECDH key agreement via the YubiKey
            val x9Params = org.bouncycastle.asn1.x9.ECNamedCurveTable.getByOIDLazy(ecPubKey.curveOID)
            val publicPoint = x9Params.curve.decodePoint(pkEnc)
            val peerKey = JcaPGPKeyConverter().setProvider(BouncyCastleProvider())
                .getPublicKey(
                    PGPPublicKey(
                        PublicKeyPacket(
                            pubKey.version, PublicKeyAlgorithmTags.ECDH, Date(),
                            ECDHPublicBCPGKey(
                                ecPubKey.curveOID,
                                publicPoint,
                                ecPubKey.hashAlgorithm.toInt(),
                                ecPubKey.symmetricKeyAlgorithm.toInt(),
                            ),
                        ),
                        BcKeyFingerprintCalculator(),
                    ),
                )

            val secret = openPgpSession.decrypt(PublicKeyValues.fromPublicKey(peerKey))

            // Use the shared key to decrypt the session key
            val hashAlgorithm: Int = ecPubKey.hashAlgorithm.toInt()
            val symmetricKeyAlgorithm: Int = ecPubKey.symmetricKeyAlgorithm.toInt()
            val userKeyingMaterial = RFC6637Utils.createUserKeyingMaterial(
                pubKey.publicKeyPacket,
                BcKeyFingerprintCalculator(),
            )
            val rfc6637KDFCalculator =
                RFC6637KDFCalculator(
                    BcPGPDigestCalculatorProvider()[hashAlgorithm],
                    symmetricKeyAlgorithm,
                )
            val key =
                KeyParameter(rfc6637KDFCalculator.createKey(secret, userKeyingMaterial))

            val wrapper = createWrapper(symmetricKeyAlgorithm).getOrThrow()
            wrapper.init(false, key)
            val unwrappedKey = wrapper.unwrap(keyEnc, 0, keyEnc.size)
    
            PGPPad.unpadSessionData(unwrappedKey)
          }
          else -> throw UnsupportedAlgorithmException("Unsupported public key algorithm (ID: $pubKeyAlgorithm)")
        }

        PGPKey(decryptedSessionKey)
      }
//      .mapError { error -> NoDecryptionKeyAvailableException(error.message) }

    private fun createWrapper(encAlgorithm: Int): Result<RFC3394WrapEngine, Throwable> =
      runCatching {
        when (encAlgorithm) {   
          SymmetricKeyAlgorithmTags.AES_128,
          SymmetricKeyAlgorithmTags.AES_192,
          SymmetricKeyAlgorithmTags.AES_256 ->
              RFC3394WrapEngine(AESEngine.newInstance())
          SymmetricKeyAlgorithmTags.CAMELLIA_128,
          SymmetricKeyAlgorithmTags.CAMELLIA_192,
          SymmetricKeyAlgorithmTags.CAMELLIA_256 ->
              RFC3394WrapEngine(CamelliaEngine())
          else ->
             throw UnsupportedAlgorithmException("Unknown wrap algorithm (ID: $encAlgorithm)")
        }
      }
  
  public fun getEncryptedSessionKeys (
    ciphertextStream: InputStream,
  ): MutableList<Triple<KeyId, Int, ByteArray>> {
    val decoderStream = ArmorUtils.getDecoderStream(ciphertextStream)
    val bcpgStream = BCPGInputStream(decoderStream)

    val encSessionKeys: MutableList<Triple<KeyId, Int, ByteArray>> = mutableListOf()

    var packet = bcpgStream.readPacket()
    while (packet != null) {
      if (packet is PublicKeyEncSessionPacket) {
        val algorithm = packet.getAlgorithm()
        val encSessionKey = packet.getEncSessionKey()[0]
        val keyId = packet.getKeyID()
        encSessionKeys.add(Triple(KeyId(keyId), algorithm, encSessionKey))
      }
      packet = bcpgStream.readPacket()
    }

    return encSessionKeys
  }

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
  public fun getEncKeyIdFromHwKey(openPgpSession: OpenPgpSession): Result<KeyId, CryptoHandlerException> =
    /* Extract the encryption key (DEC) fingerprint (20 bytes) from Application Related
     * Data (tag 0x6E) array. We use tag 0xC4 that preceedes the combined (SIG+DEC+AUT)
     * fingerprints within the app related data array to localise and then slice out the
     * DEC fingerprint.
     */
    runCatching {
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
      return@runCatching PGPIdentifier.fromString(fingerPrintBytes.toHexString()) as KeyId
    }  
    .mapError { error -> NoDecryptionKeyAvailableException(error.message, error.cause) }
}

