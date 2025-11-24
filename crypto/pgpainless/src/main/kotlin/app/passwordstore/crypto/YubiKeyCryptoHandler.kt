/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import java.security.PublicKey
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.crypto.ec.CustomNamedCurves
import app.passwordstore.crypto.RFC6637KDFCalculator
import org.bouncycastle.openpgp.operator.PGPPad
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter
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
import com.yubico.yubikit.openpgp.KeyRef
import java.io.InputStream
import java.io.OutputStream
import javax.inject.Inject
import logcat.logcat
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.pgpainless.util.ArmorUtils
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import java.util.Date
import java.math.BigInteger
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.math.ec.ECPoint

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
            
            val ecPubKey: ECDHPublicBCPGKey = pubKey.getPublicKeyPacket().getKey() as ECDHPublicBCPGKey 

            //logcat {"+++++++++++++++++++++++++++++++++++++++++++sessionkeydata (hex): ${encSessionKeyData.toHexString()}"}
            //logcat {"+++++++++++++++++++++++++++++++++++++++++++sessionkeydata Len: ${encSessionKeyData.size}"}

            //// peer key
            val pkLen =
                ((((encSessionKeyData[0].toInt() and 0xff) shl 8) + (encSessionKeyData[1].toInt() and 0xff)) + 7) / 8
            //val pkEnc = ByteArray(pkLen)
            //System.arraycopy(encSessionKeyData, 2, pkEnc, 0, pkLen)
           
            //logcat {"+++++++++++++++++++++++++++++++++++++++++++pkLen: $pkLen"}
            //logcat {"+++++++++++++++++++++++++++++++++++++++++++pkEnc (hex): ${pkEnc.toHexString()}"}

            //// encrypted session key
            val keyLen = encSessionKeyData[pkLen + 2].toInt() and 0xff
            val keyEnc = ByteArray(keyLen)
            System.arraycopy(encSessionKeyData, 2 + pkLen + 1, keyEnc, 0, keyLen)


            //logcat {"+++++++++++++++++++++++++++++++++++++++++++keyLen: $keyLen"}
            //logcat {"+++++++++++++++++++++++++++++++++++++++++++keyEnc (hex): ${keyEnc.toHexString()}"}

            val peerKey = JcaPGPKeyConverter().setProvider(BouncyCastleProvider()).getPublicKey(pubKey)
            val secret = openPgpSession.decrypt(PublicKeyValues.fromPublicKey(peerKey))

            //// perform ECDH key agreement via the YubiKey
            //val oid = ecPubKey.getCurveOID() // ASN1ObjectIdentifier

            //val x9Params = // X9ECParameters
            //  org.bouncycastle.crypto.ec.CustomNamedCurves.getByOID(oid)
            //      ?: org.bouncycastle.asn1.x9.ECNamedCurveTable.getByOID(oid)
            //      ?: org.bouncycastle.asn1.sec.SECNamedCurves.getByOID(oid)
            //      ?: org.bouncycastle.asn1.nist.NISTNamedCurves.getByOID(oid)
            //      ?: org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves.getByOID(oid)

            //if (x9Params == null) throw IllegalArgumentException("Unknown/unsupported curve OID: $oid")

            val hashAlgorithm: Int = ecPubKey.hashAlgorithm.toInt()

            val symmetricKeyAlgorithm: Int = ecPubKey.symmetricKeyAlgorithm.toInt()

            //////////////////////////////////////////////////////////////////////////////////////////
            ////val publicPoint = x9Params.getCurve().decodePoint(pkEnc)
            ////val peerKey = JcaPGPKeyConverter().setProvider(BouncyCastleProvider())
            ////    .getPublicKey(
            ////        PGPPublicKey(
            ////            PublicKeyPacket(
            ////                pubKey.version, PublicKeyAlgorithmTags.ECDH, Date(),
            ////                ECDHPublicBCPGKey(
            ////                    ecPubKey.curveOID,
            ////                    publicPoint,
            ////                    ecPubKey.hashAlgorithm.toInt(),
            ////                    ecPubKey.symmetricKeyAlgorithm.toInt(),
            ////                ),
            ////            ),
            ////            BcKeyFingerprintCalculator(),
            ////        ),
            ////    )
            ////////////////////////////////////////////////////////////////////////////////////////

            //val (peerKey, keyEnc) = parseTag1EncSessionBlob(
            //    encSessionKeyData,
            //    oid,
            //    x9Params,
            //    hashAlgorithm,
            //    symmetricKeyAlgorithm,
            //  )

            //val secret = openPgpSession.decrypt(PublicKeyValues.fromPublicKey(peerKey))

            // Use the shared key to decrypt the session key
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

  private fun parseTag1EncSessionBlob(
      blob: ByteArray,
      curveOid: ASN1ObjectIdentifier,
      x9Params: X9ECParameters,
      hashAlg: Int,
      symAlg: Int,
      creationDate: Date = Date(),
      version: Int = 4
  ): Pair<PublicKey,ByteArray> { //ephemeral key and encrypted session key
      var off = 0
      if (blob.size < 2) throw IllegalArgumentException("blob too small")
  
      // 1) read two-octet MPI bit-length for the ephemeral-public-key MPI
      val bitLen = ((blob[off].toInt() and 0xff) shl 8) or (blob[off + 1].toInt() and 0xff)
      val mpiByteLen = (bitLen + 7) / 8
      off += 2
      if (off + mpiByteLen > blob.size) throw IllegalArgumentException("truncated MPI for ephemeral public key")
  
      val mpi = blob.copyOfRange(off, off + mpiByteLen)
      off += mpiByteLen
	  mpi[0]=byteArrayOf(3)[0]

	  logcat {"+++++++++++++++++++++++++++++++mpi: "+mpi.toHexString()}
  
      // Determine coordinate byte length for the curve (P-256 -> 32)
      val coordLen = (x9Params.curve.fieldSize + 7) / 8
  
      // 2) Interpret mpi contents and produce ECPoint
      val ecPoint: ECPoint = when {
          // SEC1 point octet string directly in MPI
          mpi.isNotEmpty() && (mpi[0].toInt() and 0xff) in setOf(0x02, 0x03, 0x04) -> {
              x9Params.curve.decodePoint(mpi)
          }
  
          // length-prefixed raw X||Y inside MPI: first byte == expectedXY and mpi.size == 1 + expectedXY
          mpi.size >= 1 -> {
              val first = mpi[0].toInt() and 0xff
              val expectedXY = 2 * coordLen
              if (first == expectedXY && mpi.size == 1 + expectedXY) {
                  val xBytes = mpi.copyOfRange(1, 1 + coordLen)
                  val yBytes = mpi.copyOfRange(1 + coordLen, 1 + expectedXY)
                  val x = BigInteger(1, xBytes)
                  val y = BigInteger(1, yBytes)
                  x9Params.curve.createPoint(x, y)
              } else if (mpi.size == coordLen) {
                  // maybe compressed point without leading prefix? (rare) try to decode by adding compressed prefix if sensible
                  // If you know the parity of Y use 0x02 or 0x03; here we can't, so throw.
                  throw IllegalArgumentException("MPI appears to be a raw X coordinate only; can't reconstruct Y without parity info")
              } else {
                  // last fallback: maybe MPI actually contains an ASN.1 OCTET STRING (first byte 0x04 is tag, but we've handled 0x04 above)
                  // If other patterns occur, dump the MPI hex for diagnosis
                  throw IllegalArgumentException("Unrecognized MPI content for ephemeral EC key: size=${mpi.size}, first=0x%02x".format(mpi[0].toInt() and 0xff))
              }
          }
  
          else -> throw IllegalArgumentException("Empty MPI for ephemeral key")
      }
  
      // 3) Next octet is length of the encrypted session-key blob (one octet)
      if (off >= blob.size) throw IllegalArgumentException("no data left for encrypted session key length")
      val encLen = blob[off].toInt() and 0xff
      off += 1
      if (off + encLen > blob.size) throw IllegalArgumentException("truncated encrypted session key; expected $encLen bytes, have ${blob.size - off}")
  
      val encSessionKey = blob.copyOfRange(off, off + encLen)
      off += encLen
  
      // sanity: no leftover bytes expected; if there are, you can log them
      if (off != blob.size) {
          // optionally warn: leftover bytes present
      }
  
      // 4) build PGPPublicKey packet for the ephemeral EC point so callers can convert to java.security.PublicKey
      val ecdhBCPGKey = ECDHPublicBCPGKey(curveOid, ecPoint, hashAlg, symAlg)
      val pubPacket = PublicKeyPacket(version, PublicKeyAlgorithmTags.ECDH, creationDate, ecdhBCPGKey)
      val pgpPub = PGPPublicKey(pubPacket, BcKeyFingerprintCalculator())
  
      val peerKey = JcaPGPKeyConverter().setProvider(BouncyCastleProvider()).getPublicKey(pgpPub)

      return peerKey to encSessionKey
  }
}
