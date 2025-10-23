/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.crypto

import app.passwordstore.crypto.errors.CryptoHandlerException
import app.passwordstore.crypto.errors.IncorrectPassphraseException
import app.passwordstore.crypto.errors.NoDecryptionKeyAvailableException
import app.passwordstore.crypto.errors.NoKeysProvidedException
import app.passwordstore.crypto.errors.UnknownError
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.runCatching
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import javax.inject.Inject
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.util.io.Streams
import org.bouncycastle.bcpg.BCPGInputStream
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.exception.MissingDecryptionMethodException
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.util.Passphrase
import org.pgpainless.util.ArmorUtils
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.ApplicationNotAvailableException
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.openpgp.OpenPgpSession
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPIdentifier.KeyId
import app.passwordstore.crypto.PGPKeyManager
import logcat.logcat

public class YubiKeyCryptoHandler @Inject constructor() {

  public fun decryptSessionKey(
    ciphertextStream: InputStream,
	openPgpSession: OpenPgpSession,
  ): Result<Unit, CryptoHandlerException> =
    runCatching {
	  val decoderStream = ArmorUtils.getDecoderStream(ciphertextStream)
      val bcpgStream = BCPGInputStream(decoderStream)

      while (bcpgStream.nextPacketTag() > 0) {
        var packet = bcpgStream.readPacket()
        if (packet is PublicKeyEncSessionPacket) {
          logcat {"PublicKeyEncSessionPacket ID:"  + packet.getKeyID().toHexString()}
          var pubKeyAlgorithm = packet.getAlgorithm()
          var pkeskVersion = packet.getVersion()
          val encSessionKeyData = packet.getEncSessionKey()[0]
          @Suppress("DEPRECATION")
		  val encSessionKey = if(
		   pubKeyAlgorithm == PublicKeyAlgorithmTags.RSA_GENERAL
            || pubKeyAlgorithm == PublicKeyAlgorithmTags.RSA_SIGN
            || pubKeyAlgorithm == PublicKeyAlgorithmTags.RSA_ENCRYPT
		  ){
		    //remove first 2 bytes that encode length
		    encSessionKeyData.copyOfRange(2, encSessionKeyData.size)
		  }else{
            throw NoDecryptionKeyAvailableException()
		  }
		  val sessionKeyRaw = openPgpSession.decrypt(encSessionKey)
	    }	
	  }  
	  ciphertextStream.reset()
	  //throw NoDecryptionKeyAvailableException
    }
    .mapError { error ->
       NoDecryptionKeyAvailableException()
    }

  public fun parseEncMessage(
//    keyId: KeyId,
    ciphertextStream: InputStream,
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
        logcat {"Tag: " + packet.getPacketTag().toString() }
        if (packet is PublicKeyEncSessionPacket) {
          encSessionKey = packet.getEncSessionKey()[0]
          pubKeyAlgorithm = packet.getAlgorithm()
          pubKeyVersion = packet.getKeyVersion()
          pkeskVersion = packet.getVersion()
//		  ciphertextStream.reset()
//		  return@runCatching
          logcat {"+++++++++++++++++++++++++++++PublicKeyEncSessionPacket found ID:"  + packet.getKeyID().toHexString()}
          logcat {"pubKeyAlgorithm:"  + pubKeyAlgorithm.toString()}
          logcat {"pubKeyVersion:"  + pubKeyVersion.toString()}
          logcat {"pkeskVersion:"  + pkeskVersion.toString()}
	    }	
	  }  
	  ciphertextStream.reset()
	  //throw NoDecryptionKeyAvailableException
    }
    .mapError { error ->
       NoDecryptionKeyAvailableException()
    }

  public fun decrypt(
	openPgpSession: OpenPgpSession,
    userpin: CharArray,
    ciphertextStream: InputStream,
    outputStream: OutputStream,
  ): Result<Unit, CryptoHandlerException> =
    runCatching {
      }
      .mapError { error ->
          NoDecryptionKeyAvailableException(error.message, error.cause)
      }

}
