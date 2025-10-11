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
import org.bouncycastle.openpgp.api.MessageEncryptionMechanism
import org.bouncycastle.openpgp.api.OpenPGPKey
import org.bouncycastle.util.io.Streams
import org.pgpainless.PGPainless
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.exception.MissingDecryptionMethodException
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.util.Passphrase
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

public class YubiKeyCryptoHandler @Inject constructor() {

  public fun parseEncMessage(
    keyId: KeyId,
    ciphertextStream: InputStream,
  ): Result<Unit, CryptoHandlerException> =
     
    runCatching {
	  val decoderStream = ArmorUtils.getDecoderStream(ciphertextStream)
      val bcpgStream = BCPGInputStream(decoderStream)

      lateinit var encSessionKey: ByteArray
      lateinit var pubKeyAlgorithm: Int
      lateinit var pubKeyVersion: Int
      lateinit var pkeskVersion: Int

      var packet = bcpgStream.readPacket()
      while (packet != null) {
        logcat {"Tag: " + packet.getPacketTag().toString() }
        if (packet is PublicKeyEncSessionPacket && packet.getKeyId() == keyId.id) {
          logcat {"Matching PublicKeyEncSessionPacket found"}
          encSessionKey = packet.getEncSessionKey()[0]
          pubKeyAlgorithm = getAlgorithm()
          pubKeyVersion = getKeyVersion()
          pkeskVersion = getVersion()
		  return@runCatching
	    }	
	  }  
	  throw NoDecryptionKeyAvailableException
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
