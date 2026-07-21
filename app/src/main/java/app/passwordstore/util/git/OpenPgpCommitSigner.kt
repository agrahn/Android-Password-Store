/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.git

import android.widget.Button
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.FragmentActivity
import app.passwordstore.R
import app.passwordstore.crypto.KeyUtils
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.PGPKey
import app.passwordstore.crypto.PGPKeyManager
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.crypto.CardReader
import app.passwordstore.util.crypto.OpenPgpCardPrompt
import app.passwordstore.util.crypto.OpenPgpNfcCard
import app.passwordstore.util.crypto.OpenPgpSmartcardStore
import app.passwordstore.util.crypto.SmartcardOperationHandledException
import app.passwordstore.util.extensions.hideKeyboard
import app.passwordstore.util.extensions.wipe
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getOrElse
import com.github.michaelbull.result.runCatching
import com.google.android.material.R as materialR
import com.google.android.material.color.MaterialColors
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import logcat.asLog
import logcat.logcat
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.DigestInfo
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.PGPContentSigner
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.eclipse.jgit.api.errors.CanceledException
import org.eclipse.jgit.lib.CommitBuilder
import org.eclipse.jgit.lib.GpgSignature
import org.eclipse.jgit.lib.GpgSigner
import org.eclipse.jgit.lib.PersonIdent
import org.eclipse.jgit.transport.CredentialsProvider

class OpenPgpCommitSigner(
  private val activity: FragmentActivity,
  private val keyManager: PGPKeyManager,
  private val smartcardStore: OpenPgpSmartcardStore,
  private val dispatcherProvider: DispatcherProvider,
) : GpgSigner() {

  override fun sign(
    commit: CommitBuilder,
    gpgSigningKey: String?,
    committer: PersonIdent,
    credentialsProvider: CredentialsProvider?,
  ) {
    val signingKey = resolveSigningKey(gpgSigningKey)
    val primaryKeyId =
      KeyUtils.tryGetKeyId(signingKey)
        ?: throw PGPException("Cannot determine OpenPGP signing key ID")
    val payload = commit.build()
    val signature =
      if (smartcardStore.hasAssociation(primaryKeyId)) {
        signWithSmartcard(signingKey, primaryKeyId, payload)
      } else {
        signWithSecretKey(signingKey, payload)
      }
    // A null signature means the user chose to proceed with an unsigned commit.
    if (signature != null) {
      commit.setGpgSignature(GpgSignature(signature))
    }
  }

  override fun canLocateSigningKey(
    gpgSigningKey: String?,
    committer: PersonIdent,
    credentialsProvider: CredentialsProvider?,
  ): Boolean = runCatching { resolveSigningKey(gpgSigningKey) }.isOk

  private fun resolveSigningKey(gpgSigningKey: String?): PGPKey {
    val identifiers =
      gpgSigningKey?.let(PGPIdentifier::fromString)?.let(::listOf) ?: rootGpgIdentifiers()
    identifiers.forEach { identifier ->
      keyManager.getKeyById(identifier).get()?.let {
        return it
      }
    }
    throw PGPException("No OpenPGP key from .gpg-id is available for Git commit signing")
  }

  private fun rootGpgIdentifiers(): List<PGPIdentifier> {
    val gpgIdFile = PasswordRepository.getRepositoryDirectory().resolve(".gpg-id")
    if (!gpgIdFile.isFile) throw PGPException("No root .gpg-id found for Git commit signing")
    return gpgIdFile
      .readLines()
      .map { it.substringBefore('#').substringBefore('!').trim() }
      .filter { it.isNotEmpty() && it != "gpg-id" }
      .mapNotNull(PGPIdentifier::fromString)
  }

  private fun signWithSecretKey(key: PGPKey, payload: ByteArray): ByteArray {
    val secretKey = findSecretSigningKey(key)
    if (secretKey.isPrivateKeyEmpty) {
      throw PGPException("Git commit signing key is a smartcard stub without a card association")
    }
    val passphrase =
      runBlocking {
        OpenPgpCardPrompt(activity, R.string.git_signing_passphrase_title, dispatcherProvider)
          .askSecret(
            titleRes = R.string.git_signing_passphrase_title,
            hintRes = R.string.ssh_keygen_passphrase,
            identityLabel = identityLabel(key),
          )
      }
        ?.secret ?: throw CanceledException(activity.getString(R.string.dialog_cancel))
    try {
      val decryptor =
        BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(passphrase)
      val privateKey = secretKey.extractPrivateKey(decryptor)
      return buildDetachedSignature(
        secretKey.publicKey,
        BcPGPContentSignerBuilder(secretKey.publicKey.algorithm, HashAlgorithmTags.SHA256),
        privateKey,
        payload,
      )
    } finally {
      passphrase.wipe()
    }
  }

  /**
   * Signs [payload] with the OpenPGP smartcard associated with [primaryKeyId].
   *
   * Returns `null` when the user explicitly opts to proceed with an unsigned commit, in which case
   * the caller must not attach a signature to the commit.
   */
  private fun signWithSmartcard(
    key: PGPKey,
    primaryKeyId: PGPIdentifier.KeyId,
    payload: ByteArray,
  ): ByteArray? {
    // Collapse (and unfocus) the entry form's keyboard up front so it can't linger behind the
    // signing dialogs or resurface over the status/error UI when they close.
    activity.runOnUiThread { activity.hideKeyboard() }
    when (confirmSmartcardSigning()) {
      SigningChoice.CANCEL -> throw CanceledException(activity.getString(R.string.dialog_cancel))
      SigningChoice.SKIP -> return null
      SigningChoice.SIGN -> {}
    }
    // The shared prompt keeps reader mode enabled for the whole operation, shows the reused
    // present/hold-card dialog, and runs the card exchange on the card's own thread via
    // OpenPgpCardPrompt.runWithPin. Any smartcard failure is reported to the user in a dialog
    // (never a snackbar) by the outer catch below.
    val prompt = OpenPgpCardPrompt(activity, R.string.git_signing_card_title, dispatcherProvider)
    var reader: CardReader? = null
    // Reader mode is released via the removal watcher (which disables it once the card leaves) on
    // every terminal outcome — success or failure — so the finally only closes it if we exit
    // unexpectedly.
    var readerHandedOff = false
    try {
      // Namespaced so the signing PIN cache is kept separate from the decryption PIN cache.
      val cacheKey = "sign:$primaryKeyId"
      val cardFingerprints = smartcardStore.getFingerprints(primaryKeyId)
      val publicKey = findCardSigningKey(key, cardFingerprints)
      val activeReader =
        runBlocking { prompt.createReader() }
          ?: throw IOException(activity.getString(R.string.openpgp_nfc_unavailable))
      reader = activeReader
      val outcome = runBlocking {
        prompt.runWithPin(
          reader = activeReader,
          cacheKey = cacheKey,
          pinTitleRes = R.string.git_signing_card_pin_title,
          pinHintRes = R.string.openpgp_card_pin_hint,
          identityLabel = identityLabel(key),
          pinMode = OpenPgpCardPrompt.PinMode.SIGNATURE,
          presentMessage = activity.getString(R.string.git_signing_tap_card),
          commFailedMessage = activity.getString(R.string.openpgp_nfc_card_comm_failed),
        ) { card, currentPin ->
          // The whole card exchange (applet select -> verify -> sign) runs on a single thread
          // with no hop, so a genuine wrong PIN reliably comes back as a card status word (e.g.
          // 63 Cx) rather than a transceive error caused by racing the NFC presence check.
          card.verifySignaturePin(currentPin)
          val privateKey = PGPPrivateKey(publicKey.keyID, publicKey.publicKeyPacket, null)
          buildDetachedSignature(
            publicKey,
            CardContentSignerBuilder(publicKey, card),
            privateKey,
            payload,
          )
        }
      }
      when (outcome) {
        is OpenPgpCardPrompt.CardOutcome.Success -> {
          // Keep reader mode on until the card is physically lifted, so the platform never
          // dispatches its NDEF URL while it is still present (e.g. while the success dialog is
          // up).
          readerHandedOff = true
          prompt.releaseReaderWhenCardRemoved(outcome.card, activeReader)
          return outcome.value
        }
        OpenPgpCardPrompt.CardOutcome.Cancelled -> {
          readerHandedOff = true
          prompt.releaseReaderWhenCardRemoved(null, activeReader)
          throw CanceledException(activity.getString(R.string.dialog_cancel))
        }
        is OpenPgpCardPrompt.CardOutcome.Blocked -> {
          // Hold reader mode until the card is lifted, then abort - the outer catch reports it.
          readerHandedOff = true
          prompt.releaseReaderWhenCardRemoved(outcome.card, activeReader)
          throw PGPException(activity.getString(R.string.openpgp_card_pin_blocked))
        }
        is OpenPgpCardPrompt.CardOutcome.Failed -> {
          readerHandedOff = true
          prompt.releaseReaderWhenCardRemoved(outcome.card, activeReader)
          throw outcome.error
        }
      }
    } catch (e: Throwable) {
      // Cancellation and already-reported failures propagate untouched; every other smartcard
      // failure is reported in a dialog (never a snackbar), then marked handled.
      if (e is CanceledException || OpenPgpCardPrompt.isHandled(e)) throw e
      runBlocking {
        prompt.dismissDialog()
        prompt.showError(
          R.string.error,
          e.message ?: activity.getString(R.string.password_decryption_unknown_error),
        )
      }
      throw SmartcardOperationHandledException(e.message)
    } finally {
      runBlocking { prompt.dismissDialog() }
      if (!readerHandedOff && reader != null) prompt.releaseReaderWhenCardRemoved(null, reader)
    }
  }

  private enum class SigningChoice {
    SIGN,
    SKIP,
    CANCEL,
  }

  private fun confirmSmartcardSigning(): SigningChoice {
    if (activity.isFinishing || activity.isDestroyed) return SigningChoice.CANCEL
    val choice = AtomicReference(SigningChoice.CANCEL)
    val latch = CountDownLatch(1)
    val error = AtomicReference<Throwable?>(null)
    activity.runOnUiThread {
      try {
        val dialog =
          MaterialAlertDialogBuilder(activity)
            .setTitle(R.string.git_signing_card_title)
            .setMessage(R.string.git_signing_confirm_message)
            .setPositiveButton(R.string.git_signing_confirm_positive) { _, _ ->
              choice.set(SigningChoice.SIGN)
              latch.countDown()
            }
            .setNegativeButton(R.string.git_signing_confirm_unsigned) { _, _ ->
              choice.set(SigningChoice.SKIP)
              latch.countDown()
            }
            .setOnCancelListener { latch.countDown() }
            .setCancelable(true)
            .show()
        dialog.setCanceledOnTouchOutside(true)
        // Keep "Commit without signing" available but visually understated so it does not
        // invite accidental taps over the primary "Sign" action.
        dialog.getButton(AlertDialog.BUTTON_NEGATIVE)?.let(::deemphasizeButton)
      } catch (t: Throwable) {
        error.set(t)
        latch.countDown()
      }
    }
    latch.await()
    error.get()?.let { logcat { it.asLog() } }
    return choice.get()
  }

  private fun deemphasizeButton(button: Button) {
    button.setTextColor(MaterialColors.getColor(button, materialR.attr.colorOnSurfaceVariant))
  }

  /**
   * Short label naming the signing key, so the passphrase/PIN prompt shows which key it unlocks.
   */
  private fun identityLabel(key: PGPKey): String? =
    KeyUtils.tryGetUserId(key)?.toString()?.takeIf { it.isNotBlank() && it != "null" }
      ?: KeyUtils.tryGetKeyId(key)?.toString()

  private fun findSecretSigningKey(key: PGPKey): PGPSecretKey {
    val rings =
      PGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(key.contents.inputStream()),
        JcaKeyFingerprintCalculator(),
      )
    return rings.keyRings
      .asSequence()
      .flatMap { it.secretKeys.asSequence() }
      .firstOrNull { it.isSigningKey }
      ?: throw PGPException("No signing-capable OpenPGP secret key found")
  }

  private fun publicKeys(key: PGPKey): Sequence<PGPPublicKey> = runCatching {
    PGPSecretKeyRingCollection(
        PGPUtil.getDecoderStream(key.contents.inputStream()),
        JcaKeyFingerprintCalculator(),
      )
      .keyRings
      .asSequence()
      .flatMap { it.secretKeys.asSequence() }
      .map { it.publicKey }
  }
    .getOrElse {
      PGPPublicKeyRingCollection(
          PGPUtil.getDecoderStream(key.contents.inputStream()),
          JcaKeyFingerprintCalculator(),
        )
        .keyRings
        .asSequence()
        .flatMap { it.publicKeys.asSequence() }
    }

  private fun findCardSigningKey(key: PGPKey, cardFingerprints: List<ByteArray>): PGPPublicKey {
    return publicKeys(key).firstOrNull { publicKey ->
      publicKey.algorithm in RSA_SIGNING_ALGORITHMS &&
        cardFingerprints.any { it.contentEquals(publicKey.fingerprint) }
    } ?: throw PGPException("No RSA signing key matching this OpenPGP card was found")
  }

  private fun buildDetachedSignature(
    publicKey: PGPPublicKey,
    signerBuilder: PGPContentSignerBuilder,
    privateKey: PGPPrivateKey,
    payload: ByteArray,
  ): ByteArray {
    val generator = PGPSignatureGenerator(signerBuilder, publicKey)
    generator.init(PGPSignature.BINARY_DOCUMENT, privateKey)
    generator.update(payload)
    val out = ByteArrayOutputStream()
    ArmoredOutputStream(out).use { armored -> generator.generate().encode(armored) }
    return out.toByteArray()
  }

  // The PIN is verified explicitly (see signWithSmartcard) before this builder runs, so it only has
  // to compute the signature.
  private class CardContentSignerBuilder(
    private val publicKey: PGPPublicKey,
    private val card: OpenPgpNfcCard,
  ) : PGPContentSignerBuilder {

    override fun build(signatureType: Int, privateKey: PGPPrivateKey): PGPContentSigner {
      if (publicKey.algorithm !in RSA_SIGNING_ALGORITHMS) {
        throw PGPException("NFC OpenPGP commit signing currently supports RSA card keys only")
      }
      val digestCalculator = BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256)
      return object : PGPContentSigner {
        override fun getOutputStream(): OutputStream = digestCalculator.outputStream

        override fun getSignature(): ByteArray {
          val digestInfo =
            DigestInfo(
                AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE),
                digestCalculator.digest,
              )
              .encoded
          return card.computeDigitalSignature(
            digestInfo,
            expectedLength = (publicKey.bitStrength + 7) / 8,
          )
        }

        override fun getDigest(): ByteArray = digestCalculator.digest

        override fun getType(): Int = signatureType

        override fun getHashAlgorithm(): Int = HashAlgorithmTags.SHA256

        override fun getKeyAlgorithm(): Int = publicKey.algorithm

        override fun getKeyID(): Long = publicKey.keyID
      }
    }
  }

  companion object {
    // RSA_SIGN is a legacy OpenPGP algorithm id that BouncyCastle deprecates in favour of
    // RSA_GENERAL, but keys carrying the old tag still exist and must be recognized here.
    @Suppress("DEPRECATION")
    private val RSA_SIGNING_ALGORITHMS =
      setOf(PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_SIGN)
  }
}
