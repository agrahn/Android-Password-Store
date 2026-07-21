/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.crypto

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import app.passwordstore.R
import com.github.michaelbull.result.get
import com.github.michaelbull.result.getOr
import com.github.michaelbull.result.runCatching
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.suspendCancellableCoroutine
import logcat.LogPriority.WARN
import logcat.asLog
import logcat.logcat

class OpenPgpNfcCard(
  private val isoDep: IsoDep,
  private val onClose: () -> Unit = {},
) : AutoCloseable {

  fun selectOpenPgpApplet() {
    transceive(SELECT_OPENPGP)
  }

  fun verifyUserPin(pin: CharArray) {
    verifyPin(pin, reference = 0x82)
  }

  fun verifySignaturePin(pin: CharArray) {
    verifyPin(pin, reference = 0x81)
  }

  /** Remaining PW1 verification attempts as seen through the decryption (0x82) slot. */
  fun readUserPinRetries(): Int? = readPinRetries(reference = 0x82)

  /** Remaining PW1 verification attempts as seen through the signature (0x81) slot. */
  fun readSignaturePinRetries(): Int? = readPinRetries(reference = 0x81)

  /**
   * Asks the card how many verification attempts are left for the password [reference], *without*
   * consuming one. Per the OpenPGP Card spec a VERIFY with an empty data field (a Case-1 APDU) is a
   * pure status check: the card answers `63 Cx` (x tries left), `69 83` (blocked → 0), or `90 00`
   * (already verified this session). Returns null when the card doesn't report a usable count.
   */
  private fun readPinRetries(reference: Int): Int? =
    try {
      transceive(byteArrayOf(0x00, 0x20, 0x00, reference.toByte()))
      null // 90 00: already verified this session; no counter reported.
    } catch (e: OpenPgpCardStatusException) {
      e.retriesRemaining
    } catch (e: IOException) {
      null // A transport problem while probing shouldn't mask the original failure.
    }

  private fun verifyPin(pin: CharArray, reference: Int) {
    val pinBytes = pin.concatToString().toByteArray(Charsets.UTF_8)
    try {
      transceive(
        byteArrayOf(0x00, 0x20, 0x00, reference.toByte(), pinBytes.size.toByte()) + pinBytes
      )
    } catch (e: OpenPgpCardStatusException) {
      // A VERIFY carries only the PIN in its data field, so a "wrong data / wrong length" rejection
      // (67 xx / 6A 80) means the PIN didn't fit the card's PW length bounds — surface it as a
      // recoverable, re-promptable error rather than the raw status word.
      if (e.isDataFieldRejection) throw SmartcardPinFormatException(e.sw1, e.sw2)
      throw e
    } finally {
      pinBytes.fill(0)
    }
  }

  fun decipher(ciphertext: ByteArray): ByteArray {
    val payload = byteArrayOf(0x00) + ciphertext
    return transceiveData(0x2A, 0x80, 0x86, payload, expectedLength = ciphertext.size)
  }

  fun computeDigitalSignature(digestInfo: ByteArray, expectedLength: Int): ByteArray {
    return transceiveData(0x2A, 0x9E, 0x9A, digestInfo, expectedLength)
  }

  /**
   * Runs INTERNAL AUTHENTICATE (INS 0x88) with the card's Authentication key over [input] and
   * returns the raw signature. Unlike PSO:CDS (used for OpenPGP signatures), this uses the
   * Authentication key slot and requires PW1 verified in mode 0x82 (see [verifyUserPin]). Used for
   * SSH public-key authentication.
   */
  fun internalAuthenticate(input: ByteArray): ByteArray {
    // Le = 0 → request up to 256 bytes; longer responses (e.g. RSA) are pulled in via 61xx chaining.
    return transceiveData(0x88, 0x00, 0x00, input, expectedLength = 0)
  }

  fun readCardInfo(): OpenPgpCardInfo {
    val applicationData = transceive(GET_APPLICATION_RELATED_DATA)
    val fingerprints = findTlv(applicationData, 0xC5)?.let(::parseFingerprints).orEmpty()
    val url = runCatching { transceive(GET_URL).toString(Charsets.UTF_8).trim() }.get()
    return OpenPgpCardInfo(fingerprints = fingerprints, url = url?.takeIf { it.isNotBlank() })
  }

  /**
   * Whether the card is still within the reader field. Actively probes with a benign read command
   * rather than trusting [IsoDep.isConnected], whose cached presence state can stay `true` after
   * the card has physically left the field. Uses a short transceive timeout so a removed card is
   * reported quickly instead of blocking for the (long) signing timeout before throwing.
   */
  fun isPresent(): Boolean =
    runCatching {
        isoDep.timeout = PRESENCE_PROBE_TIMEOUT_MS
        isoDep.transceive(GET_APPLICATION_RELATED_DATA)
        true
      }
      .getOr(false)

  override fun close() {
    runCatching { isoDep.close() }
    onClose()
  }

  private fun transceive(command: ByteArray): ByteArray {
    val response = isoDep.transceive(command)
    if (response.size < 2) throw IOException("Malformed NFC response")
    val sw1 = response[response.size - 2].toInt() and 0xff
    val sw2 = response[response.size - 1].toInt() and 0xff
    val data = response.copyOf(response.size - 2)
    if (sw1 == 0x90 && sw2 == 0x00) return data
    if (sw1 == 0x61)
      return data + transceive(byteArrayOf(0x00, 0xC0.toByte(), 0x00, 0x00, sw2.toByte()))
    if (sw1 == 0x6C) return transceive(command.copyOf(command.size - 1) + sw2.toByte())
    throw OpenPgpCardStatusException(sw1, sw2)
  }

  private fun transceiveData(
    ins: Int,
    p1: Int,
    p2: Int,
    payload: ByteArray,
    expectedLength: Int,
  ): ByteArray {
    return if (payload.size <= MAX_APDU_NC) {
      transceiveShort(ins, p1, p2, payload, expectedLength)
    } else {
      transceiveChained(ins, p1, p2, payload, expectedLength)
    }
  }

  private fun transceiveShort(
    ins: Int,
    p1: Int,
    p2: Int,
    payload: ByteArray,
    expectedLength: Int,
  ): ByteArray {
    val command =
      byteArrayOf(0x00, ins.toByte(), p1.toByte(), p2.toByte(), payload.size.toByte()) +
        payload +
        encodeShortLe(expectedLength)
    return transceive(command)
  }

  private fun transceiveChained(
    ins: Int,
    p1: Int,
    p2: Int,
    payload: ByteArray,
    expectedLength: Int,
  ): ByteArray {
    val chunkSize = (isoDep.maxTransceiveLength - 6).coerceIn(1, MAX_APDU_NC)
    var offset = 0
    var response = byteArrayOf()
    while (offset < payload.size) {
      val end = minOf(offset + chunkSize, payload.size)
      val chunk = payload.copyOfRange(offset, end)
      val isLast = end == payload.size
      val cla = if (isLast) 0x00 else 0x10
      val command =
        byteArrayOf(cla.toByte(), ins.toByte(), p1.toByte(), p2.toByte(), chunk.size.toByte()) +
          chunk +
          if (isLast) encodeShortLe(expectedLength) else byteArrayOf()
      response = transceive(command)
      offset = end
    }
    return response
  }

  @Suppress("unused")
  private fun transceiveExtended(ins: Int, p1: Int, p2: Int, payload: ByteArray): ByteArray {
    val lc = payload.size
    val command =
      byteArrayOf(
        0x00,
        ins.toByte(),
        p1.toByte(),
        p2.toByte(),
        0x00,
        ((lc ushr 8) and 0xff).toByte(),
        (lc and 0xff).toByte(),
      ) + payload + byteArrayOf(0x00, 0x00)
    return transceive(command)
  }

  companion object {
    private const val MAX_APDU_NC = 254

    // Short transceive timeout used only for presence probing, so a removed card fails fast instead
    // of waiting out the multi-second signing timeout.
    private const val PRESENCE_PROBE_TIMEOUT_MS = 200

    private fun encodeShortLe(expectedLength: Int): ByteArray =
      byteArrayOf(if (expectedLength >= 256) 0x00 else expectedLength.toByte())

    private val OPENPGP_AID = byteArrayOf(0xD2.toByte(), 0x76, 0x00, 0x01, 0x24, 0x01)
    private val SELECT_OPENPGP =
      byteArrayOf(0x00, 0xA4.toByte(), 0x04, 0x00, OPENPGP_AID.size.toByte()) +
        OPENPGP_AID +
        byteArrayOf(0x00)
    private val GET_APPLICATION_RELATED_DATA = byteArrayOf(0x00, 0xCA.toByte(), 0x00, 0x6E, 0x00)
    private val GET_URL = byteArrayOf(0x00, 0xCA.toByte(), 0x5F, 0x50, 0x00)

    private fun parseFingerprints(value: ByteArray): List<ByteArray> =
      value
        .asSequence()
        .chunked(20)
        .map { it.toByteArray() }
        .filter { fingerprint -> fingerprint.any { it != 0.toByte() } }
        .toList()

    private fun findTlv(data: ByteArray, expectedTag: Int): ByteArray? {
      var offset = 0
      while (offset < data.size) {
        val (tag, tagEnd) = readTag(data, offset)
        val (length, valueOffset) = readLength(data, tagEnd)
        val valueEnd = valueOffset + length
        if (valueEnd > data.size) return null
        val value = data.copyOfRange(valueOffset, valueEnd)
        if (tag == expectedTag) return value
        if (tag == 0x6E || tag == 0x73)
          findTlv(value, expectedTag)?.let {
            return it
          }
        offset = valueEnd
      }
      return null
    }

    private fun readTag(data: ByteArray, offset: Int): Pair<Int, Int> {
      var cursor = offset
      var tag = data[cursor++].toInt() and 0xff
      if (tag and 0x1f == 0x1f) {
        do {
          val next = data[cursor++].toInt() and 0xff
          tag = (tag shl 8) or next
        } while (next and 0x80 == 0x80 && cursor < data.size)
      }
      return tag to cursor
    }

    private fun readLength(data: ByteArray, offset: Int): Pair<Int, Int> {
      var cursor = offset
      val first = data[cursor++].toInt() and 0xff
      if (first and 0x80 == 0) return first to cursor
      val count = first and 0x7f
      var length = 0
      repeat(count) { length = (length shl 8) or (data[cursor++].toInt() and 0xff) }
      return length to cursor
    }

    fun disableReaderMode(activity: Activity) {
      val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return
      try {
        adapter.disableReaderMode(activity)
      } catch (e: IllegalStateException) {
        // NfcAdapter.disableReaderMode throws "activity is already destroyed" when it runs as an
        // onDestroy() cleanup (the platform has already torn down the activity's NFC state, so
        // reader mode is gone anyway). Swallow it so finishing the activity never crashes.
        logcat(WARN) { e.asLog() }
      }
    }

    suspend fun waitForCard(
      activity: Activity,
      disableReaderModeOnError: Boolean = true,
      disableReaderModeOnClose: Boolean = true,
      onCardDetected: () -> Unit = {},
    ): OpenPgpNfcCard = suspendCancellableCoroutine { continuation ->
      val adapter = NfcAdapter.getDefaultAdapter(activity)
      if (adapter == null || !adapter.isEnabled) {
        continuation.resumeWithException(
          IOException(activity.getString(R.string.openpgp_nfc_unavailable))
        )
        return@suspendCancellableCoroutine
      }
      val completed = AtomicBoolean(false)

      val callback = NfcAdapter.ReaderCallback { tag: Tag ->
        if (!completed.compareAndSet(false, true)) return@ReaderCallback
        try {
          val isoDep =
            IsoDep.get(tag)
              ?: throw IOException(activity.getString(R.string.openpgp_nfc_not_iso_dep))
          activity.runOnUiThread { onCardDetected() }
          isoDep.connect()
          isoDep.timeout = 30_000
          val card =
            OpenPgpNfcCard(isoDep) {
              if (disableReaderModeOnClose) {
                activity.runOnUiThread { disableReaderMode(activity) }
              }
            }
          card.selectOpenPgpApplet()
          if (continuation.isActive) {
            continuation.resume(card)
          } else {
            card.close()
          }
        } catch (e: Throwable) {
          if (disableReaderModeOnError) {
            activity.runOnUiThread { disableReaderMode(activity) }
          }
          if (continuation.isActive) {
            continuation.resumeWithException(e)
          }
        }
      }

      adapter.enableReaderMode(
        activity,
        callback,
        NfcAdapter.FLAG_READER_NFC_A or
          NfcAdapter.FLAG_READER_NFC_B or
          NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or
          NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
        Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 500) },
      )
      continuation.invokeOnCancellation {
        if (completed.compareAndSet(false, true)) disableReaderMode(activity)
      }
    }

    suspend fun waitForCardOrNull(
      activity: Activity,
      cancelSignal: Deferred<Unit>,
      disableReaderModeOnError: Boolean = true,
      disableReaderModeOnClose: Boolean = true,
      onCardDetected: () -> Unit = {},
    ): OpenPgpNfcCard? = coroutineScope {
      val wait = async {
        waitForCard(
          activity,
          disableReaderModeOnError,
          disableReaderModeOnClose,
          onCardDetected,
        )
      }
      try {
        select {
          wait.onAwait { it }
          cancelSignal.onAwait {
            wait.cancel()
            disableReaderMode(activity)
            null
          }
        }
      } finally {
        if (!wait.isCompleted) wait.cancel()
      }
    }

    fun isTransceiveFailure(error: Throwable?): Boolean {
      var cause = error
      while (cause != null) {
        if (cause is IOException && cause.message?.contains("Transceive failed") == true) {
          return true
        }
        cause = cause.cause
      }
      return false
    }
  }
}

open class OpenPgpCardStatusException(val sw1: Int, val sw2: Int) :
  IOException(
    "OpenPGP card returned ${sw1.toString(16).padStart(2, '0')} " +
      sw2.toString(16).padStart(2, '0')
  ) {

  val isAuthenticationFailure: Boolean
    // 69 82: security status not satisfied, 69 83: authentication method blocked,
    // 63 Cx: verification failed with x retries remaining.
    get() = sw1 == 0x69 && (sw2 == 0x82 || sw2 == 0x83) || sw1 == 0x63 && sw2 in 0xC0..0xCF

  /**
   * Whether the card rejected the command *data field* itself — `67 xx` (wrong length) or `6A 80`
   * (incorrect parameters in the data field). For a PIN VERIFY, whose data field is only the PIN,
   * this means the PIN did not fit the card's PW length bounds (too long or too short).
   */
  val isDataFieldRejection: Boolean
    get() = sw1 == 0x67 || (sw1 == 0x6A && sw2 == 0x80)

  /**
   * Number of PIN attempts the card reports as still remaining, or `null` when the status word does
   * not carry that information. `63 Cx` encodes the remaining tries in its low nibble; `69 83`
   * (authentication method blocked) means none are left.
   */
  val retriesRemaining: Int?
    get() =
      when {
        sw1 == 0x63 && sw2 in 0xC0..0xCF -> sw2 and 0x0F
        sw1 == 0x69 && sw2 == 0x83 -> 0
        else -> null
      }
}

/**
 * A PIN VERIFY the card rejected because the PIN did not fit its configured PW length bounds (the
 * OpenPGP Card spec defines a per-card min of 6 and a max in the PW Status Bytes). Some cards (e.g.
 * YubiKey) answer an over-long PIN with `6A 80` rather than a normal `63 Cx` wrong-PIN status. This
 * rejection does **not** decrement the retry counter, so it is recoverable: the user can simply
 * re-enter a PIN of acceptable length.
 */
class SmartcardPinFormatException(sw1: Int, sw2: Int) : OpenPgpCardStatusException(sw1, sw2)

data class OpenPgpCardInfo(val fingerprints: List<ByteArray>, val url: String?)

/**
 * Keeps NFC reader mode enabled for the whole duration of a multi-step card operation (such as
 * commit signing with PIN retries), so the platform never falls back to dispatching the card's NDEF
 * URL between taps. Enable reader mode once via [create], await successive card presentations with
 * [awaitCard], and [close] it exactly once (which disables reader mode) when finished.
 */
class CardReader
private constructor(private val activity: Activity, private val adapter: NfcAdapter) :
  AutoCloseable {

  private val tags = Channel<Tag>(Channel.UNLIMITED)
  private val closed = AtomicBoolean(false)
  private val callback = NfcAdapter.ReaderCallback { tag -> tags.trySend(tag) }

  init {
    adapter.enableReaderMode(
      activity,
      callback,
      NfcAdapter.FLAG_READER_NFC_A or
        NfcAdapter.FLAG_READER_NFC_B or
        NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK or
        NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
      Bundle().apply { putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 500) },
    )
  }

  /**
   * Suspends until an OpenPGP card is presented and its applet selected, transparently skipping
   * past transient tag glitches (a card lifted mid-connect, a stale buffered tag, a non-ISO-DEP
   * tag). [onCardDetected] is invoked once a card has connected. Throws
   * [OpenPgpCardStatusException] only when the card actively rejects the applet selection.
   */
  suspend fun awaitCard(onCardDetected: () -> Unit): OpenPgpNfcCard {
    while (true) {
      val tag = tags.receive()
      val isoDep = IsoDep.get(tag) ?: continue
      try {
        isoDep.connect()
        isoDep.timeout = 30_000
        onCardDetected()
        val card = OpenPgpNfcCard(isoDep)
        card.selectOpenPgpApplet()
        return card
      } catch (e: OpenPgpCardStatusException) {
        runCatching { isoDep.close() }
        throw e
      } catch (e: Throwable) {
        // Tag lost or a transient transport error: wait for the next presentation.
        runCatching { isoDep.close() }
      }
    }
  }

  override fun close() {
    if (closed.compareAndSet(false, true)) {
      tags.close()
      runCatching { adapter.disableReaderMode(activity) }
    }
  }

  companion object {
    fun create(activity: Activity): CardReader? {
      val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return null
      if (!adapter.isEnabled) return null
      return CardReader(activity, adapter)
    }
  }
}
