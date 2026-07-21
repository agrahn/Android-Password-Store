/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.crypto

import android.text.InputType
import android.view.View
import android.view.WindowManager
import androidx.annotation.StringRes
import androidx.appcompat.app.AlertDialog
import androidx.core.content.edit
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.databinding.DialogPasswordEntryBinding
import app.passwordstore.ui.crypto.BasePGPActivity
import app.passwordstore.util.coroutines.DispatcherProvider
import app.passwordstore.util.extensions.hideKeyboard
import app.passwordstore.util.extensions.sharedPrefs
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.runCatching
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import java.io.IOException
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext
import logcat.asLog
import logcat.logcat

/**
 * Drives the shared OpenPGP smartcard UX for a single card operation (commit signing, decryption,
 * …). It keeps NFC reader mode enabled for the whole operation via a single [CardReader], shows a
 * reusable "present card" / "keep the card on the phone" dialog, runs the card operation on the
 * card's own thread right after applet selection (so it can't race the NFC presence check), and —
 * on success — keeps reader mode on until the card is physically removed so the platform never
 * dispatches the card's NDEF URL.
 *
 * All UI-touching members are `suspend` so callers on the main thread (e.g. decryption) don't block
 * it; callers running off the main thread (e.g. commit signing) can wrap them in `runBlocking`.
 */
class OpenPgpCardPrompt(
  private val activity: FragmentActivity,
  @StringRes private val titleRes: Int,
  private val dispatcherProvider: DispatcherProvider,
) {

  private val cardDialog = AtomicReference<AlertDialog?>(null)
  private val cardDialogCancel = AtomicReference<CompletableDeferred<Unit>?>(null)

  /** Outcome of a single [attempt]. */
  sealed interface Attempt<out T> {
    /** [card] is left open so reader mode can be released once it is physically removed. */
    class Success<T>(val value: T, val card: OpenPgpNfcCard) : Attempt<T>

    data object Cancelled : Attempt<Nothing>

    /**
     * [card] is the connected card when the failure happened after connecting (else null); it is
     * left open so the caller can hold reader mode until the card is physically removed (terminal
     * failure) or close it to allow the user to present it again (retry).
     */
    class Error(val error: Throwable, val card: OpenPgpNfcCard?) : Attempt<Nothing>
  }

  /** Enables reader mode for the operation. Returns `null` when NFC is unavailable or disabled. */
  suspend fun createReader(): CardReader? =
    withContext(dispatcherProvider.main()) { CardReader.create(activity) }

  /**
   * Shows (or, on a retry, reuses and re-labels with [message]) the card dialog, awaits a tap on
   * the already-open [reader], and runs [block] on the connected card on the same thread,
   * immediately after applet selection. The dialog stays on screen for the whole exchange and for
   * the next attempt; the caller dismisses it via [dismissDialog] when the operation ends.
   */
  suspend fun <T> attempt(
    reader: CardReader,
    message: String,
    block: (OpenPgpNfcCard) -> T,
  ): Attempt<T> = coroutineScope {
    val cancel = CompletableDeferred<Unit>()
    cardDialogCancel.set(cancel)
    withContext(dispatcherProvider.main()) { showOrUpdateDialog(message) }
    val attemptJob =
      async(dispatcherProvider.io()) {
        val card = reader.awaitCard {
          activity.runOnUiThread {
            cardDialog.get()?.let { dialog ->
              dialog.setTitle(R.string.openpgp_nfc_hold_card_title)
              dialog.setMessage(activity.getString(R.string.openpgp_nfc_hold_card))
            }
          }
        }
        try {
          Attempt.Success(block(card), card)
        } catch (e: Throwable) {
          if (e is CancellationException) {
            runCatching { card.close() }
            throw e
          }
          // Leave the card open; the caller closes it (retry) or holds reader mode until it is
          // removed (terminal failure).
          Attempt.Error(e, card)
        }
      }
    try {
      select<Attempt<T>> {
        attemptJob.onAwait { it }
        cancel.onAwait {
          attemptJob.cancel()
          Attempt.Cancelled
        }
      }
    } catch (e: Throwable) {
      // The card wait itself failed (no card connected).
      Attempt.Error(e, null)
    }
  }

  /** Creates the card dialog, or just re-labels it if it is already showing. Main thread. */
  private fun showOrUpdateDialog(message: String) {
    // Collapse the soft keyboard left over from PIN entry so it doesn't cover the card prompt or
    // the
    // status bar, and keep the card dialog from resurrecting it.
    activity.hideKeyboard()
    val existing = cardDialog.get()
    if (existing != null && existing.isShowing) {
      existing.setTitle(titleRes)
      existing.setMessage(message)
      return
    }
    val dialog =
      MaterialAlertDialogBuilder(activity)
        .setTitle(titleRes)
        .setMessage(message)
        .setNegativeButton(R.string.dialog_cancel) { _, _ ->
          cardDialogCancel.get()?.complete(Unit)
        }
        .setOnCancelListener { cardDialogCancel.get()?.complete(Unit) }
        .setCancelable(true)
        .show()
    dialog.setCanceledOnTouchOutside(true)
    dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN)
    cardDialog.set(dialog)
  }

  suspend fun dismissDialog() {
    val dialog = cardDialog.getAndSet(null) ?: return
    withContext(dispatcherProvider.main()) { dialog.dismiss() }
  }

  class SecretEntry(val secret: CharArray, val cache: Boolean)

  /**
   * Prompts the user for a card PIN (or passphrase). When [showCacheOption] is true the dialog
   * offers a "keep until screen-off" checkbox; the caller decides whether to actually cache via
   * [storeCachedPin]. [errorMessage] is reported inline on the field (e.g. "Wrong PIN, N tries
   * left"). When [minLength] is > 0 the confirm button stays disabled until at least that many
   * characters are entered (the OpenPGP card spec mandates a 6-character minimum PIN). Returns
   * `null` if the user cancels.
   */
  suspend fun askSecret(
    @StringRes titleRes: Int,
    @StringRes hintRes: Int,
    showCacheOption: Boolean = false,
    errorMessage: String? = null,
    minLength: Int = 0,
    identityLabel: String? = null,
  ): SecretEntry? {
    if (activity.isFinishing || activity.isDestroyed) return null
    val showCache = showCacheOption && AESEncryption.isHardwareBacked()
    val cacheDefault =
      showCache && activity.sharedPrefs.getBoolean(PreferenceKeys.CACHE_PASSPHRASE, false)
    val result = CompletableDeferred<SecretEntry?>()
    withContext(dispatcherProvider.main()) {
      try {
        val binding = DialogPasswordEntryBinding.inflate(activity.layoutInflater)
        binding.passwordField.setHint(hintRes)
        // Tell the user which key/card this PIN unlocks.
        identityLabel?.let {
          binding.userIdList.text = it
          binding.userIdList.visibility = View.VISIBLE
        }
        binding.passwordEditText.inputType =
          InputType.TYPE_CLASS_TEXT or
            InputType.TYPE_TEXT_VARIATION_PASSWORD or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        if (showCache) {
          binding.cacheEnabled.visibility = View.VISIBLE
          binding.cacheEnabled.setText(R.string.cache_openpgp_card_pin_until_screen_off)
          binding.cacheEnabled.isChecked = cacheDefault
        }
        val dialog =
          MaterialAlertDialogBuilder(activity)
            .setTitle(titleRes)
            .setView(binding.root)
            .setPositiveButton(android.R.string.ok) { _, _ ->
              val text = binding.passwordEditText.text
              val secret =
                text?.let { CharArray(it.length) { index -> it[index] } } ?: charArrayOf()
              text?.clear()
              result.complete(SecretEntry(secret, showCache && binding.cacheEnabled.isChecked))
            }
            .setNegativeButton(R.string.dialog_cancel) { _, _ -> result.complete(null) }
            .setOnCancelListener { result.complete(null) }
            .show()
        // The error and the min-length hint share the caption area below the field, and the error
        // (e.g. "Wrong PIN, N left") takes priority; only fall back to the hint when there is none.
        when {
          errorMessage != null -> binding.passwordField.error = errorMessage
          minLength > 0 ->
            binding.passwordField.helperText =
              activity.resources.getQuantityString(
                R.plurals.openpgp_card_pin_min_length,
                minLength,
                minLength,
              )
        }
        if (minLength > 0) {
          // Enforce the minimum PIN length by keeping the confirm button disabled until enough
          // characters are entered.
          val okButton = dialog.getButton(AlertDialog.BUTTON_POSITIVE)
          val updateOkEnabled = {
            okButton.isEnabled = (binding.passwordEditText.text?.length ?: 0) >= minLength
          }
          updateOkEnabled()
          binding.passwordEditText.doAfterTextChanged { updateOkEnabled() }
        }
        dialog.window?.setFlags(
          WindowManager.LayoutParams.FLAG_SECURE,
          WindowManager.LayoutParams.FLAG_SECURE,
        )
      } catch (t: Throwable) {
        logcat { t.asLog() }
        result.complete(null)
      }
    }
    return result.await()
  }

  /** Reads and decrypts a screen-off-cached PIN for [cacheKey], or null if none. */
  fun readCachedPin(cacheKey: String): CharArray? {
    val encrypted = BasePGPActivity.cachedPassphrases[cacheKey] ?: return null
    return AESEncryption.decrypt(encrypted)
  }

  fun clearCachedPin(cacheKey: String) {
    BasePGPActivity.cachedPassphrases[cacheKey]?.wipe()
    BasePGPActivity.cachedPassphrases.remove(cacheKey)
  }

  /** Caches [pin] (AES-encrypted, until screen-off) under [cacheKey] when [cache] is set. */
  fun storeCachedPin(cacheKey: String, pin: CharArray, cache: Boolean) {
    runCatching {
        val hardwareBacked = AESEncryption.isHardwareBacked()
        val encryptedPin = if (cache) AESEncryption.encrypt(pin) else null
        if (hardwareBacked && cache && encryptedPin != null) {
          BasePGPActivity.cachedPassphrases[cacheKey]?.wipe()
          BasePGPActivity.cachedPassphrases[cacheKey] = encryptedPin
        } else {
          clearCachedPin(cacheKey)
        }
        activity.sharedPrefs.edit {
          putBoolean(
            PreferenceKeys.CACHE_PASSPHRASE,
            hardwareBacked && cache && encryptedPin != null,
          )
        }
      }
      .onErr { e -> logcat { e.asLog() } }
  }

  /** Shows a simple informational dialog (used for terminal card errors, e.g. a blocked PIN). */
  suspend fun showError(@StringRes titleRes: Int, message: String) {
    withContext(dispatcherProvider.main()) {
      MaterialAlertDialogBuilder(activity)
        .setTitle(titleRes)
        .setMessage(message)
        .setPositiveButton(android.R.string.ok, null)
        .setCancelable(true)
        .show()
    }
  }

  /**
   * Keeps reader mode enabled until [card] is lifted (or a timeout elapses), then disables it, so
   * the platform never dispatches the still-present card's NDEF URL after an operation ends —
   * whether it succeeded or failed — for instance while a result dialog is still on screen. When
   * [card] is null (e.g. the card was never connected), reader mode is disabled right away. Runs
   * off the calling thread on the activity scope so it does not delay the operation.
   */
  fun releaseReaderWhenCardRemoved(card: OpenPgpNfcCard?, reader: CardReader) {
    activity.lifecycleScope.launch {
      if (card != null) {
        withContext(dispatcherProvider.io()) {
          try {
            val deadline = System.currentTimeMillis() + READER_MODE_RELEASE_TIMEOUT_MS
            // Actively probe the card; two consecutive misses mean it has left the field (a single
            // miss can be a transient transceive glitch while it is still present). Only pace the
            // "still present" case with the interval so removal is detected in ~2 probe timeouts.
            var consecutiveMisses = 0
            while (consecutiveMisses < 2 && System.currentTimeMillis() < deadline) {
              if (card.isPresent()) {
                consecutiveMisses = 0
                delay(READER_MODE_POLL_INTERVAL_MS)
              } else {
                consecutiveMisses++
              }
            }
          } finally {
            runCatching { card.close() }
          }
        }
      }
      reader.close()
    }
  }

  /**
   * Shows a modal "remove your card" dialog and **suspends** until [card] is physically lifted (or a
   * timeout elapses), then dismisses the dialog and releases [reader].
   *
   * Unlike [releaseReaderWhenCardRemoved] this blocks the caller. NFC reader mode is only active
   * while the hosting activity is resumed, so when an operation would otherwise let its activity
   * pause/finish right after the card exchange (e.g. an SSH authentication during a git push, whose
   * activity moves on once auth succeeds), holding the caller here keeps the activity foreground —
   * and the card in reader mode — until the user removes it, so the platform never dispatches the
   * still-present card's NDEF URL.
   */
  suspend fun awaitCardRemoval(card: OpenPgpNfcCard, reader: CardReader) {
    val dialog =
      withContext(dispatcherProvider.main()) {
        if (activity.isFinishing || activity.isDestroyed) return@withContext null
        MaterialAlertDialogBuilder(activity)
          .setTitle(R.string.openpgp_nfc_remove_card_title)
          .setMessage(R.string.openpgp_nfc_remove_card_message)
          .setCancelable(false)
          .show()
      }
    try {
      withContext(dispatcherProvider.io()) {
        val deadline = System.currentTimeMillis() + READER_MODE_REMOVAL_TIMEOUT_MS
        var consecutiveMisses = 0
        while (consecutiveMisses < 2 && System.currentTimeMillis() < deadline) {
          if (card.isPresent()) {
            consecutiveMisses = 0
            delay(READER_MODE_POLL_INTERVAL_MS)
          } else {
            consecutiveMisses++
          }
        }
      }
    } finally {
      runCatching { card.close() }
      withContext(dispatcherProvider.main()) { runCatching { dialog?.dismiss() } }
      reader.close()
    }
  }

  companion object {
    /** The minimum PW1 (user/signing) PIN length mandated by the OpenPGP Card specification. */
    const val MIN_PIN_LENGTH = 6

    private const val READER_MODE_RELEASE_TIMEOUT_MS = 30_000L
    // Longer cap for the interactive "remove your card" wait, which depends on the user reacting.
    private const val READER_MODE_REMOVAL_TIMEOUT_MS = 60_000L
    private const val READER_MODE_POLL_INTERVAL_MS = 300L
    private val PIN_FAILURE_REGEX = Regex("""63 c[0-9a-f]""", RegexOption.IGNORE_CASE)

    /**
     * Whether [error] is a smartcard PIN rejection, recognised whether it arrives as a structured
     * [OpenPgpCardStatusException] or only in a wrapped message.
     */
    fun isSmartcardPinFailure(error: Throwable?): Boolean {
      var cause = error
      while (cause != null) {
        // A PIN the card rejected for its length/format is also a (recoverable) PIN problem.
        if (cause is SmartcardPinFormatException) return true
        if (cause is OpenPgpCardStatusException && cause.isAuthenticationFailure) return true
        val message = cause.message.orEmpty()
        if (message.contains("69 82", ignoreCase = true)) return true
        if (message.contains("69 83", ignoreCase = true)) return true
        if (PIN_FAILURE_REGEX.containsMatchIn(message)) return true
        cause = cause.cause
      }
      return false
    }

    /** The card-reported number of PIN attempts still available, or null if the card didn't say. */
    fun smartcardPinRetriesRemaining(error: Throwable?): Int? {
      var cause = error
      while (cause != null) {
        if (cause is OpenPgpCardStatusException) {
          cause.retriesRemaining?.let {
            return it
          }
        }
        cause = cause.cause
      }
      return null
    }

    /**
     * Whether [error] is a transient NFC/card *transport* problem (tag lost mid-exchange, a
     * malformed/short response, a transceive glitch), for which the user should simply present the
     * card again.
     *
     * Crucially, an [OpenPgpCardStatusException] is *not* retryable even though it extends
     * [IOException]: the card answered with a status word, so it was read just fine — that's a card
     * error to report (or, if it's a PIN rejection, to re-prompt for), never a "couldn't read the
     * card". Only a plain transport [IOException] (no card status word anywhere in the chain)
     * counts.
     */
    fun isRetryableCardError(error: Throwable?): Boolean {
      var cause = error
      var transportFailure = false
      while (cause != null) {
        // The card responded — whatever the status word, this was not a failed read.
        if (cause is OpenPgpCardStatusException) return false
        if (cause is IOException) transportFailure = true
        cause = cause.cause
      }
      return transportFailure
    }

    /** Whether [error] (or a cause) is an already-reported smartcard failure (see below). */
    fun isHandled(error: Throwable?): Boolean {
      var cause = error
      while (cause != null) {
        if (cause is SmartcardOperationHandledException) return true
        cause = cause.cause
      }
      return false
    }
  }
}

/**
 * Thrown when a smartcard operation (e.g. commit signing) has already reported its failure to the
 * user via a dialog, so callers should not additionally surface it (e.g. as a snackbar).
 */
class SmartcardOperationHandledException(message: String? = null) : Exception(message)
