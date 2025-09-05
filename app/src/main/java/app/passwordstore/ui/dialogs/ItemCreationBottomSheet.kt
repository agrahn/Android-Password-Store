/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.ui.dialogs

import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.ViewTreeObserver
import android.widget.FrameLayout
import androidx.core.os.bundleOf
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updateLayoutParams
import androidx.fragment.app.setFragmentResult
import app.passwordstore.R
import app.passwordstore.ui.passwords.PasswordFragment.Companion.ACTION_FOLDER
import app.passwordstore.ui.passwords.PasswordFragment.Companion.ACTION_KEY
import app.passwordstore.ui.passwords.PasswordFragment.Companion.ACTION_PASSWORD
import app.passwordstore.ui.passwords.PasswordFragment.Companion.ITEM_CREATION_REQUEST_KEY
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.android.material.bottomsheet.BottomSheetDialogFragment

class ItemCreationBottomSheet : BottomSheetDialogFragment() {

  private var behavior: BottomSheetBehavior<FrameLayout>? = null
  private val bottomSheetCallback =
    object : BottomSheetBehavior.BottomSheetCallback() {
      override fun onSlide(bottomSheet: View, slideOffset: Float) {}

      override fun onStateChanged(bottomSheet: View, newState: Int) {
        if (newState == BottomSheetBehavior.STATE_COLLAPSED) {
          dismiss()
        }
      }
    }

  override fun onCreateView(
    inflater: LayoutInflater,
    container: ViewGroup?,
    savedInstanceState: Bundle?,
  ): View? {
    if (savedInstanceState != null) dismiss()
    return inflater.inflate(R.layout.item_create_sheet, container, false)
  }

  override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
    super.onViewCreated(view, savedInstanceState)
    if (Build.VERSION.SDK_INT > Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
      ViewCompat.setOnApplyWindowInsetsListener(view) { v, windowInsets ->
        val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
        v.updateLayoutParams<ViewGroup.MarginLayoutParams> { bottomMargin = insets.bottom }
        windowInsets
      }

    view.viewTreeObserver.addOnGlobalLayoutListener(
      object : ViewTreeObserver.OnGlobalLayoutListener {
        override fun onGlobalLayout() {
          view.viewTreeObserver.removeOnGlobalLayoutListener(this)
          val dialog = dialog as BottomSheetDialog? ?: return
          behavior = dialog.behavior
          behavior?.apply {
            state = BottomSheetBehavior.STATE_EXPANDED
            peekHeight = 0
            addBottomSheetCallback(bottomSheetCallback)
          }
          dialog.findViewById<View>(R.id.create_folder)?.setOnClickListener {
            setFragmentResult(ITEM_CREATION_REQUEST_KEY, bundleOf(ACTION_KEY to ACTION_FOLDER))
            dismiss()
          }
          dialog.findViewById<View>(R.id.create_password)?.setOnClickListener {
            setFragmentResult(ITEM_CREATION_REQUEST_KEY, bundleOf(ACTION_KEY to ACTION_PASSWORD))
            dismiss()
          }
        }
      }
    )
  }

  override fun dismiss() {
    super.dismiss()
    behavior?.removeBottomSheetCallback(bottomSheetCallback)
  }
}
