/*
 * Copyright © 2014-2025 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.util.extensions

import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updateLayoutParams

fun AppCompatActivity.enableEdgeToEdgeView(view: View) = run {
  WindowCompat.enableEdgeToEdge(window)
  ViewCompat.setOnApplyWindowInsetsListener(view) { v, windowInsets ->
    val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars())
    v.updateLayoutParams<ViewGroup.MarginLayoutParams> {
      topMargin = insets.top
      leftMargin = insets.left
      bottomMargin = insets.bottom
      rightMargin = insets.right
    }

    WindowInsetsCompat.CONSUMED
  }
}
