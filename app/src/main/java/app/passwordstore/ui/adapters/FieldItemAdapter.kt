/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.adapters

import android.text.method.PasswordTransformationMethod
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.res.ResourcesCompat
import androidx.recyclerview.widget.RecyclerView
import app.passwordstore.R
import app.passwordstore.data.passfile.Totp
import app.passwordstore.data.password.FieldItem
import app.passwordstore.databinding.ItemFieldBinding
import app.passwordstore.ui.compose.R as composeR
import app.passwordstore.util.extensions.wipe
import com.google.android.material.textfield.TextInputLayout
import java.nio.CharBuffer

class FieldItemAdapter(
  private var fieldItemList: List<FieldItem>,
  private val showPassword: Boolean,
  private val copyToClipboard: (text: CharArray?, isSensitive: Boolean) -> Unit,
) : RecyclerView.Adapter<FieldItemAdapter.FieldItemViewHolder>() {

  override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): FieldItemViewHolder {
    val binding = ItemFieldBinding.inflate(LayoutInflater.from(parent.context), parent, false)
    return FieldItemViewHolder(binding.root, binding)
  }

  override fun onBindViewHolder(holder: FieldItemViewHolder, position: Int) {
    holder.bind(fieldItemList[position], showPassword, copyToClipboard)
  }

  override fun getItemCount(): Int {
    return fieldItemList.size
  }

  fun updateOTPCode(totp: Totp, labelFormat: String) {
    var otpItemPosition = -1
    fieldItemList =
      fieldItemList.mapIndexed { position, item ->
        if (item.type == FieldItem.ItemType.OTP) {
          otpItemPosition = position
          return@mapIndexed FieldItem.createOtpField(labelFormat, totp)
        }

        return@mapIndexed item
      }

    notifyItemChanged(otpItemPosition)
  }

  class FieldItemViewHolder(itemView: View, val binding: ItemFieldBinding) :
    RecyclerView.ViewHolder(itemView) {

    fun bind(
      fieldItem: FieldItem,
      showPassword: Boolean,
      copyToClipboard: (CharArray?, Boolean) -> Unit,
    ) {
      with(binding) {
        itemText.hint = fieldItem.label
        itemTextContainer.hint = fieldItem.label
        itemText.setText(CharBuffer.wrap(fieldItem.value))
        fieldItem.value.wipe()

        when (fieldItem.action) {
          FieldItem.ActionType.COPY -> {
            itemTextContainer.apply {
              setEndIconMode(TextInputLayout.END_ICON_CUSTOM)
              setEndIconDrawable(R.drawable.ic_content_copy)
              setEndIconOnClickListener {
                val chars = itemText.text?.let { CharArray(it.length) { i -> it[i] } }
                copyToClipboard(chars, false)
                chars?.wipe()
              }
            }
            itemText.transformationMethod = null
          }
          FieldItem.ActionType.HIDE -> {
            itemTextContainer.apply {
              setEndIconMode(TextInputLayout.END_ICON_PASSWORD_TOGGLE)
              setOnClickListener {
                val chars = itemText.text?.let { CharArray(it.length) { i -> it[i] } }
                copyToClipboard(chars, true)
                chars?.wipe()
              }
            }
            itemText.apply {
              transformationMethod =
                if (!showPassword) {
                  PasswordTransformationMethod.getInstance()
                } else {
                  null
                }
              if (fieldItem.type == FieldItem.ItemType.PASSWORD) {
                setTextIsSelectable(false)
                typeface =
                  ResourcesCompat.getFont(
                    binding.root.context,
                    composeR.font.jetbrainsmono_nl_regular,
                  )
              }
              setOnClickListener {
                val chars = itemText.text?.let { CharArray(it.length) { i -> it[i] } }
                copyToClipboard(chars, true)
                chars?.wipe()
              }
            }
          }
        }
      }
    }
  }
}
