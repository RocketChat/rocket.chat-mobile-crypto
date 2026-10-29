package com.margelo.nitro.mobilecrypto

import androidx.annotation.Keep
import chat.rocket.mobilecrypto.algorithms.AESCrypto
import com.facebook.proguard.annotations.DoNotStrip

@Keep
@DoNotStrip
class HybridAESKey(val key: ByteArray) : HybridAESKeySpec() {
  override val memorySize: Long = key.size.toLong()

  override fun exportBase64Url(): String =
    AESCrypto.exportKey(key)
}
