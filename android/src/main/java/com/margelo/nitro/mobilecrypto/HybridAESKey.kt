package com.margelo.nitro.mobilecrypto

import androidx.annotation.Keep
import chat.rocket.mobilecrypto.AESKey
import chat.rocket.mobilecrypto.algorithms.AESCrypto
import com.facebook.proguard.annotations.DoNotStrip

@Keep
@DoNotStrip
class HybridAESKey(val key: AESKey) : HybridAESKeySpec() {
  override val memorySize: Long = key.bytes.size.toLong()

  override fun exportBase64Url(): String =
    AESCrypto.exportKey(key)
}
