package com.margelo.nitro.mobilecrypto

import androidx.annotation.Keep
import chat.rocket.mobilecrypto.algorithms.RSACrypto
import com.facebook.proguard.annotations.DoNotStrip
import com.margelo.nitro.core.ArrayBuffer
import com.margelo.nitro.core.Promise
import java.security.interfaces.RSAPrivateKey

@Keep
@DoNotStrip
class HybridRSAPrivateKey(private val privateKey: RSAPrivateKey) : HybridRSAPrivateKeySpec() {
  override val memorySize: Long = privateKey.modulus.bitLength().toLong() / 8

  override fun decrypt(ciphertext: ArrayBuffer): Promise<ArrayBuffer> {
    val ciphertextBytes = ciphertext.toByteArray()
    return Promise.async { ArrayBuffer.copy(RSACrypto.decrypt(ciphertextBytes, privateKey)) }
  }

  override fun sign(message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer> {
    val messageBytes = message.toByteArray()
    return Promise.async { ArrayBuffer.copy(RSACrypto.sign(messageBytes, privateKey, hash)) }
  }
}
