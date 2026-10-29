package com.margelo.nitro.mobilecrypto

import androidx.annotation.Keep
import chat.rocket.mobilecrypto.algorithms.RSACrypto
import com.facebook.proguard.annotations.DoNotStrip
import com.margelo.nitro.core.ArrayBuffer
import com.margelo.nitro.core.Promise
import java.security.interfaces.RSAPrivateCrtKey

@Keep
@DoNotStrip
class HybridRSAPrivateKey(private val privateKey: RSAPrivateCrtKey) : HybridRSAPrivateKeySpec() {
  override val memorySize: Long = privateKey.modulus.bitLength().toLong() / 8

  override fun decrypt(ciphertext: String): Promise<String> =
    Promise.async { RSACrypto.decrypt(ciphertext, privateKey) }

  override fun sign(message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer> {
    val messageBytes = message.toByteArray()
    return Promise.async { ArrayBuffer.copy(RSACrypto.sign(messageBytes, privateKey, hash)) }
  }

  override fun exportJwk(): String =
    RSACrypto.exportJwk(privateKey)
}
