package com.margelo.nitro.mobilecrypto

import androidx.annotation.Keep
import chat.rocket.mobilecrypto.algorithms.RSACrypto
import com.facebook.proguard.annotations.DoNotStrip
import com.margelo.nitro.core.ArrayBuffer
import java.security.SignatureException
import java.security.interfaces.RSAPublicKey

@Keep
@DoNotStrip
class HybridRSAPublicKey(private val publicKey: RSAPublicKey) : HybridRSAPublicKeySpec() {
  override val memorySize: Long = publicKey.modulus.bitLength().toLong() / 8

  override fun encrypt(plaintext: ArrayBuffer): ArrayBuffer =
    ArrayBuffer.copy(RSACrypto.encrypt(plaintext.toByteArray(), publicKey))

  override fun verify(signature: ArrayBuffer, message: ArrayBuffer, hash: RSAHashAlgorithm): Boolean =
    try {
      RSACrypto.verify(signature.toByteArray(), message.toByteArray(), publicKey, hash)
    } catch (exception: SignatureException) {
      false
    }
}
