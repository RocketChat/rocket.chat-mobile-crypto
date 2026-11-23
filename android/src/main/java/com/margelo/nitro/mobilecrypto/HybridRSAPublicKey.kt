package com.margelo.nitro.mobilecrypto

import androidx.annotation.Keep
import chat.rocket.mobilecrypto.algorithms.RSACrypto
import com.facebook.proguard.annotations.DoNotStrip
import java.security.interfaces.RSAPublicKey

@Keep
@DoNotStrip
class HybridRSAPublicKey(val publicKey: RSAPublicKey) : HybridRSAPublicKeySpec() {
  override val memorySize: Long = publicKey.modulus.bitLength().toLong() / 8

  override fun exportJwk(): String =
    RSACrypto.exportJwk(publicKey)
}
