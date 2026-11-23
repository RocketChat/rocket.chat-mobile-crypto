package com.margelo.nitro.mobilecrypto

import androidx.annotation.Keep
import chat.rocket.mobilecrypto.algorithms.RSACrypto
import com.facebook.proguard.annotations.DoNotStrip
import java.security.interfaces.RSAPrivateCrtKey

@Keep
@DoNotStrip
class HybridRSAPrivateKey(val privateKey: RSAPrivateCrtKey) : HybridRSAPrivateKeySpec() {
  override val memorySize: Long = privateKey.modulus.bitLength().toLong() / 8

  override fun exportJwk(): String =
    RSACrypto.exportJwk(privateKey)
}
