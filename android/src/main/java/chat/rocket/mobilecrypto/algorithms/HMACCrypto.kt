package chat.rocket.mobilecrypto.algorithms

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object HMACCrypto {

    private const val HMAC_SHA256 = "HmacSHA256"

    fun hmacSha256(data: ByteArray, key: ByteArray): ByteArray {
        val mac = Mac.getInstance(HMAC_SHA256)
        mac.init(SecretKeySpec(key, HMAC_SHA256))
        return mac.doFinal(data)
    }
}
