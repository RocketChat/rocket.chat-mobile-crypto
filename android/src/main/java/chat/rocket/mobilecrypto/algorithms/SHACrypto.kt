package chat.rocket.mobilecrypto.algorithms

import com.margelo.nitro.mobilecrypto.SHAAlgorithm
import java.security.MessageDigest

/**
 * SHA (Secure Hash Algorithm) operations
 */
object SHACrypto {

    fun computeHash(data: ByteArray, algorithm: SHAAlgorithm): ByteArray {
        return MessageDigest.getInstance(algorithm.digestName).digest(data)
    }

    fun hashBase64(dataBase64: String, algorithm: SHAAlgorithm): String {
        val digest = computeHash(CryptoUtils.decodeBase64NoWrap(dataBase64), algorithm)
        return CryptoUtils.encodeBase64NoWrap(digest)
    }

    fun hashUtf8ToHex(data: String, algorithm: SHAAlgorithm): String {
        val digest = computeHash(CryptoUtils.stringToUtf8Bytes(data), algorithm)
        return CryptoUtils.bytesToHex(digest)
    }
}
