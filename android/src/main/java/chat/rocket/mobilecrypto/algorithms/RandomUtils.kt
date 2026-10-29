package chat.rocket.mobilecrypto.algorithms

import java.security.SecureRandom
import java.util.UUID

object RandomUtils {

    private val secureRandom = SecureRandom()

    fun generateUuid(): String {
        return UUID.randomUUID().toString()
    }

    fun generateRandomKeyHex(length: Int): String {
        return CryptoUtils.bytesToHex(generateRandomBytes(length))
    }

    fun generateRandomBytes(size: Int): ByteArray {
        val bytes = ByteArray(size)
        secureRandom.nextBytes(bytes)
        return bytes
    }
}
