package chat.rocket.mobilecrypto.algorithms

import android.util.Base64
import java.nio.charset.StandardCharsets

/**
 * Common utility functions used across cryptographic algorithms
 */
object CryptoUtils {
    
    /**
     * Convert byte array to hexadecimal string
     */
    fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Convert hexadecimal string to byte array
     */
    fun hexToBytes(hex: String): ByteArray {
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    /**
     * Encode byte array to Base64 string (no wrap)
     */
    fun encodeBase64NoWrap(bytes: ByteArray): String {
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    /**
     * Decode Base64 string to byte array (default flags)
     */
    fun decodeBase64(base64: String): ByteArray {
        return Base64.decode(base64, Base64.DEFAULT)
    }

    /**
     * Decode Base64 string to byte array (no wrap)
     */
    fun decodeBase64NoWrap(base64: String): ByteArray {
        return Base64.decode(base64, Base64.NO_WRAP)
    }

    /**
     * Decode Base64 URL-safe string to byte array
     */
    fun decodeBase64UrlSafe(base64: String): ByteArray {
        return Base64.decode(base64, Base64.URL_SAFE or Base64.NO_WRAP)
    }

    /**
     * Convert string to UTF-8 byte array
     */
    fun stringToUtf8Bytes(text: String): ByteArray {
        return text.toByteArray(StandardCharsets.UTF_8)
    }

    /**
     * Convert byte array to UTF-8 string
     */
    fun utf8BytesToString(bytes: ByteArray): String {
        return String(bytes, StandardCharsets.UTF_8)
    }
}
