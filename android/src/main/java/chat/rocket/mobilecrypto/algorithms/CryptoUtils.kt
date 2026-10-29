package chat.rocket.mobilecrypto.algorithms

import android.util.Base64
import java.nio.charset.StandardCharsets

/**
 * Common utility functions used across cryptographic algorithms
 */
object CryptoUtils {
    
    private val HEX_DIGITS = "0123456789abcdef".toCharArray()

    /**
     * Convert byte array to hexadecimal string
     */
    fun bytesToHex(bytes: ByteArray): String {
        val hexCharacters = CharArray(bytes.size * 2)
        for (index in bytes.indices) {
            val unsignedByte = bytes[index].toInt() and 0xff
            hexCharacters[index * 2] = HEX_DIGITS[unsignedByte ushr 4]
            hexCharacters[index * 2 + 1] = HEX_DIGITS[unsignedByte and 0x0f]
        }
        return String(hexCharacters)
    }

    /**
     * Convert hexadecimal string to byte array
     */
    fun hexToBytes(hex: String): ByteArray {
        val bytes = ByteArray((hex.length + 1) / 2)
        for (index in bytes.indices) {
            val highNibble = hexDigitValue(hex, index * 2)
            bytes[index] = if (index * 2 + 1 < hex.length) {
                ((highNibble shl 4) or hexDigitValue(hex, index * 2 + 1)).toByte()
            } else {
                highNibble.toByte()
            }
        }
        return bytes
    }

    private fun hexDigitValue(hex: String, position: Int): Int {
        val digitValue = Character.digit(hex[position], 16)
        if (digitValue < 0) {
            throw NumberFormatException("Invalid hex character '${hex[position]}' at position $position")
        }
        return digitValue
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
