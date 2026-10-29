package chat.rocket.mobilecrypto.algorithms

import android.util.Base64
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

object CryptoUtils {

    private val HEX_DIGITS = "0123456789abcdef".toCharArray()

    fun bytesToHex(bytes: ByteArray): String {
        val hexCharacters = CharArray(bytes.size * 2)
        for (index in bytes.indices) {
            val unsignedByte = bytes[index].toInt() and 0xff
            hexCharacters[index * 2] = HEX_DIGITS[unsignedByte ushr 4]
            hexCharacters[index * 2 + 1] = HEX_DIGITS[unsignedByte and 0x0f]
        }
        return String(hexCharacters)
    }

    fun encodeBase64(bytes: ByteArray): String {
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    fun decodeBase64(base64: String): ByteArray {
        return Base64.decode(base64, Base64.DEFAULT)
    }

    fun encodeBase64Url(bytes: ByteArray): String {
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    fun decodeBase64Url(base64Url: String): ByteArray {
        return Base64.decode(base64Url, Base64.URL_SAFE or Base64.NO_WRAP)
    }

    fun encodeUtf8(text: String): ByteArray {
        return text.toByteArray(StandardCharsets.UTF_8)
    }

    fun decodeUtf8(bytes: ByteArray): String {
        return StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    }
}
