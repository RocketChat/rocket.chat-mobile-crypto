package chat.rocket.mobilecrypto.algorithms

import android.content.Context
import android.net.Uri
import android.util.Base64
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES encryption and decryption operations
 */
object AESCrypto {

    private const val CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding"
    private const val GCM_CIPHER_ALGORITHM = "AES/GCM/NoPadding"
    private const val FILE_CIPHER_ALGORITHM = "AES/CTR/NoPadding"
    private const val KEY_ALGORITHM = "AES"
    private const val BUFFER_SIZE = 65536
    private const val CBC_IV_LENGTH = 16
    private const val GCM_IV_LENGTH = 12
    private const val GCM_TAG_LENGTH = 16
    private val AES_KEY_LENGTHS = setOf(16, 24, 32)

    /**
     * Encrypt Base64-encoded data using AES-CBC with PKCS7 padding
     */
    fun encryptBase64(textBase64: String?, hexKey: String, hexIv: String?): String? {
        if (textBase64.isNullOrEmpty()) return null

        val encrypted = runCbc(Cipher.ENCRYPT_MODE, CryptoUtils.decodeBase64(textBase64), CryptoUtils.hexToBytes(hexKey), cbcIv(hexIv))
        return CryptoUtils.encodeBase64NoWrap(encrypted)
    }

    /**
     * Decrypt Base64-encoded data using AES-CBC with PKCS7 padding
     */
    fun decryptBase64(ciphertext: String?, hexKey: String, hexIv: String?): String? {
        if (ciphertext.isNullOrEmpty()) return null

        val decrypted = runCbc(Cipher.DECRYPT_MODE, CryptoUtils.decodeBase64(ciphertext), CryptoUtils.hexToBytes(hexKey), cbcIv(hexIv))
        return CryptoUtils.encodeBase64NoWrap(decrypted)
    }

    fun encryptCbc(plaintext: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        requireKeyLength(key)
        requireIvLength(iv, CBC_IV_LENGTH)
        return runCbc(Cipher.ENCRYPT_MODE, plaintext, key, iv)
    }

    fun decryptCbc(ciphertext: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        requireKeyLength(key)
        requireIvLength(iv, CBC_IV_LENGTH)
        return runCbc(Cipher.DECRYPT_MODE, ciphertext, key, iv)
    }

    fun encryptGcm(plaintext: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        requireKeyLength(key)
        requireIvLength(iv, GCM_IV_LENGTH)
        return runGcm(Cipher.ENCRYPT_MODE, plaintext, key, iv)
    }

    fun decryptGcm(sealed: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        requireKeyLength(key)
        requireIvLength(iv, GCM_IV_LENGTH)
        require(sealed.size >= GCM_TAG_LENGTH) {
            "AES-GCM input must be at least $GCM_TAG_LENGTH bytes, got ${sealed.size}"
        }
        return runGcm(Cipher.DECRYPT_MODE, sealed, key, iv)
    }

    private fun runCbc(mode: Int, input: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        cipher.init(mode, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
        return cipher.doFinal(input)
    }

    private fun runGcm(mode: Int, input: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(GCM_CIPHER_ALGORITHM)
        cipher.init(mode, SecretKeySpec(key, KEY_ALGORITHM), GCMParameterSpec(GCM_TAG_LENGTH * 8, iv))
        return cipher.doFinal(input)
    }

    private fun cbcIv(hexIv: String?): ByteArray =
        if (hexIv == null) ByteArray(CBC_IV_LENGTH) else CryptoUtils.hexToBytes(hexIv)

    private fun requireKeyLength(key: ByteArray) {
        require(key.size in AES_KEY_LENGTHS) { "AES key must be 16, 24 or 32 bytes, got ${key.size}" }
    }

    private fun requireIvLength(iv: ByteArray, expectedLength: Int) {
        require(iv.size == expectedLength) { "AES IV must be $expectedLength bytes, got ${iv.size}" }
    }

    /**
     * Encrypt a file using AES-CTR mode
     */
    fun encryptFile(inputFile: String, base64UrlKey: String, base64Iv: String, context: Context): String {
        return processFile(inputFile, base64UrlKey, base64Iv, Cipher.ENCRYPT_MODE, context)
    }

    /**
     * Decrypt a file using AES-CTR mode
     */
    fun decryptFile(inputFile: String, base64UrlKey: String, base64Iv: String, context: Context): String {
        return processFile(inputFile, base64UrlKey, base64Iv, Cipher.DECRYPT_MODE, context)
    }

    /**
     * Process file encryption/decryption using AES-CTR mode
     */
    private fun processFile(inputFile: String, base64UrlKey: String, base64Iv: String, cipherMode: Int, context: Context): String {
        // Decode the key and IV
        val key = Base64.decode(base64UrlKey, Base64.URL_SAFE or Base64.NO_WRAP)
        val iv = CryptoUtils.decodeBase64NoWrap(base64Iv)
        val secretKey = SecretKeySpec(key, "AES")

        // Initialize the cipher
        val cipher = Cipher.getInstance(FILE_CIPHER_ALGORITHM)
        val ivParameterSpec = IvParameterSpec(iv)
        cipher.init(cipherMode, secretKey, ivParameterSpec)

        val targetUri = Uri.parse(inputFile)
        val isPlainFilePath = targetUri.scheme == null || targetUri.scheme == "file"
        val targetFile = File(normalizeFilePath(inputFile))
        val outputDirectory = if (cipherMode == Cipher.DECRYPT_MODE && isPlainFilePath) {
            targetFile.absoluteFile.parentFile?.takeIf { it.canWrite() } ?: context.cacheDir
        } else {
            context.cacheDir
        }
        val outputFileObj = File(outputDirectory, "processed_${UUID.randomUUID()}")

        try {
            getInputStream(inputFile, context).use { inputStream ->
                FileOutputStream(outputFileObj).use { fos ->
                    val buffer = ByteArray(BUFFER_SIZE)
                    var numBytesRead: Int
                    
                    while (inputStream.read(buffer).also { numBytesRead = it } != -1) {
                        val output = cipher.update(buffer, 0, numBytesRead)
                        output?.let { fos.write(it) }
                    }
                    
                    val finalBytes = cipher.doFinal()
                    finalBytes?.let { fos.write(it) }
                }
            }
        } catch (ex: Exception) {
            outputFileObj.delete()
            throw ex
        }

        return if (cipherMode == Cipher.DECRYPT_MODE) {
            if (isPlainFilePath && outputFileObj.renameTo(targetFile)) {
                return inputFile
            }
            FileInputStream(outputFileObj).use { inputStream ->
                val outputStream = if (isPlainFilePath) {
                    FileOutputStream(targetFile)
                } else {
                    context.contentResolver.openOutputStream(targetUri)
                        ?: throw IllegalArgumentException("Cannot open output stream for URI: $targetUri")
                }
                outputStream.use { fos ->
                    val buffer = ByteArray(BUFFER_SIZE)
                    var numBytesRead: Int
                    
                    while (inputStream.read(buffer).also { numBytesRead = it } != -1) {
                        fos.write(buffer, 0, numBytesRead)
                    }
                }
            }
            outputFileObj.delete()
            inputFile
        } else {
            "file://${outputFileObj.absolutePath}"
        }
    }

    /**
     * Encrypt Base64-encoded data using AES-256-GCM
     * @param textBase64 The Base64-encoded plaintext to encrypt
     * @param hexKey The 256-bit (32 bytes) key in hexadecimal format
     * @param hexIv The 96-bit (12 bytes) IV in hexadecimal format, or null to use zero IV
     * @return Base64-encoded encrypted data with authentication tag, or null on error
     */
    fun encryptGcmBase64(textBase64: String?, hexKey: String, hexIv: String?): String? {
        if (textBase64.isNullOrEmpty()) return null

        return try {
            val encrypted = runGcm(Cipher.ENCRYPT_MODE, CryptoUtils.decodeBase64(textBase64), CryptoUtils.hexToBytes(hexKey), gcmIv(hexIv))
            CryptoUtils.encodeBase64NoWrap(encrypted)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Decrypt Base64-encoded data using AES-256-GCM
     * @param ciphertext The Base64-encoded ciphertext with authentication tag to decrypt
     * @param hexKey The 256-bit (32 bytes) key in hexadecimal format
     * @param hexIv The 96-bit (12 bytes) IV in hexadecimal format, or null to use zero IV
     * @return Base64-encoded decrypted data, or null on error or authentication failure
     */
    fun decryptGcmBase64(ciphertext: String?, hexKey: String, hexIv: String?): String? {
        if (ciphertext.isNullOrEmpty()) return null

        return try {
            val decrypted = runGcm(Cipher.DECRYPT_MODE, CryptoUtils.decodeBase64(ciphertext), CryptoUtils.hexToBytes(hexKey), gcmIv(hexIv))
            CryptoUtils.encodeBase64NoWrap(decrypted)
        } catch (e: Exception) {
            null
        }
    }

    private fun gcmIv(hexIv: String?): ByteArray =
        if (hexIv == null) ByteArray(GCM_IV_LENGTH) else CryptoUtils.hexToBytes(hexIv)

    /**
     * Get input stream for a file path with better error handling
     */
    private fun getInputStream(filePath: String, context: Context): InputStream {
        val uri = Uri.parse(filePath)

        return if (uri.scheme == null || uri.scheme == "file") {
            // Use the decoded path for FileInputStream
            val normalizedPath = normalizeFilePath(filePath)
            FileInputStream(normalizedPath)
        } else {
            context.contentResolver.openInputStream(uri)
                ?: throw IllegalArgumentException("Cannot open input stream for URI: $uri")
        }
    }

    /**
     * Normalize file path by removing file:// prefix and decoding URL-encoded characters
     * (e.g., %20 for spaces, %D0%9D for Cyrillic chars)
     */
    private fun normalizeFilePath(filePath: String): String {
        var path = filePath

        // Remove file:// prefix if present
        if (path.startsWith("file://")) {
            path = path.substring(7)
            return try {
                Uri.decode(path)
            } catch (e: Exception) {
                path
            }
        }

        return path
    }
}
