package chat.rocket.mobilecrypto.algorithms

import android.util.Base64
import com.facebook.react.bridge.ReactApplicationContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES encryption and decryption operations
 */
object AESCrypto {

    private const val CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding"
    private const val FILE_CIPHER_ALGORITHM = "AES/CTR/NoPadding"
    private const val KEY_ALGORITHM = "AES"
    private const val BUFFER_SIZE = 4096
    private val EMPTY_IV_SPEC = IvParameterSpec(ByteArray(16) { 0 })

    /**
     * Encrypt Base64-encoded data using AES-CBC with PKCS7 padding
     */
    fun encryptBase64(textBase64: String?, hexKey: String, hexIv: String?): String? {
        if (textBase64.isNullOrEmpty()) return null

        val key = CryptoUtils.hexToBytes(hexKey)
        val secretKey = SecretKeySpec(key, KEY_ALGORITHM)

        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        val ivSpec = if (hexIv == null) EMPTY_IV_SPEC else IvParameterSpec(CryptoUtils.hexToBytes(hexIv))
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
        
        val encrypted = cipher.doFinal(CryptoUtils.decodeBase64(textBase64))
        return CryptoUtils.encodeBase64NoWrap(encrypted)
    }

    /**
     * Decrypt Base64-encoded data using AES-CBC with PKCS7 padding
     */
    fun decryptBase64(ciphertext: String?, hexKey: String, hexIv: String?): String? {
        if (ciphertext.isNullOrEmpty()) return null

        val key = CryptoUtils.hexToBytes(hexKey)
        val secretKey = SecretKeySpec(key, KEY_ALGORITHM)

        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        val ivSpec = if (hexIv == null) EMPTY_IV_SPEC else IvParameterSpec(CryptoUtils.hexToBytes(hexIv))
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        
        val decrypted = cipher.doFinal(CryptoUtils.decodeBase64(ciphertext))
        return CryptoUtils.encodeBase64NoWrap(decrypted)
    }

    /**
     * Encrypt a file using AES-CTR mode
     */
    fun encryptFile(inputFile: String, base64UrlKey: String, base64Iv: String, reactContext: ReactApplicationContext): String {
        return processFile(inputFile, base64UrlKey, base64Iv, "encrypt", reactContext)
    }

    /**
     * Decrypt a file using AES-CTR mode
     */
    fun decryptFile(inputFile: String, base64UrlKey: String, base64Iv: String, reactContext: ReactApplicationContext): String {
        return processFile(inputFile, base64UrlKey, base64Iv, "decrypt", reactContext)
    }

    /**
     * Process file encryption/decryption using AES-CTR mode
     */
    private fun processFile(inputFile: String, base64UrlKey: String, base64Iv: String, mode: String, reactContext: ReactApplicationContext): String {
        // Decode the key and IV
        val key = Base64.decode(base64UrlKey, Base64.URL_SAFE or Base64.NO_WRAP)
        val iv = CryptoUtils.decodeBase64NoWrap(base64Iv)
        val secretKey = SecretKeySpec(key, "AES")

        // Initialize the cipher
        val cipher = Cipher.getInstance(FILE_CIPHER_ALGORITHM)
        val ivParameterSpec = IvParameterSpec(iv)
        val cipherMode = if (mode == "encrypt") Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE
        cipher.init(cipherMode, secretKey, ivParameterSpec)

        // Create a temporary output file in the cache directory
        val outputFileObj = File(reactContext.cacheDir, "processed_${UUID.randomUUID()}")

        try {
            getInputStream(inputFile).use { inputStream ->
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

        return if (mode == "decrypt") {
            // Overwrite the input file with the decrypted file
            val targetPath = if (inputFile.startsWith("file://")) inputFile.substring(7) else inputFile
            FileInputStream(outputFileObj).use { inputStream ->
                FileOutputStream(targetPath).use { fos ->
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
     * Get input stream for a file path
     */
    private fun getInputStream(filePath: String): InputStream {
        val path = if (filePath.startsWith("file://")) filePath.substring(7) else filePath
        return FileInputStream(File(path))
    }
}
