package chat.rocket.mobilecrypto.algorithms

import android.content.Context
import android.net.Uri
import com.margelo.nitro.mobilecrypto.AESGCMCiphertext
import com.margelo.nitro.mobilecrypto.EncryptedFile
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.DigestInputStream
import java.security.DigestOutputStream
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object AESCrypto {

    private const val CBC_CIPHER_ALGORITHM = "AES/CBC/PKCS7Padding"
    private const val GCM_CIPHER_ALGORITHM = "AES/GCM/NoPadding"
    private const val FILE_CIPHER_ALGORITHM = "AES/CTR/NoPadding"
    private const val KEY_ALGORITHM = "AES"
    private const val FILE_DIGEST_ALGORITHM = "SHA-256"
    private const val BUFFER_SIZE = 65536
    private const val CBC_IV_LENGTH = 16
    private const val GCM_IV_LENGTH = 12
    private const val GCM_TAG_LENGTH = 16
    private const val FILE_KEY_LENGTH = 32
    private const val FILE_IV_LENGTH = 16
    private val AES_KEY_LENGTHS = setOf(16, 24, 32)

    fun generateKey(byteLength: Int): ByteArray {
        requireKeyLength(byteLength)
        return RandomUtils.generateRandomBytes(byteLength)
    }

    fun importKey(base64Url: String): ByteArray {
        val key = CryptoUtils.decodeBase64Url(base64Url)
        requireKeyLength(key.size)
        return key
    }

    fun exportKey(key: ByteArray): String {
        return CryptoUtils.encodeBase64Url(key)
    }

    fun requireKeyLength(byteLength: Int) {
        require(byteLength in AES_KEY_LENGTHS) { "AES key must be 16, 24 or 32 bytes, got $byteLength" }
    }

    fun gcmEncrypt(key: ByteArray, plaintext: String): AESGCMCiphertext {
        val iv = RandomUtils.generateRandomBytes(GCM_IV_LENGTH)
        val sealed = runGcm(Cipher.ENCRYPT_MODE, CryptoUtils.encodeUtf8(plaintext), key, iv)
        return AESGCMCiphertext(CryptoUtils.encodeBase64(iv), CryptoUtils.encodeBase64(sealed))
    }

    fun gcmDecrypt(key: ByteArray, ciphertext: String, iv: String): String {
        val sealed = CryptoUtils.decodeBase64(ciphertext)
        val ivBytes = CryptoUtils.decodeBase64(iv)
        require(ivBytes.size == GCM_IV_LENGTH) { "AES-GCM IV must be $GCM_IV_LENGTH bytes, got ${ivBytes.size}" }
        require(sealed.size >= GCM_TAG_LENGTH) {
            "AES-GCM ciphertext must be at least $GCM_TAG_LENGTH bytes, got ${sealed.size}"
        }
        return CryptoUtils.decodeUtf8(runGcm(Cipher.DECRYPT_MODE, sealed, key, ivBytes))
    }

    fun cbcEncrypt(key: ByteArray, plaintext: String): String {
        val iv = RandomUtils.generateRandomBytes(CBC_IV_LENGTH)
        val ciphertext = runCbc(Cipher.ENCRYPT_MODE, CryptoUtils.encodeUtf8(plaintext), key, iv)
        return CryptoUtils.encodeBase64(iv + ciphertext)
    }

    fun cbcDecrypt(key: ByteArray, ivAndCiphertext: String): String {
        val combined = CryptoUtils.decodeBase64(ivAndCiphertext)
        require(combined.size >= CBC_IV_LENGTH * 2) {
            "AES-CBC input must be at least ${CBC_IV_LENGTH * 2} bytes, got ${combined.size}"
        }
        val iv = combined.copyOfRange(0, CBC_IV_LENGTH)
        val ciphertext = combined.copyOfRange(CBC_IV_LENGTH, combined.size)
        return CryptoUtils.decodeUtf8(runCbc(Cipher.DECRYPT_MODE, ciphertext, key, iv))
    }

    private fun runCbc(mode: Int, input: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        requireKeyLength(key.size)
        val cipher = Cipher.getInstance(CBC_CIPHER_ALGORITHM)
        cipher.init(mode, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
        return cipher.doFinal(input)
    }

    private fun runGcm(mode: Int, input: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        requireKeyLength(key.size)
        val cipher = Cipher.getInstance(GCM_CIPHER_ALGORITHM)
        cipher.init(mode, SecretKeySpec(key, KEY_ALGORITHM), GCMParameterSpec(GCM_TAG_LENGTH * 8, iv))
        return cipher.doFinal(input)
    }

    fun encryptFile(inputFile: String, context: Context): EncryptedFile {
        val key = RandomUtils.generateRandomBytes(FILE_KEY_LENGTH)
        val iv = RandomUtils.generateRandomBytes(FILE_IV_LENGTH)
        val plaintextDigest = MessageDigest.getInstance(FILE_DIGEST_ALGORITHM)
        val outputFile = File(context.cacheDir, "processed_${UUID.randomUUID()}")

        try {
            DigestInputStream(openInputStream(inputFile, context), plaintextDigest).use { inputStream ->
                FileOutputStream(outputFile).use { outputStream ->
                    runCtr(Cipher.ENCRYPT_MODE, key, iv, inputStream, outputStream)
                }
            }
        } catch (exception: Exception) {
            outputFile.delete()
            throw exception
        }

        return EncryptedFile(
            "file://${outputFile.absolutePath}",
            CryptoUtils.encodeBase64Url(key),
            CryptoUtils.encodeBase64(iv),
            CryptoUtils.bytesToHex(plaintextDigest.digest())
        )
    }

    fun decryptFile(inputFile: String, base64UrlKey: String, base64Iv: String, expectedSha256: String, context: Context): String {
        val key = CryptoUtils.decodeBase64Url(base64UrlKey)
        val iv = CryptoUtils.decodeBase64(base64Iv)
        val targetUri = Uri.parse(inputFile)
        val isPlainFilePath = targetUri.scheme == null || targetUri.scheme == "file"
        val targetFile = File(normalizeFilePath(inputFile))
        val outputDirectory = if (isPlainFilePath) {
            targetFile.absoluteFile.parentFile?.takeIf { it.canWrite() } ?: context.cacheDir
        } else {
            context.cacheDir
        }
        val outputFile = File(outputDirectory, "processed_${UUID.randomUUID()}")
        val plaintextDigest = MessageDigest.getInstance(FILE_DIGEST_ALGORITHM)

        try {
            openInputStream(inputFile, context).use { inputStream ->
                DigestOutputStream(FileOutputStream(outputFile), plaintextDigest).use { outputStream ->
                    runCtr(Cipher.DECRYPT_MODE, key, iv, inputStream, outputStream)
                }
            }
            val actualSha256 = CryptoUtils.bytesToHex(plaintextDigest.digest())
            if (!actualSha256.equals(expectedSha256, ignoreCase = true)) {
                throw SecurityException("Decrypted file SHA-256 $actualSha256 does not match expected $expectedSha256")
            }
        } catch (exception: Exception) {
            outputFile.delete()
            throw exception
        }

        if (isPlainFilePath && outputFile.renameTo(targetFile)) {
            return inputFile
        }
        try {
            FileInputStream(outputFile).use { inputStream ->
                val outputStream = if (isPlainFilePath) {
                    FileOutputStream(targetFile)
                } else {
                    context.contentResolver.openOutputStream(targetUri)
                        ?: throw IllegalArgumentException("Cannot open output stream for URI: $targetUri")
                }
                outputStream.use { inputStream.copyTo(it, BUFFER_SIZE) }
            }
        } finally {
            outputFile.delete()
        }
        return inputFile
    }

    private fun runCtr(mode: Int, key: ByteArray, iv: ByteArray, inputStream: InputStream, outputStream: OutputStream) {
        val cipher = Cipher.getInstance(FILE_CIPHER_ALGORITHM)
        cipher.init(mode, SecretKeySpec(key, KEY_ALGORITHM), IvParameterSpec(iv))
        val buffer = ByteArray(BUFFER_SIZE)
        var bytesRead: Int
        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
            cipher.update(buffer, 0, bytesRead)?.let { outputStream.write(it) }
        }
        cipher.doFinal()?.let { outputStream.write(it) }
    }

    private fun openInputStream(filePath: String, context: Context): InputStream {
        val uri = Uri.parse(filePath)

        return if (uri.scheme == null || uri.scheme == "file") {
            FileInputStream(normalizeFilePath(filePath))
        } else {
            context.contentResolver.openInputStream(uri)
                ?: throw IllegalArgumentException("Cannot open input stream for URI: $uri")
        }
    }

    private fun normalizeFilePath(filePath: String): String {
        if (!filePath.startsWith("file://")) {
            return filePath
        }
        val path = filePath.substring("file://".length)
        return try {
            Uri.decode(path)
        } catch (exception: Exception) {
            path
        }
    }
}
