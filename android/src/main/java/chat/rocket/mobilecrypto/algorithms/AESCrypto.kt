package chat.rocket.mobilecrypto.algorithms

import android.content.Context
import android.net.Uri
import chat.rocket.mobilecrypto.AESKey
import com.margelo.nitro.mobilecrypto.AESGCMCiphertext
import com.margelo.nitro.mobilecrypto.EncryptedFile
import com.margelo.nitro.mobilecrypto.PBKDF2HashAlgorithm
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
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

internal object AESCrypto {

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

    fun generateKey(byteLength: Int): AESKey {
        AESKey.requireValidByteLength(byteLength)
        return AESKey(RandomUtils.generateRandomBytes(byteLength))
    }

    fun importKey(base64Url: String): AESKey =
        AESKey(CryptoUtils.decodeBase64Url(base64Url))

    fun exportKey(key: AESKey): String =
        CryptoUtils.encodeBase64Url(key.bytes)

    fun deriveKey(
        passwordBase64: String,
        saltBase64: String,
        iterations: Int,
        byteLength: Int,
        hash: PBKDF2HashAlgorithm
    ): AESKey {
        AESKey.requireValidByteLength(byteLength)
        return AESKey(
            PBKDF2Crypto.deriveKey(
                CryptoUtils.decodeBase64(passwordBase64),
                CryptoUtils.decodeBase64(saltBase64),
                iterations,
                byteLength,
                hash
            )
        )
    }

    fun gcmEncrypt(key: AESKey, plaintext: String): AESGCMCiphertext {
        val iv = RandomUtils.generateRandomBytes(GCM_IV_LENGTH)
        val sealed = runGcm(Cipher.ENCRYPT_MODE, CryptoUtils.encodeUtf8(plaintext), key, iv)
        return AESGCMCiphertext(CryptoUtils.encodeBase64(iv), CryptoUtils.encodeBase64(sealed))
    }

    fun gcmDecrypt(key: AESKey, ciphertext: String, iv: String): String {
        val sealed = CryptoUtils.decodeBase64(ciphertext)
        val ivBytes = CryptoUtils.decodeBase64(iv)
        require(ivBytes.size == GCM_IV_LENGTH) { "AES-GCM IV must be $GCM_IV_LENGTH bytes, got ${ivBytes.size}" }
        require(sealed.size >= GCM_TAG_LENGTH) {
            "AES-GCM ciphertext must be at least $GCM_TAG_LENGTH bytes, got ${sealed.size}"
        }
        return CryptoUtils.decodeUtf8(runGcm(Cipher.DECRYPT_MODE, sealed, key, ivBytes))
    }

    fun cbcEncrypt(key: AESKey, plaintext: String): String {
        val iv = RandomUtils.generateRandomBytes(CBC_IV_LENGTH)
        val ciphertext = runCbc(Cipher.ENCRYPT_MODE, CryptoUtils.encodeUtf8(plaintext), key, iv)
        return CryptoUtils.encodeBase64(iv + ciphertext)
    }

    fun cbcDecrypt(key: AESKey, ivAndCiphertext: String): String {
        val combined = CryptoUtils.decodeBase64(ivAndCiphertext)
        require(combined.size >= CBC_IV_LENGTH * 2) {
            "AES-CBC input must be at least ${CBC_IV_LENGTH * 2} bytes, got ${combined.size}"
        }
        val iv = combined.copyOfRange(0, CBC_IV_LENGTH)
        val ciphertext = combined.copyOfRange(CBC_IV_LENGTH, combined.size)
        return CryptoUtils.decodeUtf8(runCbc(Cipher.DECRYPT_MODE, ciphertext, key, iv))
    }

    private fun runCbc(mode: Int, input: ByteArray, key: AESKey, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(CBC_CIPHER_ALGORITHM)
        cipher.init(mode, SecretKeySpec(key.bytes, KEY_ALGORITHM), IvParameterSpec(iv))
        return cipher.doFinal(input)
    }

    private fun runGcm(mode: Int, input: ByteArray, key: AESKey, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(GCM_CIPHER_ALGORITHM)
        cipher.init(mode, SecretKeySpec(key.bytes, KEY_ALGORITHM), GCMParameterSpec(GCM_TAG_LENGTH * 8, iv))
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

    fun decryptFile(file: EncryptedFile, context: Context): String {
        val key = CryptoUtils.decodeBase64Url(file.key)
        require(key.size == FILE_KEY_LENGTH) { "File key must be $FILE_KEY_LENGTH bytes, got ${key.size}" }
        val iv = CryptoUtils.decodeBase64(file.iv)
        val targetUri = Uri.parse(file.path)
        val isPlainFilePath = targetUri.scheme == null || targetUri.scheme == "file"
        val targetFile = File(normalizeFilePath(file.path))
        val outputDirectory = if (isPlainFilePath) {
            targetFile.absoluteFile.parentFile?.takeIf { it.canWrite() } ?: context.cacheDir
        } else {
            context.cacheDir
        }
        val outputFile = File(outputDirectory, "processed_${UUID.randomUUID()}")
        val plaintextDigest = MessageDigest.getInstance(FILE_DIGEST_ALGORITHM)

        try {
            openInputStream(file.path, context).use { inputStream ->
                DigestOutputStream(FileOutputStream(outputFile), plaintextDigest).use { outputStream ->
                    runCtr(Cipher.DECRYPT_MODE, key, iv, inputStream, outputStream)
                }
            }
            val actualSha256 = CryptoUtils.bytesToHex(plaintextDigest.digest())
            if (!actualSha256.equals(file.sha256, ignoreCase = true)) {
                throw SecurityException("Decrypted file SHA-256 $actualSha256 does not match expected ${file.sha256}")
            }
        } catch (exception: Exception) {
            outputFile.delete()
            throw exception
        }

        if (isPlainFilePath && outputFile.renameTo(targetFile)) {
            return file.path
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
        } catch (exception: Exception) {
            throw IOException(
                "Writing the decrypted file to $targetUri failed; decrypted output kept at ${outputFile.absolutePath}",
                exception
            )
        }
        outputFile.delete()
        return file.path
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
