package com.rocketchat.mobilecrypto.algorithms

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * SHA (Secure Hash Algorithm) operations
 */
object SHACrypto {

    /**
     * Supported SHA algorithms
     */
    private val supportedAlgorithms = listOf("SHA-1", "SHA-256", "SHA-384", "SHA-512")

    /**
     * Compute SHA hash of data
     * 
     * @param data Input data bytes
     * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
     * @return Hash bytes
     * @throws NoSuchAlgorithmException if algorithm not supported
     * @throws IllegalArgumentException if algorithm not in supported list
     */
    @Throws(NoSuchAlgorithmException::class, IllegalArgumentException::class)
    fun computeHash(data: ByteArray, algorithm: String): ByteArray {
        if (!supportedAlgorithms.contains(algorithm)) {
            throw IllegalArgumentException("Unsupported algorithm: $algorithm. Supported: $supportedAlgorithms")
        }
        
        val messageDigest = MessageDigest.getInstance(algorithm)
        messageDigest.update(data)
        return messageDigest.digest()
    }

    /**
     * Compute SHA hash of Base64-encoded data and return Base64-encoded result
     * 
     * @param dataBase64 Base64-encoded input data
     * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
     * @return Base64-encoded hash
     */
    @Throws(NoSuchAlgorithmException::class, IllegalArgumentException::class)
    fun hashBase64(dataBase64: String, algorithm: String): String {
        val decodedData = CryptoUtils.decodeBase64NoWrap(dataBase64)
        val digest = computeHash(decodedData, algorithm)
        return CryptoUtils.encodeBase64NoWrap(digest)
    }

    /**
     * Compute SHA hash of UTF-8 string and return hexadecimal result
     * 
     * @param data UTF-8 string data
     * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
     * @return Hexadecimal hash
     */
    @Throws(NoSuchAlgorithmException::class, IllegalArgumentException::class)
    fun hashUtf8ToHex(data: String, algorithm: String): String {
        val digest = computeHash(CryptoUtils.stringToUtf8Bytes(data), algorithm)
        return CryptoUtils.bytesToHex(digest)
    }

    /**
     * Compute SHA hash of UTF-8 string and return Base64-encoded result
     * 
     * @param data UTF-8 string data
     * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
     * @return Base64-encoded hash
     */
    @Throws(NoSuchAlgorithmException::class, IllegalArgumentException::class)
    fun hashUtf8ToBase64(data: String, algorithm: String): String {
        val digest = computeHash(CryptoUtils.stringToUtf8Bytes(data), algorithm)
        return CryptoUtils.encodeBase64NoWrap(digest)
    }

    /**
     * Compute SHA hash of byte array and return hexadecimal result
     * 
     * @param data Input data bytes
     * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
     * @return Hexadecimal hash
     */
    @Throws(NoSuchAlgorithmException::class, IllegalArgumentException::class)
    fun hashToHex(data: ByteArray, algorithm: String): String {
        val digest = computeHash(data, algorithm)
        return CryptoUtils.bytesToHex(digest)
    }

    /**
     * Compute SHA hash of byte array and return Base64-encoded result
     * 
     * @param data Input data bytes
     * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
     * @return Base64-encoded hash
     */
    @Throws(NoSuchAlgorithmException::class, IllegalArgumentException::class)
    fun hashToBase64(data: ByteArray, algorithm: String): String {
        val digest = computeHash(data, algorithm)
        return CryptoUtils.encodeBase64NoWrap(digest)
    }

    /**
     * Get list of supported SHA algorithms
     */
    fun getSupportedAlgorithms(): List<String> {
        return supportedAlgorithms.toList()
    }

    /**
     * Check if algorithm is supported
     */
    fun isAlgorithmSupported(algorithm: String): Boolean {
        return supportedAlgorithms.contains(algorithm)
    }
}
