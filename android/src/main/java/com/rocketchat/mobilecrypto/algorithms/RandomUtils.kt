package com.rocketchat.mobilecrypto.algorithms

import java.security.SecureRandom
import java.util.UUID

/**
 * Random value generation utilities
 */
object RandomUtils {

    private const val ALPHANUMERIC_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    /**
     * Generate a random UUID string
     * 
     * @return UUID string
     */
    fun generateUuid(): String {
        return UUID.randomUUID().toString()
    }

    /**
     * Generate a random key as hexadecimal string
     * 
     * @param length Key length in bytes
     * @return Hexadecimal key string
     */
    fun generateRandomKeyHex(length: Int): String {
        val key = ByteArray(length)
        val secureRandom = SecureRandom()
        secureRandom.nextBytes(key)
        return CryptoUtils.bytesToHex(key)
    }

    /**
     * Generate random bytes as Base64 string
     * 
     * @param size Number of bytes to generate
     * @return Base64-encoded random bytes
     */
    fun generateRandomBytesBase64(size: Int): String {
        val bytes = ByteArray(size)
        val secureRandom = SecureRandom()
        secureRandom.nextBytes(bytes)
        return CryptoUtils.encodeBase64NoWrap(bytes)
    }

    /**
     * Generate random bytes as byte array
     * 
     * @param size Number of bytes to generate
     * @return Random byte array
     */
    fun generateRandomBytes(size: Int): ByteArray {
        val bytes = ByteArray(size)
        val secureRandom = SecureRandom()
        secureRandom.nextBytes(bytes)
        return bytes
    }

    /**
     * Generate random alphanumeric string
     * 
     * @param length Length of the string to generate
     * @return Random alphanumeric string
     */
    fun generateRandomAlphanumeric(length: Int): String {
        val secureRandom = SecureRandom()
        return (1..length)
            .map { ALPHANUMERIC_CHARS[secureRandom.nextInt(ALPHANUMERIC_CHARS.length)] }
            .joinToString("")
    }

    /**
     * Generate random integer within specified range
     * 
     * @param min Minimum value (inclusive)
     * @param max Maximum value (exclusive)
     * @return Random integer
     */
    fun generateRandomInt(min: Int, max: Int): Int {
        val secureRandom = SecureRandom()
        return secureRandom.nextInt(max - min) + min
    }

    /**
     * Generate cryptographically secure random boolean
     * 
     * @return Random boolean value
     */
    fun generateRandomBoolean(): Boolean {
        val secureRandom = SecureRandom()
        return secureRandom.nextBoolean()
    }

    /**
     * Generate random IV (Initialization Vector) for AES
     * 
     * @param size IV size in bytes (default: 16 for AES)
     * @return Random IV as byte array
     */
    fun generateRandomIV(size: Int = 16): ByteArray {
        return generateRandomBytes(size)
    }

    /**
     * Generate random IV (Initialization Vector) for AES as hex string
     * 
     * @param size IV size in bytes (default: 16 for AES)
     * @return Random IV as hexadecimal string
     */
    fun generateRandomIVHex(size: Int = 16): String {
        return generateRandomKeyHex(size)
    }

    /**
     * Generate random salt for password hashing
     * 
     * @param size Salt size in bytes (default: 32)
     * @return Random salt as byte array
     */
    fun generateRandomSalt(size: Int = 32): ByteArray {
        return generateRandomBytes(size)
    }

    /**
     * Generate random salt for password hashing as Base64 string
     * 
     * @param size Salt size in bytes (default: 32)
     * @return Random salt as Base64 string
     */
    fun generateRandomSaltBase64(size: Int = 32): String {
        return generateRandomBytesBase64(size)
    }
}
