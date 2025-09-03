package com.rocketchat.mobilecrypto.algorithms

import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HMAC (Hash-based Message Authentication Code) operations
 */
object HMACCrypto {

    /**
     * Supported HMAC algorithms
     */
    enum class Algorithm(val algorithmName: String) {
        HMAC_SHA1("HmacSHA1"),
        HMAC_SHA224("HmacSHA224"),
        HMAC_SHA256("HmacSHA256"),
        HMAC_SHA384("HmacSHA384"),
        HMAC_SHA512("HmacSHA512")
    }

    /**
     * Compute HMAC using specified algorithm
     * 
     * @param data Data to authenticate
     * @param key Secret key
     * @param algorithm HMAC algorithm to use
     * @return HMAC bytes
     */
    @Throws(NoSuchAlgorithmException::class, InvalidKeyException::class)
    fun computeHmac(data: ByteArray, key: ByteArray, algorithm: Algorithm): ByteArray {
        val mac = Mac.getInstance(algorithm.algorithmName)
        val secretKey = SecretKeySpec(key, algorithm.algorithmName)
        mac.init(secretKey)
        return mac.doFinal(data)
    }

    /**
     * Compute HMAC-SHA256 with hex input/output
     * 
     * @param dataHex Data in hexadecimal format
     * @param keyHex Key in hexadecimal format
     * @return HMAC result in hexadecimal format
     */
    @Throws(NoSuchAlgorithmException::class, InvalidKeyException::class)
    fun hmacSha256Hex(dataHex: String, keyHex: String): String {
        val dataBytes = CryptoUtils.hexToBytes(dataHex)
        val keyBytes = CryptoUtils.hexToBytes(keyHex)
        val hmacBytes = computeHmac(dataBytes, keyBytes, Algorithm.HMAC_SHA256)
        return CryptoUtils.bytesToHex(hmacBytes)
    }

    /**
     * Compute HMAC with Base64 input/output
     * 
     * @param dataBase64 Base64-encoded data
     * @param keyBase64 Base64-encoded key
     * @param algorithm HMAC algorithm to use
     * @return Base64-encoded HMAC result
     */
    @Throws(NoSuchAlgorithmException::class, InvalidKeyException::class)
    fun hmacBase64(dataBase64: String, keyBase64: String, algorithm: Algorithm): String {
        val dataBytes = CryptoUtils.decodeBase64(dataBase64)
        val keyBytes = CryptoUtils.decodeBase64(keyBase64)
        val hmacBytes = computeHmac(dataBytes, keyBytes, algorithm)
        return CryptoUtils.encodeBase64NoWrap(hmacBytes)
    }

    /**
     * Compute HMAC with UTF-8 string input
     * 
     * @param data UTF-8 string data
     * @param keyBase64 Base64-encoded key
     * @param algorithm HMAC algorithm to use
     * @return Base64-encoded HMAC result
     */
    @Throws(NoSuchAlgorithmException::class, InvalidKeyException::class)
    fun hmacStringBase64(data: String, keyBase64: String, algorithm: Algorithm): String {
        val dataBytes = CryptoUtils.stringToUtf8Bytes(data)
        val keyBytes = CryptoUtils.decodeBase64(keyBase64)
        val hmacBytes = computeHmac(dataBytes, keyBytes, algorithm)
        return CryptoUtils.encodeBase64NoWrap(hmacBytes)
    }

    /**
     * Get algorithm by name string
     * 
     * @param name Algorithm name (case-insensitive)
     * @return Algorithm enum value
     * @throws IllegalArgumentException if algorithm not supported
     */
    fun getAlgorithmByName(name: String): Algorithm {
        return when (name.uppercase()) {
            "SHA1", "HMACSHA1" -> Algorithm.HMAC_SHA1
            "SHA224", "HMACSHA224" -> Algorithm.HMAC_SHA224
            "SHA256", "HMACSHA256" -> Algorithm.HMAC_SHA256
            "SHA384", "HMACSHA384" -> Algorithm.HMAC_SHA384
            "SHA512", "HMACSHA512" -> Algorithm.HMAC_SHA512
            else -> throw IllegalArgumentException("Unsupported HMAC algorithm: $name")
        }
    }
}
