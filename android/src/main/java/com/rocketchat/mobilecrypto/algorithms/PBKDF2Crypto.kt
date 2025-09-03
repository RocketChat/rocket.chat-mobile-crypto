package com.rocketchat.mobilecrypto.algorithms

import java.security.NoSuchAlgorithmException
import org.spongycastle.crypto.ExtendedDigest
import org.spongycastle.crypto.PBEParametersGenerator
import org.spongycastle.crypto.digests.SHA1Digest
import org.spongycastle.crypto.digests.SHA224Digest
import org.spongycastle.crypto.digests.SHA256Digest
import org.spongycastle.crypto.digests.SHA384Digest
import org.spongycastle.crypto.digests.SHA512Digest
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.spongycastle.crypto.params.KeyParameter

/**
 * PBKDF2 (Password-Based Key Derivation Function 2) operations
 */
object PBKDF2Crypto {

    private val algorithmMap = mapOf<String, ExtendedDigest>(
        "SHA1" to SHA1Digest(),
        "SHA224" to SHA224Digest(),
        "SHA256" to SHA256Digest(),
        "SHA384" to SHA384Digest(),
        "SHA512" to SHA512Digest()
    )

    /**
     * Derive a key using PBKDF2 with specified parameters
     * 
     * @param password Password bytes
     * @param salt Salt bytes
     * @param iterations Number of iterations
     * @param keyLength Desired key length in bytes
     * @param hashAlgorithm Hash algorithm (SHA1, SHA224, SHA256, SHA384, SHA512)
     * @return Derived key bytes
     */
    fun deriveKey(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        keyLength: Int,
        hashAlgorithm: String
    ): ByteArray {
        val digest = algorithmMap[hashAlgorithm] 
            ?: throw NoSuchAlgorithmException("Specified hash algorithm '$hashAlgorithm' is not supported")
        
        val generator: PBEParametersGenerator = PKCS5S2ParametersGenerator(digest)
        generator.init(password, salt, iterations)
        return (generator.generateDerivedParameters(keyLength * 8) as KeyParameter).key
    }

    /**
     * Derive a key using PBKDF2 with Base64-encoded inputs
     * 
     * @param passwordBase64 Base64-encoded password
     * @param saltBase64 Base64-encoded salt
     * @param iterations Number of iterations
     * @param keyLength Desired key length in bytes
     * @param hashAlgorithm Hash algorithm (SHA1, SHA224, SHA256, SHA384, SHA512)
     * @return Base64-encoded derived key
     */
    fun deriveKeyBase64(
        passwordBase64: String,
        saltBase64: String,
        iterations: Int,
        keyLength: Int,
        hashAlgorithm: String
    ): String {
        val passwordBytes = CryptoUtils.decodeBase64(passwordBase64)
        val saltBytes = CryptoUtils.decodeBase64(saltBase64)
        val derivedKey = deriveKey(passwordBytes, saltBytes, iterations, keyLength, hashAlgorithm)
        return CryptoUtils.encodeBase64NoWrap(derivedKey)
    }

    /**
     * Get list of supported hash algorithms
     */
    fun getSupportedAlgorithms(): List<String> {
        return algorithmMap.keys.toList()
    }
}
