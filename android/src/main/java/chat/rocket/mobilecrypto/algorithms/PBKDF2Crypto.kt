package chat.rocket.mobilecrypto.algorithms

import com.margelo.nitro.mobilecrypto.PBKDF2HashAlgorithm
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter

/**
 * PBKDF2 (Password-Based Key Derivation Function 2) operations
 */
object PBKDF2Crypto {

    fun deriveKey(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        keyLength: Int,
        hashAlgorithm: PBKDF2HashAlgorithm
    ): ByteArray {
        val generator = PKCS5S2ParametersGenerator(hashAlgorithm.createDigest())
        generator.init(password, salt, iterations)
        return (generator.generateDerivedParameters(keyLength * 8) as KeyParameter).key
    }

    fun deriveKeyBase64(
        passwordBase64: String,
        saltBase64: String,
        iterations: Int,
        keyLength: Int,
        hashAlgorithm: PBKDF2HashAlgorithm
    ): String {
        val passwordBytes = CryptoUtils.decodeBase64(passwordBase64)
        val saltBytes = CryptoUtils.decodeBase64(saltBase64)
        val derivedKey = deriveKey(passwordBytes, saltBytes, iterations, keyLength, hashAlgorithm)
        return CryptoUtils.encodeBase64NoWrap(derivedKey)
    }
}
