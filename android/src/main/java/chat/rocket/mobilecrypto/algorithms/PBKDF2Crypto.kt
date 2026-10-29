package chat.rocket.mobilecrypto.algorithms

import com.margelo.nitro.mobilecrypto.PBKDF2HashAlgorithm
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter

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
}
