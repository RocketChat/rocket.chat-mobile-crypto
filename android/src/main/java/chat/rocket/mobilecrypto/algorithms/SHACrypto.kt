package chat.rocket.mobilecrypto.algorithms

import com.margelo.nitro.mobilecrypto.SHAAlgorithm
import java.security.MessageDigest

internal object SHACrypto {

    fun computeHash(data: ByteArray, algorithm: SHAAlgorithm): ByteArray {
        return MessageDigest.getInstance(algorithm.digestName).digest(data)
    }
}
