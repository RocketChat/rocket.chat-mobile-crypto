package chat.rocket.mobilecrypto.algorithms

import com.margelo.nitro.mobilecrypto.SHAAlgorithm

val SHAAlgorithm.digestName: String
    get() = when (this) {
        SHAAlgorithm.SHA_1 -> "SHA-1"
        SHAAlgorithm.SHA_256 -> "SHA-256"
        SHAAlgorithm.SHA_384 -> "SHA-384"
        SHAAlgorithm.SHA_512 -> "SHA-512"
    }
