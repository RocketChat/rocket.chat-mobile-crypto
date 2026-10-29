package chat.rocket.mobilecrypto.algorithms

import com.margelo.nitro.mobilecrypto.RSAHashAlgorithm

val RSAHashAlgorithm.signatureAlgorithm: String
    get() = when (this) {
        RSAHashAlgorithm.RAW -> "NONEwithRSA"
        RSAHashAlgorithm.SHA1 -> "SHA1withRSA"
        RSAHashAlgorithm.SHA224 -> "SHA224withRSA"
        RSAHashAlgorithm.SHA256 -> "SHA256withRSA"
        RSAHashAlgorithm.SHA384 -> "SHA384withRSA"
        RSAHashAlgorithm.SHA512 -> "SHA512withRSA"
    }
