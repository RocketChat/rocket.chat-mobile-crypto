package chat.rocket.mobilecrypto.algorithms

import com.margelo.nitro.mobilecrypto.PBKDF2HashAlgorithm
import org.bouncycastle.crypto.ExtendedDigest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA224Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest

fun PBKDF2HashAlgorithm.createDigest(): ExtendedDigest =
    when (this) {
        PBKDF2HashAlgorithm.SHA1 -> SHA1Digest()
        PBKDF2HashAlgorithm.SHA224 -> SHA224Digest()
        PBKDF2HashAlgorithm.SHA256 -> SHA256Digest()
        PBKDF2HashAlgorithm.SHA384 -> SHA384Digest()
        PBKDF2HashAlgorithm.SHA512 -> SHA512Digest()
    }
