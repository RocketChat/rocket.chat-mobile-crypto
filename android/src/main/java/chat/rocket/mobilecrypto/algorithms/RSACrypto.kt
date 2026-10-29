package chat.rocket.mobilecrypto.algorithms

import com.margelo.nitro.mobilecrypto.RSAHashAlgorithm
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.Cipher
import org.json.JSONObject

object RSACrypto {

    private const val KEY_ALGORITHM = "RSA"
    private const val CIPHER_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    private const val JWK_HEADER_PREFIX = "{\"kty\":\"RSA\",\"alg\":\"RSA-OAEP-256\",\"ext\":true,\"key_ops\":"

    fun generateKeyPair(keySize: Int): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM)
        keyPairGenerator.initialize(keySize)
        return keyPairGenerator.generateKeyPair()
    }

    fun encrypt(plaintext: String, publicKey: PublicKey): String {
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return CryptoUtils.encodeBase64(cipher.doFinal(CryptoUtils.encodeUtf8(plaintext)))
    }

    fun decrypt(ciphertext: String, privateKey: PrivateKey): String {
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return CryptoUtils.decodeUtf8(cipher.doFinal(CryptoUtils.decodeBase64(ciphertext)))
    }

    fun sign(message: ByteArray, privateKey: PrivateKey, hash: RSAHashAlgorithm): ByteArray {
        val signature = Signature.getInstance(hash.signatureAlgorithm)
        signature.initSign(privateKey)
        signature.update(message)
        return signature.sign()
    }

    fun verify(signatureBytes: ByteArray, message: ByteArray, publicKey: PublicKey, hash: RSAHashAlgorithm): Boolean {
        val signature = Signature.getInstance(hash.signatureAlgorithm)
        signature.initVerify(publicKey)
        signature.update(message)
        return signature.verify(signatureBytes)
    }

    fun importPrivateKey(jwkJson: String): RSAPrivateCrtKey {
        val jwk = parseRsaJwk(jwkJson)
        val keySpec = RSAPrivateCrtKeySpec(
            jwkComponent(jwk, "n"),
            jwkComponent(jwk, "e"),
            jwkComponent(jwk, "d"),
            jwkComponent(jwk, "p"),
            jwkComponent(jwk, "q"),
            jwkComponent(jwk, "dp"),
            jwkComponent(jwk, "dq"),
            jwkComponent(jwk, "qi")
        )
        return KeyFactory.getInstance(KEY_ALGORITHM).generatePrivate(keySpec) as RSAPrivateCrtKey
    }

    fun importPublicKey(jwkJson: String): RSAPublicKey {
        val jwk = parseRsaJwk(jwkJson)
        val keySpec = RSAPublicKeySpec(jwkComponent(jwk, "n"), jwkComponent(jwk, "e"))
        return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(keySpec) as RSAPublicKey
    }

    fun exportJwk(privateKey: RSAPrivateCrtKey): String {
        return buildJwk(
            "decrypt",
            listOf(
                "n" to privateKey.modulus,
                "e" to privateKey.publicExponent,
                "d" to privateKey.privateExponent,
                "p" to privateKey.primeP,
                "q" to privateKey.primeQ,
                "dp" to privateKey.primeExponentP,
                "dq" to privateKey.primeExponentQ,
                "qi" to privateKey.crtCoefficient
            )
        )
    }

    fun exportJwk(publicKey: RSAPublicKey): String {
        return buildJwk(
            "encrypt",
            listOf(
                "n" to publicKey.modulus,
                "e" to publicKey.publicExponent
            )
        )
    }

    private fun parseRsaJwk(jwkJson: String): JSONObject {
        val jwk = JSONObject(jwkJson)
        val keyType = jwk.getString("kty")
        require(keyType == "RSA") { "JWK kty must be RSA, got $keyType" }
        return jwk
    }

    private fun jwkComponent(jwk: JSONObject, name: String): BigInteger {
        val bytes = CryptoUtils.decodeBase64Url(jwk.getString(name))
        require(bytes.isNotEmpty()) { "JWK component '$name' is empty" }
        return BigInteger(1, bytes)
    }

    private fun buildJwk(keyOperation: String, components: List<Pair<String, BigInteger>>): String {
        return buildString {
            append(JWK_HEADER_PREFIX)
            append("[\"").append(keyOperation).append("\"]")
            components.forEach { (name, value) ->
                append(",\"").append(name).append("\":\"").append(encodeUnsigned(value)).append('"')
            }
            append('}')
        }
    }

    private fun encodeUnsigned(value: BigInteger): String {
        val signedBytes = value.toByteArray()
        val unsignedBytes = if (signedBytes.size > 1 && signedBytes[0] == 0.toByte()) {
            signedBytes.copyOfRange(1, signedBytes.size)
        } else {
            signedBytes
        }
        return CryptoUtils.encodeBase64Url(unsignedBytes)
    }
}
