package chat.rocket.mobilecrypto.algorithms

import android.util.Base64
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.WritableNativeMap
import java.io.StringReader
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays
import javax.crypto.Cipher
import org.spongycastle.asn1.ASN1InputStream
import org.spongycastle.asn1.ASN1Primitive
import org.spongycastle.asn1.pkcs.PrivateKeyInfo
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo
import org.spongycastle.util.io.pem.PemObject
import org.spongycastle.util.io.pem.PemReader
import org.spongycastle.util.io.pem.PemWriter

/**
 * RSA encryption, decryption, signing and key format conversion operations
 */
object RSACrypto {

    /**
     * Generate RSA key pair
     * 
     * @param keySize Key size in bits (default: 2048)
     * @return Map containing PEM-formatted public and private keys
     */
    fun generateKeyPair(keySize: Int = 2048): WritableMap {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize)
        val keyPair = keyPairGenerator.generateKeyPair()
        
        val publicKeyBytes = keyPair.public.encoded
        val privateKeyBytes = keyPair.private.encoded
        
        val publicPem = keyToPem(publicKeyBytes, "PUBLIC KEY")
        val privatePem = keyToPem(privateKeyBytes, "PRIVATE KEY")
        
        val result = WritableNativeMap()
        result.putString("public", publicPem)
        result.putString("private", privatePem)
        return result
    }

    /**
     * Encrypt message with RSA public key
     * 
     * @param message Plain text message
     * @param publicKeyPem PEM-formatted public key
     * @return Base64-encoded encrypted data
     */
    fun encrypt(message: String, publicKeyPem: String): String {
        val publicKeyBytes = pemToKey(publicKeyPem)
        val keySpec = X509EncodedKeySpec(publicKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        val publicKey = keyFactory.generatePublic(keySpec)
        
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(CryptoUtils.stringToUtf8Bytes(message))
        return CryptoUtils.encodeBase64NoWrap(encryptedBytes)
    }

    /**
     * Encrypt Base64-encoded message with RSA public key
     * 
     * @param messageBase64 Base64-encoded message
     * @param publicKeyPem PEM-formatted public key
     * @return Base64-encoded encrypted data
     */
    fun encryptBase64(messageBase64: String, publicKeyPem: String): String {
        val publicKeyBytes = pemToKey(publicKeyPem)
        val keySpec = X509EncodedKeySpec(publicKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        val publicKey = keyFactory.generatePublic(keySpec)
        
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val messageBytes = CryptoUtils.decodeBase64(messageBase64)
        val encryptedBytes = cipher.doFinal(messageBytes)
        return CryptoUtils.encodeBase64NoWrap(encryptedBytes)
    }

    /**
     * Decrypt message with RSA private key
     * 
     * @param encryptedMessage Base64-encoded encrypted message
     * @param privateKeyPem PEM-formatted private key
     * @return Plain text message
     */
    fun decrypt(encryptedMessage: String, privateKeyPem: String): String {
        val privateKeyBytes = pemToKey(privateKeyPem)
        val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        val privateKey = keyFactory.generatePrivate(keySpec)
        
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val encryptedBytes = CryptoUtils.decodeBase64(encryptedMessage)
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return CryptoUtils.utf8BytesToString(decryptedBytes)
    }

    /**
     * Decrypt message with RSA private key, return Base64
     * 
     * @param encryptedMessage Base64-encoded encrypted message
     * @param privateKeyPem PEM-formatted private key
     * @return Base64-encoded decrypted data
     */
    fun decryptToBase64(encryptedMessage: String, privateKeyPem: String): String {
        val privateKeyBytes = pemToKey(privateKeyPem)
        val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        val privateKey = keyFactory.generatePrivate(keySpec)
        
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val encryptedBytes = CryptoUtils.decodeBase64(encryptedMessage)
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return CryptoUtils.encodeBase64NoWrap(decryptedBytes)
    }

    /**
     * Sign message with RSA private key
     * 
     * @param message Message to sign
     * @param privateKeyPem PEM-formatted private key
     * @param hashAlgorithm Hash algorithm (default: SHA1)
     * @return Base64-encoded signature
     */
    fun sign(message: String, privateKeyPem: String, hashAlgorithm: String? = null): String {
        val privateKeyBytes = pemToKey(privateKeyPem)
        val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        val privateKey = keyFactory.generatePrivate(keySpec)
        
        val signature = Signature.getInstance(getSignatureAlgorithm(hashAlgorithm))
        signature.initSign(privateKey)
        signature.update(CryptoUtils.stringToUtf8Bytes(message))
        val signatureBytes = signature.sign()
        return CryptoUtils.encodeBase64NoWrap(signatureBytes)
    }

    /**
     * Sign Base64-encoded message with RSA private key
     * 
     * @param messageBase64 Base64-encoded message to sign
     * @param privateKeyPem PEM-formatted private key
     * @param hashAlgorithm Hash algorithm (default: SHA1)
     * @return Base64-encoded signature
     */
    fun signBase64(messageBase64: String, privateKeyPem: String, hashAlgorithm: String? = null): String {
        val privateKeyBytes = pemToKey(privateKeyPem)
        val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        val privateKey = keyFactory.generatePrivate(keySpec)
        
        val signature = Signature.getInstance(getSignatureAlgorithm(hashAlgorithm))
        signature.initSign(privateKey)
        val messageBytes = CryptoUtils.decodeBase64(messageBase64)
        signature.update(messageBytes)
        val signatureBytes = signature.sign()
        return CryptoUtils.encodeBase64NoWrap(signatureBytes)
    }

    /**
     * Verify signature with RSA public key
     * 
     * @param signatureBase64 Base64-encoded signature
     * @param message Original message
     * @param publicKeyPem PEM-formatted public key
     * @param hashAlgorithm Hash algorithm (default: SHA1)
     * @return True if signature is valid
     */
    fun verify(signatureBase64: String, message: String, publicKeyPem: String, hashAlgorithm: String? = null): Boolean {
        val publicKeyBytes = pemToKey(publicKeyPem)
        val keySpec = X509EncodedKeySpec(publicKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        val publicKey = keyFactory.generatePublic(keySpec)
        
        val signature = Signature.getInstance(getSignatureAlgorithm(hashAlgorithm))
        signature.initVerify(publicKey)
        signature.update(CryptoUtils.stringToUtf8Bytes(message))
        val signatureBytes = CryptoUtils.decodeBase64(signatureBase64)
        return signature.verify(signatureBytes)
    }

    /**
     * Verify signature with RSA public key for Base64-encoded message
     * 
     * @param signatureBase64 Base64-encoded signature
     * @param messageBase64 Base64-encoded original message
     * @param publicKeyPem PEM-formatted public key
     * @param hashAlgorithm Hash algorithm (default: SHA1)
     * @return True if signature is valid
     */
    fun verifyBase64(signatureBase64: String, messageBase64: String, publicKeyPem: String, hashAlgorithm: String? = null): Boolean {
        val publicKeyBytes = pemToKey(publicKeyPem)
        val keySpec = X509EncodedKeySpec(publicKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        val publicKey = keyFactory.generatePublic(keySpec)
        
        val signature = Signature.getInstance(getSignatureAlgorithm(hashAlgorithm))
        signature.initVerify(publicKey)
        val messageBytes = CryptoUtils.decodeBase64(messageBase64)
        signature.update(messageBytes)
        val signatureBytes = CryptoUtils.decodeBase64(signatureBase64)
        return signature.verify(signatureBytes)
    }

    /**
     * Import JWK format key to PEM format
     * 
     * @param jwk JWK key data
     * @return PEM-formatted key
     */
    fun importJwkKey(jwk: ReadableMap): String {
        val isPrivate = jwk.hasKey("d")
        
        return if (isPrivate) {
            jwkToPrivatePkcs1(jwk)
        } else {
            jwkToPublicPkcs1(jwk)
        }
    }

    /**
     * Export PEM key to JWK format
     * 
     * @param pemKey PEM-formatted key
     * @return JWK key data
     */
    fun exportPemKey(pemKey: String): WritableMap {
        val keyData = pemToData(pemKey)
        val isPublic = pemKey.contains("PUBLIC")
        val isRsaPkcs1 = pemKey.contains("RSA")

        val jwk = if (isPublic) {
            if (isRsaPkcs1) {
                // PKCS#1 RSA PUBLIC KEY format
                val inputStream = ASN1InputStream(keyData)
                val obj = inputStream.readObject()
                pkcs1ToPublicKey(obj)
            } else {
                // X.509 SubjectPublicKeyInfo format
                val spkInfo = SubjectPublicKeyInfo.getInstance(keyData)
                val primitive = spkInfo.parsePublicKey()
                pkcs1ToPublicKey(primitive)
            }
        } else {
            if (isRsaPkcs1) {
                // PKCS#1 RSA PRIVATE KEY format
                val inputStream = ASN1InputStream(keyData)
                val obj = inputStream.readObject()
                pkcs1ToPrivateKey(obj)
            } else {
                // PKCS#8 PrivateKeyInfo format
                val pkInfo = PrivateKeyInfo.getInstance(keyData)
                val primitive = pkInfo.parsePrivateKey().toASN1Primitive()
                pkcs1ToPrivateKey(primitive)
            }
        }
        
        jwk.putString("kty", "RSA")
        jwk.putString("alg", "RSA-OAEP-256")
        jwk.putBoolean("ext", true)

        val keyOps = Arguments.createArray()
        if (isPublic) {
            keyOps.pushString("encrypt")
        } else {
            keyOps.pushString("decrypt")
        }
        jwk.putArray("key_ops", keyOps)

        return jwk
    }

    // Private helper methods

    private fun getSignatureAlgorithm(hash: String?): String {
        return when (hash ?: "SHA1") {
            "Raw" -> "NONEwithRSA"
            "SHA1" -> "SHA1withRSA"
            "SHA224" -> "SHA224withRSA"
            "SHA256" -> "SHA256withRSA"
            "SHA384" -> "SHA384withRSA"
            else -> "SHA1withRSA"
        }
    }

    private fun keyToPem(key: ByteArray, header: String): String {
        val base64Key = Base64.encodeToString(key, Base64.DEFAULT)
        val lines = base64Key.chunked(64)
        return buildString {
            appendLine("-----BEGIN $header-----")
            lines.forEach { appendLine(it) }
            appendLine("-----END $header-----")
        }
    }

    private fun pemToKey(pem: String): ByteArray {
        val lines = pem.lines().filter { 
            !it.startsWith("-----") && it.isNotBlank() 
        }
        val base64Content = lines.joinToString("")
        return Base64.decode(base64Content, Base64.DEFAULT)
    }

    private fun pemToData(pemKey: String): ByteArray {
        val keyReader = StringReader(pemKey)
        val pemReader = PemReader(keyReader)
        val pemObject = pemReader.readPemObject()
        return pemObject.content
    }

    private fun jwkToPublicPkcs1(jwk: ReadableMap): String {
        val nStr = jwk.getString("n") ?: throw Exception("Missing 'n' parameter")
        val eStr = jwk.getString("e") ?: throw Exception("Missing 'e' parameter")
        
        // Decode and validate parameters
        val modulusBytes = decodeSequence(nStr)
        val exponentBytes = decodeSequence(eStr)
        
        if (modulusBytes.isEmpty()) throw Exception("Empty modulus bytes")
        if (exponentBytes.isEmpty()) throw Exception("Empty exponent bytes")
        
        val modulus = toBigInteger(modulusBytes)
        val publicExponent = toBigInteger(exponentBytes)
        
        // Validate that modulus and exponent are positive
        if (modulus <= BigInteger.ZERO) throw Exception("Invalid modulus: must be positive")
        if (publicExponent <= BigInteger.ZERO) throw Exception("Invalid public exponent: must be positive")
        
        // Validate common RSA constraints
        if (modulus.bitLength() < 512) throw Exception("RSA modulus too small: ${modulus.bitLength()} bits")
        if (publicExponent < BigInteger.valueOf(3)) throw Exception("Public exponent too small")

        val factory = KeyFactory.getInstance("RSA")
        val keySpec = RSAPublicKeySpec(modulus, publicExponent)
        val key = factory.generatePublic(keySpec)

        val pemObject = PemObject("RSA PUBLIC KEY", publicKeyToPkcs1(key))
        val stringWriter = StringWriter()
        val pemWriter = PemWriter(stringWriter)
        pemWriter.writeObject(pemObject)
        pemWriter.close()

        return stringWriter.toString()
    }

    private fun jwkToPrivatePkcs1(jwk: ReadableMap): String {
        val nStr = jwk.getString("n") ?: throw Exception("Missing 'n' parameter")
        val eStr = jwk.getString("e") ?: throw Exception("Missing 'e' parameter")
        val dStr = jwk.getString("d") ?: throw Exception("Missing 'd' parameter")
        val pStr = jwk.getString("p") ?: throw Exception("Missing 'p' parameter")
        val qStr = jwk.getString("q") ?: throw Exception("Missing 'q' parameter")
        val dpStr = jwk.getString("dp") ?: throw Exception("Missing 'dp' parameter")
        val dqStr = jwk.getString("dq") ?: throw Exception("Missing 'dq' parameter")
        val qiStr = jwk.getString("qi") ?: throw Exception("Missing 'qi' parameter")

        val modulus = toBigInteger(decodeSequence(nStr))
        val publicExponent = toBigInteger(decodeSequence(eStr))
        val privateExponent = toBigInteger(decodeSequence(dStr))
        val primeP = toBigInteger(decodeSequence(pStr))
        val primeQ = toBigInteger(decodeSequence(qStr))
        val primeExpP = toBigInteger(decodeSequence(dpStr))
        val primeExpQ = toBigInteger(decodeSequence(dqStr))
        val crtCoefficient = toBigInteger(decodeSequence(qiStr))

        val factory = KeyFactory.getInstance("RSA")
        val key = factory.generatePrivate(RSAPrivateCrtKeySpec(
            modulus,
            publicExponent,
            privateExponent,
            primeP,
            primeQ,
            primeExpP,
            primeExpQ,
            crtCoefficient
        )) as RSAPrivateKey

        val pemObject = PemObject("RSA PRIVATE KEY", privateKeyToPkcs1(key))
        val stringWriter = StringWriter()
        val pemWriter = PemWriter(stringWriter)
        pemWriter.writeObject(pemObject)
        pemWriter.close()

        return stringWriter.toString()
    }

    private fun pkcs1ToPublicKey(obj: ASN1Primitive): WritableMap {
        val keyStruct = org.spongycastle.asn1.pkcs.RSAPublicKey.getInstance(obj)

        val jwk = Arguments.createMap()
        jwk.putString("n", toBase64String(keyStruct.modulus, true))
        jwk.putString("e", toBase64String(keyStruct.publicExponent, false))

        return jwk
    }

    private fun pkcs1ToPrivateKey(obj: ASN1Primitive): WritableMap {
        val keyStruct = org.spongycastle.asn1.pkcs.RSAPrivateKey.getInstance(obj)

        val jwk = Arguments.createMap()
        jwk.putString("n", toBase64String(keyStruct.modulus, true))
        jwk.putString("e", toBase64String(keyStruct.publicExponent, true))
        jwk.putString("d", toBase64String(keyStruct.privateExponent, true))
        jwk.putString("p", toBase64String(keyStruct.prime1, true))
        jwk.putString("q", toBase64String(keyStruct.prime2, true))
        jwk.putString("dp", toBase64String(keyStruct.exponent1, true))
        jwk.putString("dq", toBase64String(keyStruct.exponent2, true))
        jwk.putString("qi", toBase64String(keyStruct.coefficient, true))

        return jwk
    }

    private fun publicKeyToPkcs1(publicKey: PublicKey): ByteArray {
        val spkInfo = SubjectPublicKeyInfo.getInstance(publicKey.encoded)
        val primitive = spkInfo.parsePublicKey()
        return primitive.encoded
    }

    private fun privateKeyToPkcs1(privateKey: PrivateKey): ByteArray {
        val pkInfo = PrivateKeyInfo.getInstance(privateKey.encoded)
        val encodeable = pkInfo.parsePrivateKey()
        val primitive = encodeable.toASN1Primitive()
        return primitive.encoded
    }

    private fun toBase64String(bigInteger: BigInteger, positive: Boolean): String {
        var array = bigInteger.toByteArray()
        if (positive && array[0] == 0.toByte()) {
            array = Arrays.copyOfRange(array, 1, array.size)
        }
        return Base64.encodeToString(array, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    private fun toBigInteger(bytes: ByteArray): BigInteger {
        return BigInteger(1, bytes)
    }

    private fun decodeSequence(encodedSequence: String): ByteArray {
        return try {
            Base64.decode(encodedSequence, Base64.URL_SAFE)
        } catch (e: Exception) {
            // Try with standard Base64 if URL_SAFE fails
            try {
                Base64.decode(encodedSequence, Base64.DEFAULT)
            } catch (e2: Exception) {
                throw Exception("Failed to decode Base64 sequence: $encodedSequence", e2)
            }
        }
    }
}
