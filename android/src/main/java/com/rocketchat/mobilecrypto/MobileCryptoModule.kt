package com.rocketchat.mobilecrypto

import android.util.Base64
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.annotations.ReactModule
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.InvalidKeyException
import java.security.SecureRandom
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyFactory
import java.security.PublicKey
import java.security.PrivateKey
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.RSAPrivateKey
import java.security.spec.X509EncodedKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.StringWriter
import java.io.StringReader
import java.io.Reader
import java.util.UUID
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.IllegalBlockSizeException
import javax.crypto.BadPaddingException
import javax.crypto.NoSuchPaddingException
import com.facebook.react.bridge.WritableNativeMap
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReadableMap

import org.spongycastle.crypto.ExtendedDigest
import org.spongycastle.crypto.PBEParametersGenerator
import org.spongycastle.crypto.digests.SHA1Digest
import org.spongycastle.crypto.digests.SHA224Digest
import org.spongycastle.crypto.digests.SHA256Digest
import org.spongycastle.crypto.digests.SHA384Digest
import org.spongycastle.crypto.digests.SHA512Digest
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.spongycastle.crypto.params.KeyParameter
import org.spongycastle.asn1.ASN1InputStream
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo
import org.spongycastle.util.io.pem.PemObject
import org.spongycastle.util.io.pem.PemReader
import org.spongycastle.util.io.pem.PemWriter
import org.spongycastle.asn1.pkcs.PrivateKeyInfo
import org.spongycastle.asn1.ASN1Encodable
import org.spongycastle.asn1.ASN1Primitive

@ReactModule(name = MobileCryptoModule.NAME)
class MobileCryptoModule(reactContext: ReactApplicationContext) :
  NativeMobileCryptoSpec(reactContext) {

  override fun getName(): String {
    return NAME
  }



  private val algorithms = listOf("SHA-1", "SHA-256", "SHA-512")

  private fun sha(data: ByteArray, algorithm: String): ByteArray {
    if (!algorithms.contains(algorithm)) {
      throw Exception("Invalid algorithm")
    }
    
    val md = MessageDigest.getInstance(algorithm)
    md.update(data)
    return md.digest()
  }

  private fun bytesToHex(bytes: ByteArray): String {
    return bytes.joinToString("") { "%02x".format(it) }
  }

  private fun hexToBytes(hex: String): ByteArray {
    return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
  }

  override fun shaBase64(data: String, algorithm: String, promise: Promise) {
    try {
      val decodedData = Base64.decode(data, Base64.NO_WRAP)
      val digest = sha(decodedData, algorithm)
      val encodedResult = Base64.encodeToString(digest, Base64.NO_WRAP)
      promise.resolve(encodedResult)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun shaUtf8(data: String, algorithm: String, promise: Promise) {
    try {
      val digest = sha(data.toByteArray(StandardCharsets.UTF_8), algorithm)
      val hexResult = bytesToHex(digest)
      promise.resolve(hexResult)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  private fun pbkdf2(pwd: ByteArray, salt: ByteArray, iterations: Int, keyLen: Int, hash: String): ByteArray {
    val algMap = mapOf<String, ExtendedDigest>(
      "SHA1" to SHA1Digest(),
      "SHA224" to SHA224Digest(),
      "SHA256" to SHA256Digest(),
      "SHA384" to SHA384Digest(),
      "SHA512" to SHA512Digest()
    )
    
    val alg = algMap[hash] ?: throw NoSuchAlgorithmException("Specified hash algorithm is not supported")
    
    val gen: PBEParametersGenerator = PKCS5S2ParametersGenerator(alg)
    gen.init(pwd, salt, iterations)
    return (gen.generateDerivedParameters(keyLen * 8) as KeyParameter).key
  }

  override fun pbkdf2Hash(
    pwdBase64: String,
    saltBase64: String,
    iterations: Double,
    keyLen: Double,
    hash: String,
    promise: Promise
  ) {
    try {
      val pwdBytes = Base64.decode(pwdBase64, Base64.DEFAULT)
      val saltBytes = Base64.decode(saltBase64, Base64.DEFAULT)
      val digest = pbkdf2(pwdBytes, saltBytes, iterations.toInt(), keyLen.toInt(), hash)
      promise.resolve(Base64.encodeToString(digest, Base64.NO_WRAP))
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  private fun hmac256Internal(text: String, key: String): String {
    val contentData = hexToBytes(text)
    val keyData = hexToBytes(key)
    val mac = Mac.getInstance("HmacSHA256")
    val secretKey = SecretKeySpec(keyData, "HmacSHA256")
    mac.init(secretKey)
    return bytesToHex(mac.doFinal(contentData))
  }

  override fun hmac256(data: String, key: String, promise: Promise) {
    try {
      val result = hmac256Internal(data, key)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  // AES Constants
  private val cipherAlgorithm = "AES/CBC/PKCS7Padding"
  private val keyAlgorithm = "AES"
  private val fileCipherAlgorithm = "AES/CTR/NoPadding"
  private val bufferSize = 4096
  private val emptyIvSpec = IvParameterSpec(ByteArray(16) { 0 })

  private fun getInputStream(context: ReactApplicationContext, filePath: String): InputStream {
    val path = if (filePath.startsWith("file://")) filePath.substring(7) else filePath
    return FileInputStream(File(path))
  }

  private fun aesEncryptInternal(textBase64: String?, hexKey: String, hexIv: String?): String? {
    if (textBase64.isNullOrEmpty()) return null

    val key = hexToBytes(hexKey)
    val secretKey = SecretKeySpec(key, keyAlgorithm)

    val cipher = Cipher.getInstance(cipherAlgorithm)
    val ivSpec = if (hexIv == null) emptyIvSpec else IvParameterSpec(hexToBytes(hexIv))
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
    
    val encrypted = cipher.doFinal(Base64.decode(textBase64, Base64.DEFAULT))
    return Base64.encodeToString(encrypted, Base64.NO_WRAP)
  }

  private fun aesDecryptInternal(ciphertext: String?, hexKey: String, hexIv: String?): String? {
    if (ciphertext.isNullOrEmpty()) return null

    val key = hexToBytes(hexKey)
    val secretKey = SecretKeySpec(key, keyAlgorithm)

    val cipher = Cipher.getInstance(cipherAlgorithm)
    val ivSpec = if (hexIv == null) emptyIvSpec else IvParameterSpec(hexToBytes(hexIv))
    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
    
    val decrypted = cipher.doFinal(Base64.decode(ciphertext, Base64.DEFAULT))
    return Base64.encodeToString(decrypted, Base64.NO_WRAP)
  }

  private fun processFile(inputFile: String, base64UrlKey: String, base64Iv: String, mode: String): String {
    // Decode the key and IV
    val key = Base64.decode(base64UrlKey, Base64.URL_SAFE or Base64.NO_WRAP)
    val iv = Base64.decode(base64Iv, Base64.NO_WRAP)
    val secretKey = SecretKeySpec(key, "AES")

    // Initialize the cipher
    val cipher = Cipher.getInstance(fileCipherAlgorithm)
    val ivParameterSpec = IvParameterSpec(iv)
    val cipherMode = if (mode == "encrypt") Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE
    cipher.init(cipherMode, secretKey, ivParameterSpec)

    // Create a temporary output file in the cache directory
    val outputFileObj = File(reactApplicationContext.cacheDir, "processed_${UUID.randomUUID()}")

    try {
      getInputStream(reactApplicationContext, inputFile).use { inputStream ->
        FileOutputStream(outputFileObj).use { fos ->
          val buffer = ByteArray(bufferSize)
          var numBytesRead: Int
          
          while (inputStream.read(buffer).also { numBytesRead = it } != -1) {
            val output = cipher.update(buffer, 0, numBytesRead)
            output?.let { fos.write(it) }
          }
          
          val finalBytes = cipher.doFinal()
          finalBytes?.let { fos.write(it) }
        }
      }
    } catch (ex: Exception) {
      outputFileObj.delete()
      throw ex
    }

    return if (mode == "decrypt") {
      // Overwrite the input file with the decrypted file
      val targetPath = if (inputFile.startsWith("file://")) inputFile.substring(7) else inputFile
      FileInputStream(outputFileObj).use { inputStream ->
        FileOutputStream(targetPath).use { fos ->
          val buffer = ByteArray(bufferSize)
          var numBytesRead: Int
          
          while (inputStream.read(buffer).also { numBytesRead = it } != -1) {
            fos.write(buffer, 0, numBytesRead)
          }
        }
      }
      outputFileObj.delete()
      inputFile
    } else {
      "file://${outputFileObj.absolutePath}"
    }
  }

  override fun aesEncrypt(dataBase64: String, keyHex: String, ivHex: String, promise: Promise) {
    try {
      val result = aesEncryptInternal(dataBase64, keyHex, ivHex)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun aesDecrypt(dataBase64: String, keyHex: String, ivHex: String, promise: Promise) {
    try {
      val result = aesDecryptInternal(dataBase64, keyHex, ivHex)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun aesEncryptFile(filePath: String, base64UrlKey: String, base64Iv: String, promise: Promise) {
    try {
      val result = processFile(filePath, base64UrlKey, base64Iv, "encrypt")
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun aesDecryptFile(filePath: String, base64UrlKey: String, base64Iv: String, promise: Promise) {
    try {
      val result = processFile(filePath, base64UrlKey, base64Iv, "decrypt")
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun randomUuid(promise: Promise) {
    try {
      val result = UUID.randomUUID().toString()
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun randomKey(length: Double, promise: Promise) {
    try {
      val key = ByteArray(length.toInt())
      val rand = SecureRandom()
      rand.nextBytes(key)
      val keyHex = bytesToHex(key)
      promise.resolve(keyHex)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun randomBytes(size: Double, promise: Promise) {
    try {
      val bytes = ByteArray(size.toInt())
      val sr = SecureRandom()
      sr.nextBytes(bytes)
      val result = Base64.encodeToString(bytes, Base64.NO_WRAP)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  // RSA Helper Functions
  private fun getAlgorithmFromHash(hash: String?): String {
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

  override fun rsaGenerateKeys(keySize: Double?, promise: Promise) {
    try {
      val actualKeySize = keySize?.toInt() ?: 2048
      val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
      keyPairGenerator.initialize(actualKeySize)
      val keyPair = keyPairGenerator.generateKeyPair()
      
      val publicKeyBytes = keyPair.public.encoded
      val privateKeyBytes = keyPair.private.encoded
      
      val publicPem = keyToPem(publicKeyBytes, "PUBLIC KEY")
      val privatePem = keyToPem(privateKeyBytes, "PRIVATE KEY")
      
      val result = WritableNativeMap()
      result.putString("public", publicPem)
      result.putString("private", privatePem)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaEncrypt(message: String, publicKeyString: String, promise: Promise) {
    try {
      val publicKeyBytes = pemToKey(publicKeyString)
      val keySpec = X509EncodedKeySpec(publicKeyBytes)
      val keyFactory = KeyFactory.getInstance("RSA")
      val publicKey = keyFactory.generatePublic(keySpec)
      
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
      cipher.init(Cipher.ENCRYPT_MODE, publicKey)
      val encryptedBytes = cipher.doFinal(message.toByteArray(StandardCharsets.UTF_8))
      val result = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaEncrypt64(message: String, publicKeyString: String, promise: Promise) {
    try {
      val publicKeyBytes = pemToKey(publicKeyString)
      val keySpec = X509EncodedKeySpec(publicKeyBytes)
      val keyFactory = KeyFactory.getInstance("RSA")
      val publicKey = keyFactory.generatePublic(keySpec)
      
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
      cipher.init(Cipher.ENCRYPT_MODE, publicKey)
      val messageBytes = Base64.decode(message, Base64.DEFAULT)
      val encryptedBytes = cipher.doFinal(messageBytes)
      val result = Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaDecrypt(encodedMessage: String, privateKeyString: String, promise: Promise) {
    try {
      val privateKeyBytes = pemToKey(privateKeyString)
      val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
      val keyFactory = KeyFactory.getInstance("RSA")
      val privateKey = keyFactory.generatePrivate(keySpec)
      
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
      cipher.init(Cipher.DECRYPT_MODE, privateKey)
      val encryptedBytes = Base64.decode(encodedMessage, Base64.DEFAULT)
      val decryptedBytes = cipher.doFinal(encryptedBytes)
      val result = String(decryptedBytes, StandardCharsets.UTF_8)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaDecrypt64(encodedMessage: String, privateKeyString: String, promise: Promise) {
    try {
      val privateKeyBytes = pemToKey(privateKeyString)
      val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
      val keyFactory = KeyFactory.getInstance("RSA")
      val privateKey = keyFactory.generatePrivate(keySpec)
      
      val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
      cipher.init(Cipher.DECRYPT_MODE, privateKey)
      val encryptedBytes = Base64.decode(encodedMessage, Base64.DEFAULT)
      val decryptedBytes = cipher.doFinal(encryptedBytes)
      val result = Base64.encodeToString(decryptedBytes, Base64.DEFAULT)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaSign(message: String, privateKeyString: String, hash: String?, promise: Promise) {
    try {
      val privateKeyBytes = pemToKey(privateKeyString)
      val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
      val keyFactory = KeyFactory.getInstance("RSA")
      val privateKey = keyFactory.generatePrivate(keySpec)
      
      val signature = Signature.getInstance(getAlgorithmFromHash(hash))
      signature.initSign(privateKey)
      signature.update(message.toByteArray(StandardCharsets.UTF_8))
      val signatureBytes = signature.sign()
      val result = Base64.encodeToString(signatureBytes, Base64.DEFAULT)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaSign64(message: String, privateKeyString: String, hash: String?, promise: Promise) {
    try {
      val privateKeyBytes = pemToKey(privateKeyString)
      val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
      val keyFactory = KeyFactory.getInstance("RSA")
      val privateKey = keyFactory.generatePrivate(keySpec)
      
      val signature = Signature.getInstance(getAlgorithmFromHash(hash))
      signature.initSign(privateKey)
      val messageBytes = Base64.decode(message, Base64.DEFAULT)
      signature.update(messageBytes)
      val signatureBytes = signature.sign()
      val result = Base64.encodeToString(signatureBytes, Base64.DEFAULT)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaVerify(signatureString: String, message: String, publicKeyString: String, hash: String?, promise: Promise) {
    try {
      val publicKeyBytes = pemToKey(publicKeyString)
      val keySpec = X509EncodedKeySpec(publicKeyBytes)
      val keyFactory = KeyFactory.getInstance("RSA")
      val publicKey = keyFactory.generatePublic(keySpec)
      
      val signature = Signature.getInstance(getAlgorithmFromHash(hash))
      signature.initVerify(publicKey)
      signature.update(message.toByteArray(StandardCharsets.UTF_8))
      val signatureBytes = Base64.decode(signatureString, Base64.DEFAULT)
      val result = signature.verify(signatureBytes)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaVerify64(signatureString: String, message: String, publicKeyString: String, hash: String?, promise: Promise) {
    try {
      val publicKeyBytes = pemToKey(publicKeyString)
      val keySpec = X509EncodedKeySpec(publicKeyBytes)
      val keyFactory = KeyFactory.getInstance("RSA")
      val publicKey = keyFactory.generatePublic(keySpec)
      
      val signature = Signature.getInstance(getAlgorithmFromHash(hash))
      signature.initVerify(publicKey)
      val messageBytes = Base64.decode(message, Base64.DEFAULT)
      signature.update(messageBytes)
      val signatureBytes = Base64.decode(signatureString, Base64.DEFAULT)
      val result = signature.verify(signatureBytes)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun calculateFileChecksum(filePath: String, promise: Promise) {
    try {
      val file = if (filePath.startsWith("file://")) {
        File(filePath.substring(7))
      } else {
        File(filePath)
      }
      
      val inputStream = FileInputStream(file)
      val digest = MessageDigest.getInstance("SHA-256")
      val buffer = ByteArray(4096)
      var bytesRead: Int
      
      while (inputStream.read(buffer).also { bytesRead = it } != -1) {
        digest.update(buffer, 0, bytesRead)
      }
      inputStream.close()
      
      val hash = digest.digest()
      val result = bytesToHex(hash)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun getRandomValues(length: Double, promise: Promise) {
    try {
      val alphanumericChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
      val random = SecureRandom()
      val result = (1..length.toInt())
        .map { alphanumericChars[random.nextInt(alphanumericChars.length)] }
        .joinToString("")
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  // RSA Key Format Conversion Methods
  override fun rsaImportKey(jwk: ReadableMap, promise: Promise) {
    try {
      val isPrivate = jwk.hasKey("d")
      
      val pkcs1 = if (isPrivate) {
        jwkToPrivatePkcs1(jwk)
      } else {
        jwkToPublicPkcs1(jwk)
      }
      
      promise.resolve(pkcs1)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaExportKey(pem: String, promise: Promise) {
    try {
      val keyData = pemToData(pem)
      val isPublic = pem.contains("PUBLIC")
      val isRsaPkcs1 = pem.contains("RSA")

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

      promise.resolve(jwk)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  // Helper methods for RSA key conversions
  private fun jwkToPublicPkcs1(jwk: ReadableMap): String {
    try {
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
    } catch (e: Exception) {
      throw Exception("Failed to convert JWK to public PKCS1: ${e.message}", e)
    }
  }

  private fun jwkToPrivatePkcs1(jwk: ReadableMap): String {
    try {
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
    } catch (e: Exception) {
      throw Exception("Failed to convert JWK to private PKCS1: ${e.message}", e)
    }
  }

  private fun pkcs1ToPublicKey(obj: ASN1Primitive): WritableMap {
    try {
      val keyStruct = org.spongycastle.asn1.pkcs.RSAPublicKey.getInstance(obj)

      val jwk = Arguments.createMap()
      jwk.putString("n", toBase64String(keyStruct.modulus, true))
      jwk.putString("e", toBase64String(keyStruct.publicExponent, false))

      return jwk
    } catch (e: Exception) {
      throw Exception("Failed to parse PKCS1 public key: ${e.message}. ASN1 object type: ${obj.javaClass.simpleName}", e)
    }
  }

  private fun pkcs1ToPrivateKey(obj: ASN1Primitive): WritableMap {
    try {
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
    } catch (e: Exception) {
      throw Exception("Failed to parse PKCS1 private key: ${e.message}. ASN1 object type: ${obj.javaClass.simpleName}", e)
    }
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

  private fun pemToData(pemKey: String): ByteArray {
    val keyReader: Reader = StringReader(pemKey)
    val pemReader = PemReader(keyReader)
    val pemObject = pemReader.readPemObject()
    return pemObject.content
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

  companion object {
    const val NAME = "MobileCrypto"
  }
}
