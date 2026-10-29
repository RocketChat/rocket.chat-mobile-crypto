package com.margelo.nitro.mobilecrypto

import android.content.Context
import androidx.annotation.Keep
import chat.rocket.mobilecrypto.algorithms.AESCrypto
import chat.rocket.mobilecrypto.algorithms.FileUtils
import chat.rocket.mobilecrypto.algorithms.HMACCrypto
import chat.rocket.mobilecrypto.algorithms.PBKDF2Crypto
import chat.rocket.mobilecrypto.algorithms.RSACrypto
import chat.rocket.mobilecrypto.algorithms.RandomUtils
import chat.rocket.mobilecrypto.algorithms.SHACrypto
import com.facebook.proguard.annotations.DoNotStrip
import com.margelo.nitro.NitroModules
import com.margelo.nitro.core.ArrayBuffer
import com.margelo.nitro.core.Promise
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers

@Keep
@DoNotStrip
class HybridMobileCrypto : HybridMobileCryptoSpec() {
  private val context: Context
    get() = NitroModules.applicationContext ?: throw Error("No ApplicationContext set!")

  override fun shaBase64(data: String, algorithm: SHAAlgorithm): Promise<String> =
    Promise.async { shaBase64Sync(data, algorithm) }

  override fun shaBase64Sync(data: String, algorithm: SHAAlgorithm): String =
    SHACrypto.hashBase64(data, algorithm)

  override fun shaUtf8(data: String, algorithm: SHAAlgorithm): Promise<String> =
    Promise.async { shaUtf8Sync(data, algorithm) }

  override fun shaUtf8Sync(data: String, algorithm: SHAAlgorithm): String =
    SHACrypto.hashUtf8ToHex(data, algorithm)

  override fun pbkdf2Hash(
    pwdBase64: String,
    saltBase64: String,
    iterations: Double,
    keyLen: Double,
    hash: PBKDF2HashAlgorithm
  ): Promise<String> =
    Promise.async {
      PBKDF2Crypto.deriveKeyBase64(pwdBase64, saltBase64, iterations.toInt(), keyLen.toInt(), hash)
    }

  override fun hmac256(data: String, key: String): Promise<String> =
    Promise.async { hmac256Sync(data, key) }

  override fun hmac256Sync(data: String, key: String): String =
    HMACCrypto.hmacSha256Hex(data, key)

  override fun aesEncrypt(dataBase64: String, keyHex: String, ivHex: String): Promise<String?> =
    Promise.async { aesEncryptSync(dataBase64, keyHex, ivHex) }

  override fun aesEncryptSync(dataBase64: String, keyHex: String, ivHex: String): String? =
    AESCrypto.encryptBase64(dataBase64, keyHex, ivHex)

  override fun aesDecrypt(dataBase64: String, keyHex: String, ivHex: String): Promise<String?> =
    Promise.async { aesDecryptSync(dataBase64, keyHex, ivHex) }

  override fun aesDecryptSync(dataBase64: String, keyHex: String, ivHex: String): String? =
    AESCrypto.decryptBase64(dataBase64, keyHex, ivHex)

  override fun aesGcmEncrypt(dataBase64: String, keyHex: String, ivHex: String): Promise<String?> =
    Promise.async { aesGcmEncryptSync(dataBase64, keyHex, ivHex) }

  override fun aesGcmEncryptSync(dataBase64: String, keyHex: String, ivHex: String): String? =
    AESCrypto.encryptGcmBase64(dataBase64, keyHex, ivHex)

  override fun aesGcmDecrypt(dataBase64: String, keyHex: String, ivHex: String): Promise<String?> =
    Promise.async { aesGcmDecryptSync(dataBase64, keyHex, ivHex) }

  override fun aesGcmDecryptSync(dataBase64: String, keyHex: String, ivHex: String): String? =
    AESCrypto.decryptGcmBase64(dataBase64, keyHex, ivHex)

  override fun aesEncryptFile(filePath: String, base64UrlKey: String, base64Iv: String): Promise<String> =
    Promise.async(fileScope) { AESCrypto.encryptFile(filePath, base64UrlKey, base64Iv, context) }

  override fun aesDecryptFile(filePath: String, base64UrlKey: String, base64Iv: String): Promise<String> =
    Promise.async(fileScope) { AESCrypto.decryptFile(filePath, base64UrlKey, base64Iv, context) }

  override fun randomUuid(): String =
    RandomUtils.generateUuid()

  override fun randomKey(length: Double): String =
    RandomUtils.generateRandomKeyHex(length.toInt())

  override fun randomBytes(size: Double): String =
    RandomUtils.generateRandomBytesBase64(size.toInt())

  override fun rsaGenerateKeys(keySize: Double?): Promise<RSAKeyPair> =
    Promise.async { RSACrypto.generateKeyPair(keySize?.toInt() ?: DEFAULT_RSA_KEY_SIZE) }

  override fun rsaEncrypt(message: String, publicKey: String): String =
    RSACrypto.encrypt(message, publicKey)

  override fun rsaEncrypt64(message: String, publicKey: String): String =
    RSACrypto.encryptBase64(message, publicKey)

  override fun rsaDecrypt(encodedMessage: String, privateKey: String): Promise<String> =
    Promise.async { RSACrypto.decrypt(encodedMessage, privateKey) }

  override fun rsaDecrypt64(encodedMessage: String, privateKey: String): Promise<String> =
    Promise.async { RSACrypto.decryptToBase64(encodedMessage, privateKey) }

  override fun rsaSign(message: String, privateKey: String, hash: RSAHashAlgorithm?): Promise<String> =
    Promise.async { RSACrypto.sign(message, privateKey, hash) }

  override fun rsaSign64(message: String, privateKey: String, hash: RSAHashAlgorithm?): Promise<String> =
    Promise.async { RSACrypto.signBase64(message, privateKey, hash) }

  override fun rsaVerify(signature: String, message: String, publicKey: String, hash: RSAHashAlgorithm?): Promise<Boolean> =
    Promise.async { rsaVerifySync(signature, message, publicKey, hash) }

  override fun rsaVerifySync(signature: String, message: String, publicKey: String, hash: RSAHashAlgorithm?): Boolean =
    RSACrypto.verify(signature, message, publicKey, hash)

  override fun rsaVerify64(signature: String, message: String, publicKey: String, hash: RSAHashAlgorithm?): Promise<Boolean> =
    Promise.async { rsaVerify64Sync(signature, message, publicKey, hash) }

  override fun rsaVerify64Sync(signature: String, message: String, publicKey: String, hash: RSAHashAlgorithm?): Boolean =
    RSACrypto.verifyBase64(signature, message, publicKey, hash)

  override fun calculateFileChecksum(filePath: String): Promise<String> =
    Promise.async(fileScope) { FileUtils.calculateSha256Checksum(filePath, context) }

  override fun getRandomValues(length: Double): String =
    RandomUtils.generateRandomAlphanumeric(length.toInt())

  override fun rsaImportKey(jwk: JWK): Promise<String> =
    Promise.async { RSACrypto.importJwkKey(jwk) }

  override fun rsaExportKey(pem: String): Promise<JWK> =
    Promise.async { RSACrypto.exportPemKey(pem) }

  override fun rsaImportPrivateKey(pem: String): Promise<HybridRSAPrivateKeySpec> =
    Promise.async { HybridRSAPrivateKey(RSACrypto.createPrivateKeyFromPem(pem)) }

  override fun rsaImportPublicKey(pem: String): Promise<HybridRSAPublicKeySpec> =
    Promise.async { HybridRSAPublicKey(RSACrypto.createPublicKeyFromPem(pem)) }

  override fun shaBuffer(data: ArrayBuffer, algorithm: SHAAlgorithm): Promise<ArrayBuffer> {
    val dataBytes = data.toByteArray()
    return Promise.async { ArrayBuffer.copy(SHACrypto.computeHash(dataBytes, algorithm)) }
  }

  override fun shaBufferSync(data: ArrayBuffer, algorithm: SHAAlgorithm): ArrayBuffer =
    ArrayBuffer.copy(SHACrypto.computeHash(data.toByteArray(), algorithm))

  override fun hmac256Buffer(data: ArrayBuffer, key: ArrayBuffer): Promise<ArrayBuffer> {
    val dataBytes = data.toByteArray()
    val keyBytes = key.toByteArray()
    return Promise.async { ArrayBuffer.copy(HMACCrypto.hmacSha256(dataBytes, keyBytes)) }
  }

  override fun hmac256BufferSync(data: ArrayBuffer, key: ArrayBuffer): ArrayBuffer =
    ArrayBuffer.copy(HMACCrypto.hmacSha256(data.toByteArray(), key.toByteArray()))

  override fun aesEncryptBuffer(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): Promise<ArrayBuffer> =
    asyncAes(data, key, iv, AESCrypto::encryptCbc)

  override fun aesEncryptBufferSync(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): ArrayBuffer =
    syncAes(data, key, iv, AESCrypto::encryptCbc)

  override fun aesDecryptBuffer(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): Promise<ArrayBuffer> =
    asyncAes(data, key, iv, AESCrypto::decryptCbc)

  override fun aesDecryptBufferSync(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): ArrayBuffer =
    syncAes(data, key, iv, AESCrypto::decryptCbc)

  override fun aesGcmEncryptBuffer(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): Promise<ArrayBuffer> =
    asyncAes(data, key, iv, AESCrypto::encryptGcm)

  override fun aesGcmEncryptBufferSync(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): ArrayBuffer =
    syncAes(data, key, iv, AESCrypto::encryptGcm)

  override fun aesGcmDecryptBuffer(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): Promise<ArrayBuffer> =
    asyncAes(data, key, iv, AESCrypto::decryptGcm)

  override fun aesGcmDecryptBufferSync(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer): ArrayBuffer =
    syncAes(data, key, iv, AESCrypto::decryptGcm)

  override fun randomBytesBuffer(size: Double): ArrayBuffer =
    ArrayBuffer.copy(RandomUtils.generateRandomBytes(size.toInt()))

  private fun syncAes(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer, operation: (ByteArray, ByteArray, ByteArray) -> ByteArray): ArrayBuffer =
    ArrayBuffer.copy(operation(data.toByteArray(), key.toByteArray(), iv.toByteArray()))

  private fun asyncAes(data: ArrayBuffer, key: ArrayBuffer, iv: ArrayBuffer, operation: (ByteArray, ByteArray, ByteArray) -> ByteArray): Promise<ArrayBuffer> {
    val dataBytes = data.toByteArray()
    val keyBytes = key.toByteArray()
    val ivBytes = iv.toByteArray()
    return Promise.async { ArrayBuffer.copy(operation(dataBytes, keyBytes, ivBytes)) }
  }

  private companion object {
    const val DEFAULT_RSA_KEY_SIZE = 2048
    val fileScope = CoroutineScope(Dispatchers.IO)
  }
}
