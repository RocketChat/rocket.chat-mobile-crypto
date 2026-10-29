package com.margelo.nitro.mobilecrypto

import android.content.Context
import androidx.annotation.Keep
import chat.rocket.mobilecrypto.algorithms.AESCrypto
import chat.rocket.mobilecrypto.algorithms.CryptoUtils
import chat.rocket.mobilecrypto.algorithms.HMACCrypto
import chat.rocket.mobilecrypto.algorithms.PBKDF2Crypto
import chat.rocket.mobilecrypto.algorithms.RSACrypto
import chat.rocket.mobilecrypto.algorithms.RandomUtils
import chat.rocket.mobilecrypto.algorithms.SHACrypto
import com.facebook.proguard.annotations.DoNotStrip
import com.margelo.nitro.NitroModules
import com.margelo.nitro.core.ArrayBuffer
import com.margelo.nitro.core.Promise
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers

@Keep
@DoNotStrip
class HybridMobileCrypto : HybridMobileCryptoSpec() {
  private val context: Context
    get() = NitroModules.applicationContext ?: throw Error("No ApplicationContext set!")

  override fun sha(data: ArrayBuffer, algorithm: SHAAlgorithm): Promise<ArrayBuffer> {
    val dataBytes = data.toByteArray()
    return Promise.async { ArrayBuffer.copy(SHACrypto.computeHash(dataBytes, algorithm)) }
  }

  override fun shaSync(data: ArrayBuffer, algorithm: SHAAlgorithm): ArrayBuffer =
    ArrayBuffer.copy(SHACrypto.computeHash(data.toByteArray(), algorithm))

  override fun hmac256(data: ArrayBuffer, key: ArrayBuffer): Promise<ArrayBuffer> {
    val dataBytes = data.toByteArray()
    val keyBytes = key.toByteArray()
    return Promise.async { ArrayBuffer.copy(HMACCrypto.hmacSha256(dataBytes, keyBytes)) }
  }

  override fun hmac256Sync(data: ArrayBuffer, key: ArrayBuffer): ArrayBuffer =
    ArrayBuffer.copy(HMACCrypto.hmacSha256(data.toByteArray(), key.toByteArray()))

  override fun aesGenerateKey(byteLength: Double): HybridAESKeySpec =
    HybridAESKey(AESCrypto.generateKey(byteLength.toInt()))

  override fun aesImportKey(base64Url: String): HybridAESKeySpec =
    HybridAESKey(AESCrypto.importKey(base64Url))

  override fun aesDeriveKey(
    passwordBase64: String,
    saltBase64: String,
    iterations: Double,
    byteLength: Double,
    hash: PBKDF2HashAlgorithm
  ): Promise<HybridAESKeySpec> =
    Promise.async {
      AESCrypto.requireKeyLength(byteLength.toInt())
      HybridAESKey(
        PBKDF2Crypto.deriveKey(
          CryptoUtils.decodeBase64(passwordBase64),
          CryptoUtils.decodeBase64(saltBase64),
          iterations.toInt(),
          byteLength.toInt(),
          hash
        )
      )
    }

  override fun aesGcmEncrypt(key: HybridAESKeySpec, plaintext: String): Promise<AESGCMCiphertext> {
    val keyBytes = key.bytes
    return Promise.async { AESCrypto.gcmEncrypt(keyBytes, plaintext) }
  }

  override fun aesGcmEncryptSync(key: HybridAESKeySpec, plaintext: String): AESGCMCiphertext =
    AESCrypto.gcmEncrypt(key.bytes, plaintext)

  override fun aesGcmDecrypt(key: HybridAESKeySpec, ciphertext: String, iv: String): Promise<String> {
    val keyBytes = key.bytes
    return Promise.async { AESCrypto.gcmDecrypt(keyBytes, ciphertext, iv) }
  }

  override fun aesGcmDecryptSync(key: HybridAESKeySpec, ciphertext: String, iv: String): String =
    AESCrypto.gcmDecrypt(key.bytes, ciphertext, iv)

  override fun aesCbcEncrypt(key: HybridAESKeySpec, plaintext: String): Promise<String> {
    val keyBytes = key.bytes
    return Promise.async { AESCrypto.cbcEncrypt(keyBytes, plaintext) }
  }

  override fun aesCbcEncryptSync(key: HybridAESKeySpec, plaintext: String): String =
    AESCrypto.cbcEncrypt(key.bytes, plaintext)

  override fun aesCbcDecrypt(key: HybridAESKeySpec, ivAndCiphertext: String): Promise<String> {
    val keyBytes = key.bytes
    return Promise.async { AESCrypto.cbcDecrypt(keyBytes, ivAndCiphertext) }
  }

  override fun aesCbcDecryptSync(key: HybridAESKeySpec, ivAndCiphertext: String): String =
    AESCrypto.cbcDecrypt(key.bytes, ivAndCiphertext)

  override fun aesEncryptFile(filePath: String): Promise<EncryptedFile> =
    Promise.async(fileScope) { AESCrypto.encryptFile(filePath, context) }

  override fun aesDecryptFile(filePath: String, key: String, iv: String, sha256: String): Promise<String> =
    Promise.async(fileScope) { AESCrypto.decryptFile(filePath, key, iv, sha256, context) }

  override fun rsaGenerateKeys(keySize: Double?): Promise<RSAKeyPair> =
    Promise.async {
      val keyPair = RSACrypto.generateKeyPair(keySize?.toInt() ?: DEFAULT_RSA_KEY_SIZE)
      RSAKeyPair(
        HybridRSAPublicKey(keyPair.public as RSAPublicKey),
        HybridRSAPrivateKey(keyPair.private as RSAPrivateCrtKey)
      )
    }

  override fun rsaImportPrivateKey(jwk: String): Promise<HybridRSAPrivateKeySpec> =
    Promise.async { HybridRSAPrivateKey(RSACrypto.importPrivateKey(jwk)) }

  override fun rsaImportPublicKey(jwk: String): Promise<HybridRSAPublicKeySpec> =
    Promise.async { HybridRSAPublicKey(RSACrypto.importPublicKey(jwk)) }

  override fun randomUuid(): String =
    RandomUtils.generateUuid()

  override fun randomKey(length: Double): String =
    RandomUtils.generateRandomKeyHex(length.toInt())

  override fun randomBytes(size: Double): ArrayBuffer =
    ArrayBuffer.copy(RandomUtils.generateRandomBytes(size.toInt()))

  private val HybridAESKeySpec.bytes: ByteArray
    get() = (this as? HybridAESKey)?.key
      ?: throw IllegalArgumentException("AES key must be created by MobileCrypto, got $this")

  private companion object {
    const val DEFAULT_RSA_KEY_SIZE = 2048
    val fileScope = CoroutineScope(Dispatchers.IO)
  }
}
