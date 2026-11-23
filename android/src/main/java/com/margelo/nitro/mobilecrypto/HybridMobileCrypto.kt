package com.margelo.nitro.mobilecrypto

import android.content.Context
import androidx.annotation.Keep
import chat.rocket.mobilecrypto.AESKey
import chat.rocket.mobilecrypto.algorithms.AESCrypto
import chat.rocket.mobilecrypto.algorithms.HMACCrypto
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
    HybridAESKey(AESCrypto.generateKey(byteLength.toCount()))

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
      HybridAESKey(AESCrypto.deriveKey(passwordBase64, saltBase64, iterations.toCount(), byteLength.toCount(), hash))
    }

  override fun aesGcmEncrypt(key: HybridAESKeySpec, plaintext: String): Promise<AESGCMCiphertext> =
    Promise.async { aesGcmEncryptSync(key, plaintext) }

  override fun aesGcmEncryptSync(key: HybridAESKeySpec, plaintext: String): AESGCMCiphertext =
    AESCrypto.gcmEncrypt(key.aesKey, plaintext)

  override fun aesGcmDecrypt(key: HybridAESKeySpec, encrypted: AESGCMCiphertext): Promise<String> =
    Promise.async { aesGcmDecryptSync(key, encrypted) }

  override fun aesGcmDecryptSync(key: HybridAESKeySpec, encrypted: AESGCMCiphertext): String =
    AESCrypto.gcmDecrypt(key.aesKey, encrypted.ciphertext, encrypted.iv)

  override fun aesCbcEncrypt(key: HybridAESKeySpec, plaintext: String): Promise<String> =
    Promise.async { aesCbcEncryptSync(key, plaintext) }

  override fun aesCbcEncryptSync(key: HybridAESKeySpec, plaintext: String): String =
    AESCrypto.cbcEncrypt(key.aesKey, plaintext)

  override fun aesCbcDecrypt(key: HybridAESKeySpec, ivAndCiphertext: String): Promise<String> =
    Promise.async { aesCbcDecryptSync(key, ivAndCiphertext) }

  override fun aesCbcDecryptSync(key: HybridAESKeySpec, ivAndCiphertext: String): String =
    AESCrypto.cbcDecrypt(key.aesKey, ivAndCiphertext)

  override fun aesEncryptFile(filePath: String): Promise<EncryptedFile> =
    Promise.async(fileScope) { AESCrypto.encryptFile(filePath, context) }

  override fun aesDecryptFile(file: EncryptedFile): Promise<String> =
    Promise.async(fileScope) { AESCrypto.decryptFile(file, context) }

  override fun rsaGenerateKeys(keySize: Double?): Promise<RSAKeyPair> =
    Promise.async {
      val keyPair = RSACrypto.generateKeyPair(keySize?.toCount() ?: DEFAULT_RSA_KEY_SIZE)
      RSAKeyPair(
        HybridRSAPublicKey(keyPair.public as RSAPublicKey),
        HybridRSAPrivateKey(keyPair.private as RSAPrivateCrtKey)
      )
    }

  override fun rsaImportPrivateKey(jwk: String): Promise<HybridRSAPrivateKeySpec> =
    Promise.async { HybridRSAPrivateKey(RSACrypto.importPrivateKey(jwk)) }

  override fun rsaImportPublicKey(jwk: String): Promise<HybridRSAPublicKeySpec> =
    Promise.async { HybridRSAPublicKey(RSACrypto.importPublicKey(jwk)) }

  override fun rsaEncrypt(publicKey: HybridRSAPublicKeySpec, plaintext: String): String =
    RSACrypto.encrypt(plaintext, publicKey.rsaPublicKey)

  override fun rsaDecrypt(privateKey: HybridRSAPrivateKeySpec, ciphertext: String): Promise<String> {
    val key = privateKey.rsaPrivateKey
    return Promise.async { RSACrypto.decrypt(ciphertext, key) }
  }

  override fun rsaSign(privateKey: HybridRSAPrivateKeySpec, message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer> {
    val key = privateKey.rsaPrivateKey
    val messageBytes = message.toByteArray()
    return Promise.async { ArrayBuffer.copy(RSACrypto.sign(messageBytes, key, hash)) }
  }

  override fun rsaVerify(
    publicKey: HybridRSAPublicKeySpec,
    signature: ArrayBuffer,
    message: ArrayBuffer,
    hash: RSAHashAlgorithm
  ): Boolean =
    RSACrypto.verify(signature.toByteArray(), message.toByteArray(), publicKey.rsaPublicKey, hash)

  override fun randomUuid(): String =
    RandomUtils.generateUuid()

  override fun randomKey(length: Double): String =
    RandomUtils.generateRandomKeyHex(length.toCount())

  override fun randomBytes(size: Double): ArrayBuffer =
    ArrayBuffer.copy(RandomUtils.generateRandomBytes(size.toCount()))

  private val HybridRSAPrivateKeySpec.rsaPrivateKey: RSAPrivateCrtKey
    get() = (this as? HybridRSAPrivateKey)?.privateKey
      ?: throw IllegalArgumentException("RSA private key must be created by MobileCrypto, got $this")

  private val HybridRSAPublicKeySpec.rsaPublicKey: RSAPublicKey
    get() = (this as? HybridRSAPublicKey)?.publicKey
      ?: throw IllegalArgumentException("RSA public key must be created by MobileCrypto, got $this")

  private val HybridAESKeySpec.aesKey: AESKey
    get() = (this as? HybridAESKey)?.key
      ?: throw IllegalArgumentException("AES key must be created by MobileCrypto, got $this")

  private companion object {
    const val DEFAULT_RSA_KEY_SIZE = 2048
    val fileScope = CoroutineScope(Dispatchers.IO)
  }
}
