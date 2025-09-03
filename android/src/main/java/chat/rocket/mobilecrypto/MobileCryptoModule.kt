package chat.rocket.mobilecrypto

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.annotations.ReactModule
import com.facebook.react.bridge.ReadableMap
import chat.rocket.mobilecrypto.algorithms.AESCrypto
import chat.rocket.mobilecrypto.algorithms.FileUtils
import chat.rocket.mobilecrypto.algorithms.HMACCrypto
import chat.rocket.mobilecrypto.algorithms.PBKDF2Crypto
import chat.rocket.mobilecrypto.algorithms.RSACrypto
import chat.rocket.mobilecrypto.algorithms.RandomUtils
import chat.rocket.mobilecrypto.algorithms.SHACrypto

@ReactModule(name = MobileCryptoModule.NAME)
class MobileCryptoModule(reactContext: ReactApplicationContext) :
  NativeMobileCryptoSpec(reactContext) {

  // Initialize algorithm modules
  private val aesCrypto = AESCrypto(reactContext)

  override fun getName(): String {
    return NAME
  }

  override fun shaBase64(data: String, algorithm: String, promise: Promise) {
    try {
      val result = SHACrypto.hashBase64(data, algorithm)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun shaUtf8(data: String, algorithm: String, promise: Promise) {
    try {
      val result = SHACrypto.hashUtf8ToHex(data, algorithm)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
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
      val result = PBKDF2Crypto.deriveKeyBase64(
        pwdBase64, 
        saltBase64, 
        iterations.toInt(), 
        keyLen.toInt(), 
        hash
      )
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun hmac256(data: String, key: String, promise: Promise) {
    try {
      val result = HMACCrypto.hmacSha256Hex(data, key)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }


  override fun aesEncrypt(dataBase64: String, keyHex: String, ivHex: String, promise: Promise) {
    try {
      val result = aesCrypto.encryptBase64(dataBase64, keyHex, ivHex)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun aesDecrypt(dataBase64: String, keyHex: String, ivHex: String, promise: Promise) {
    try {
      val result = aesCrypto.decryptBase64(dataBase64, keyHex, ivHex)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun aesEncryptFile(filePath: String, base64UrlKey: String, base64Iv: String, promise: Promise) {
    try {
      val result = aesCrypto.encryptFile(filePath, base64UrlKey, base64Iv)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun aesDecryptFile(filePath: String, base64UrlKey: String, base64Iv: String, promise: Promise) {
    try {
      val result = aesCrypto.decryptFile(filePath, base64UrlKey, base64Iv)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun randomUuid(promise: Promise) {
    try {
      val result = RandomUtils.generateUuid()
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun randomKey(length: Double, promise: Promise) {
    try {
      val result = RandomUtils.generateRandomKeyHex(length.toInt())
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun randomBytes(size: Double, promise: Promise) {
    try {
      val result = RandomUtils.generateRandomBytesBase64(size.toInt())
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaGenerateKeys(keySize: Double?, promise: Promise) {
    try {
      val actualKeySize = keySize?.toInt() ?: 2048
      val result = RSACrypto.generateKeyPair(actualKeySize)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaEncrypt(message: String, publicKeyString: String, promise: Promise) {
    try {
      val result = RSACrypto.encrypt(message, publicKeyString)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaEncrypt64(message: String, publicKeyString: String, promise: Promise) {
    try {
      val result = RSACrypto.encryptBase64(message, publicKeyString)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaDecrypt(encodedMessage: String, privateKeyString: String, promise: Promise) {
    try {
      val result = RSACrypto.decrypt(encodedMessage, privateKeyString)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaDecrypt64(encodedMessage: String, privateKeyString: String, promise: Promise) {
    try {
      val result = RSACrypto.decryptToBase64(encodedMessage, privateKeyString)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaSign(message: String, privateKeyString: String, hash: String?, promise: Promise) {
    try {
      val result = RSACrypto.sign(message, privateKeyString, hash)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaSign64(message: String, privateKeyString: String, hash: String?, promise: Promise) {
    try {
      val result = RSACrypto.signBase64(message, privateKeyString, hash)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaVerify(signatureString: String, message: String, publicKeyString: String, hash: String?, promise: Promise) {
    try {
      val result = RSACrypto.verify(signatureString, message, publicKeyString, hash)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaVerify64(signatureString: String, message: String, publicKeyString: String, hash: String?, promise: Promise) {
    try {
      val result = RSACrypto.verifyBase64(signatureString, message, publicKeyString, hash)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun calculateFileChecksum(filePath: String, promise: Promise) {
    try {
      val result = FileUtils.calculateSha256Checksum(filePath)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun getRandomValues(length: Double, promise: Promise) {
    try {
      val result = RandomUtils.generateRandomAlphanumeric(length.toInt())
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  // RSA Key Format Conversion Methods
  override fun rsaImportKey(jwk: ReadableMap, promise: Promise) {
    try {
      val result = RSACrypto.importJwkKey(jwk)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  override fun rsaExportKey(pem: String, promise: Promise) {
    try {
      val result = RSACrypto.exportPemKey(pem)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("-1", e.message)
    }
  }

  companion object {
    const val NAME = "MobileCrypto"
  }
}
