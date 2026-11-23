package chat.rocket.mobilecrypto

import chat.rocket.mobilecrypto.algorithms.AESCrypto
import chat.rocket.mobilecrypto.algorithms.RSACrypto
import java.security.PrivateKey

object MobileCryptoNative {

  data class EncryptedText(val iv: String, val ciphertext: String)

  fun rsaImportPrivateKey(jwkJson: String): PrivateKey? =
    orNull { RSACrypto.importPrivateKey(jwkJson) }

  fun rsaDecrypt(ciphertext: String, privateKey: PrivateKey): String? =
    orNull { RSACrypto.decrypt(ciphertext, privateKey) }

  fun aesImportKey(base64Url: String): AESKey? =
    orNull { AESCrypto.importKey(base64Url) }

  fun aesGcmDecrypt(ciphertext: String, iv: String, key: AESKey): String? =
    orNull { AESCrypto.gcmDecrypt(key, ciphertext, iv) }

  fun aesGcmEncrypt(plaintext: String, key: AESKey): EncryptedText? =
    orNull { AESCrypto.gcmEncrypt(key, plaintext).let { EncryptedText(it.iv, it.ciphertext) } }

  fun aesCbcDecrypt(ivAndCiphertext: String, key: AESKey): String? =
    orNull { AESCrypto.cbcDecrypt(key, ivAndCiphertext) }

  fun aesCbcEncrypt(plaintext: String, key: AESKey): String? =
    orNull { AESCrypto.cbcEncrypt(key, plaintext) }

  private inline fun <T> orNull(operation: () -> T): T? =
    try {
      operation()
    } catch (exception: Exception) {
      null
    }
}
