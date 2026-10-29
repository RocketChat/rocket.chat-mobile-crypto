package chat.rocket.mobilecrypto

import chat.rocket.mobilecrypto.algorithms.AESCrypto
import chat.rocket.mobilecrypto.algorithms.RSACrypto
import com.margelo.nitro.mobilecrypto.AESGCMCiphertext
import java.security.PrivateKey

object MobileCryptoNative {

  fun rsaImportPrivateKey(jwkJson: String): PrivateKey? =
    runCatching { RSACrypto.importPrivateKey(jwkJson) }.getOrNull()

  fun rsaDecrypt(ciphertext: String, privateKey: PrivateKey): String? =
    runCatching { RSACrypto.decrypt(ciphertext, privateKey) }.getOrNull()

  fun aesImportKey(base64Url: String): ByteArray? =
    runCatching { AESCrypto.importKey(base64Url) }.getOrNull()

  fun aesGcmDecrypt(ciphertext: String, iv: String, key: ByteArray): String? =
    runCatching { AESCrypto.gcmDecrypt(key, ciphertext, iv) }.getOrNull()

  fun aesGcmEncrypt(plaintext: String, key: ByteArray): AESGCMCiphertext? =
    runCatching { AESCrypto.gcmEncrypt(key, plaintext) }.getOrNull()

  fun aesCbcDecrypt(ivAndCiphertext: String, key: ByteArray): String? =
    runCatching { AESCrypto.cbcDecrypt(key, ivAndCiphertext) }.getOrNull()

  fun aesCbcEncrypt(plaintext: String, key: ByteArray): String? =
    runCatching { AESCrypto.cbcEncrypt(key, plaintext) }.getOrNull()
}
