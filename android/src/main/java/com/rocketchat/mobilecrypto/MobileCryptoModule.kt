package com.rocketchat.mobilecrypto

import android.util.Base64
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.annotations.ReactModule
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.nio.charset.StandardCharsets

import org.spongycastle.crypto.ExtendedDigest
import org.spongycastle.crypto.PBEParametersGenerator
import org.spongycastle.crypto.digests.SHA1Digest
import org.spongycastle.crypto.digests.SHA224Digest
import org.spongycastle.crypto.digests.SHA256Digest
import org.spongycastle.crypto.digests.SHA384Digest
import org.spongycastle.crypto.digests.SHA512Digest
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.spongycastle.crypto.params.KeyParameter

@ReactModule(name = MobileCryptoModule.NAME)
class MobileCryptoModule(reactContext: ReactApplicationContext) :
  NativeMobileCryptoSpec(reactContext) {

  override fun getName(): String {
    return NAME
  }

  // Example method
  // See https://reactnative.dev/docs/native-modules-android
  override fun multiply(a: Double, b: Double): Double {
    return a * b
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

  companion object {
    const val NAME = "MobileCrypto"
  }
}
