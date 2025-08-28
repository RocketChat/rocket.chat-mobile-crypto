package com.rocketchat.mobilecrypto

import android.util.Base64
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.annotations.ReactModule
import java.security.MessageDigest
import java.nio.charset.StandardCharsets

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

  companion object {
    const val NAME = "MobileCrypto"
  }
}
