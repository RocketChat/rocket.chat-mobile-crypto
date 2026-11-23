package chat.rocket.mobilecrypto

class AESKey internal constructor(internal val bytes: ByteArray) {
  init {
    requireValidByteLength(bytes.size)
  }

  internal companion object {
    private val VALID_BYTE_LENGTHS = setOf(16, 32)

    fun requireValidByteLength(byteLength: Int) {
      require(byteLength in VALID_BYTE_LENGTHS) { "AES key must be 16 or 32 bytes, got $byteLength" }
    }
  }
}
