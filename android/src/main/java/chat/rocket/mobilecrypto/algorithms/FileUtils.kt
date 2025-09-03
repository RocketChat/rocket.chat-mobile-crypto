package chat.rocket.mobilecrypto.algorithms

import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

/**
 * File-related cryptographic utilities
 */
object FileUtils {

    private const val BUFFER_SIZE = 4096

    /**
     * Calculate SHA-256 checksum of a file
     * 
     * @param filePath Path to the file (supports file:// prefix)
     * @return Hexadecimal checksum string
     */
    fun calculateSha256Checksum(filePath: String): String {
        return calculateChecksum(filePath, "SHA-256")
    }

    /**
     * Calculate SHA-1 checksum of a file
     * 
     * @param filePath Path to the file (supports file:// prefix)
     * @return Hexadecimal checksum string
     */
    fun calculateSha1Checksum(filePath: String): String {
        return calculateChecksum(filePath, "SHA-1")
    }

    /**
     * Calculate SHA-512 checksum of a file
     * 
     * @param filePath Path to the file (supports file:// prefix)
     * @return Hexadecimal checksum string
     */
    fun calculateSha512Checksum(filePath: String): String {
        return calculateChecksum(filePath, "SHA-512")
    }

    /**
     * Calculate checksum of a file using specified algorithm
     * 
     * @param filePath Path to the file (supports file:// prefix)
     * @param algorithm Hash algorithm (SHA-1, SHA-256, SHA-384, SHA-512, MD5)
     * @return Hexadecimal checksum string
     */
    fun calculateChecksum(filePath: String, algorithm: String): String {
        val file = normalizeFilePath(filePath)
        
        val inputStream = FileInputStream(file)
        val digest = MessageDigest.getInstance(algorithm)
        val buffer = ByteArray(BUFFER_SIZE)
        var bytesRead: Int
        
        try {
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        } finally {
            inputStream.close()
        }
        
        val hash = digest.digest()
        return CryptoUtils.bytesToHex(hash)
    }

    /**
     * Calculate checksum of a file using specified algorithm and return Base64
     * 
     * @param filePath Path to the file (supports file:// prefix)
     * @param algorithm Hash algorithm (SHA-1, SHA-256, SHA-384, SHA-512, MD5)
     * @return Base64-encoded checksum string
     */
    fun calculateChecksumBase64(filePath: String, algorithm: String): String {
        val file = normalizeFilePath(filePath)
        
        val inputStream = FileInputStream(file)
        val digest = MessageDigest.getInstance(algorithm)
        val buffer = ByteArray(BUFFER_SIZE)
        var bytesRead: Int
        
        try {
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        } finally {
            inputStream.close()
        }
        
        val hash = digest.digest()
        return CryptoUtils.encodeBase64NoWrap(hash)
    }

    /**
     * Get file size in bytes
     * 
     * @param filePath Path to the file (supports file:// prefix)
     * @return File size in bytes
     */
    fun getFileSize(filePath: String): Long {
        val file = normalizeFilePath(filePath)
        return file.length()
    }

    /**
     * Check if file exists
     * 
     * @param filePath Path to the file (supports file:// prefix)
     * @return True if file exists
     */
    fun fileExists(filePath: String): Boolean {
        val file = normalizeFilePath(filePath)
        return file.exists() && file.isFile
    }

    /**
     * Verify file integrity by comparing checksums
     * 
     * @param filePath Path to the file (supports file:// prefix)
     * @param expectedChecksum Expected checksum in hexadecimal format
     * @param algorithm Hash algorithm to use (default: SHA-256)
     * @return True if checksums match
     */
    fun verifyFileIntegrity(filePath: String, expectedChecksum: String, algorithm: String = "SHA-256"): Boolean {
        val actualChecksum = calculateChecksum(filePath, algorithm)
        return actualChecksum.equals(expectedChecksum, ignoreCase = true)
    }

    /**
     * Calculate multiple checksums for a file
     * 
     * @param filePath Path to the file (supports file:// prefix)
     * @param algorithms List of hash algorithms to use
     * @return Map of algorithm to checksum (hexadecimal)
     */
    fun calculateMultipleChecksums(filePath: String, algorithms: List<String>): Map<String, String> {
        val file = normalizeFilePath(filePath)
        val digests = algorithms.associateWith { MessageDigest.getInstance(it) }
        
        val inputStream = FileInputStream(file)
        val buffer = ByteArray(BUFFER_SIZE)
        var bytesRead: Int
        
        try {
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                digests.values.forEach { digest ->
                    digest.update(buffer, 0, bytesRead)
                }
            }
        } finally {
            inputStream.close()
        }
        
        return digests.mapValues { (_, digest) ->
            CryptoUtils.bytesToHex(digest.digest())
        }
    }

    /**
     * Normalize file path by removing file:// prefix if present
     * 
     * @param filePath Original file path
     * @return File object with normalized path
     */
    private fun normalizeFilePath(filePath: String): File {
        val path = if (filePath.startsWith("file://")) {
            filePath.substring(7)
        } else {
            filePath
        }
        return File(path)
    }
}
