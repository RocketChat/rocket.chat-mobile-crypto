package chat.rocket.mobilecrypto.algorithms

import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.security.MessageDigest
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns

/**
 * File-related cryptographic utilities
 */
object FileUtils {
    private lateinit var appContext: Context

    fun init(context: Context) {
        appContext = context.applicationContext
    }

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
     * @param filePath Path to the file (supports file:// and content:// prefixes)
     * @param algorithm Hash algorithm (SHA-1, SHA-256, SHA-384, SHA-512, MD5)
     * @return Hexadecimal checksum string
     */
    fun calculateChecksum(filePath: String, algorithm: String): String {
        getInputStream(filePath).use { inputStream ->
            val digest = MessageDigest.getInstance(algorithm)
            val buffer = ByteArray(BUFFER_SIZE)
            var bytesRead: Int
            
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
            
            val hash = digest.digest()
            return CryptoUtils.bytesToHex(hash)
        }
    }

    /**
     * Calculate checksum of a file using specified algorithm and return Base64
     * 
     * @param filePath Path to the file (supports file:// and content:// prefixes)
     * @param algorithm Hash algorithm (SHA-1, SHA-256, SHA-384, SHA-512, MD5)
     * @return Base64-encoded checksum string
     */
    fun calculateChecksumBase64(filePath: String, algorithm: String): String {
        getInputStream(filePath).use { inputStream ->
            val digest = MessageDigest.getInstance(algorithm)
            val buffer = ByteArray(BUFFER_SIZE)
            var bytesRead: Int
            
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
            
            val hash = digest.digest()
            return CryptoUtils.encodeBase64NoWrap(hash)
        }
    }

    /**
     * Get file size in bytes
     * 
     * @param filePath Path to the file (supports file:// and content:// prefixes)
     * @return File size in bytes, or -1 if size cannot be determined
     */
    fun getFileSize(filePath: String): Long {
        val uri = Uri.parse(filePath)

        return if (uri.scheme == null || uri.scheme == "file") {
            File(uri.path ?: filePath).length()
        } else {
            if (!::appContext.isInitialized) {
                throw IllegalStateException("FileUtils.init(context) not called")
            }
            
            appContext.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
                val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (cursor.moveToFirst() && sizeIndex != -1) {
                    cursor.getLong(sizeIndex)
                } else {
                    -1L
                }
            } ?: -1L
        }
    }

    /**
     * Check if file exists
     * 
     * @param filePath Path to the file (supports file:// and content:// prefixes)
     * @return True if file exists
     */
    fun fileExists(filePath: String): Boolean {
        val uri = Uri.parse(filePath)

        return if (uri.scheme == null || uri.scheme == "file") {
            val file = File(uri.path ?: filePath)
            file.exists() && file.isFile
        } else {
            if (!::appContext.isInitialized) {
                throw IllegalStateException("FileUtils.init(context) not called")
            }
            
            try {
                appContext.contentResolver.openInputStream(uri)?.use { true } ?: false
            } catch (e: Exception) {
                false
            }
        }
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
     * @param filePath Path to the file (supports file:// and content:// prefixes)
     * @param algorithms List of hash algorithms to use
     * @return Map of algorithm to checksum (hexadecimal)
     */
    fun calculateMultipleChecksums(filePath: String, algorithms: List<String>): Map<String, String> {
        val digests = algorithms.associateWith { MessageDigest.getInstance(it) }
        
        getInputStream(filePath).use { inputStream ->
            val buffer = ByteArray(BUFFER_SIZE)
            var bytesRead: Int
            
            while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                digests.values.forEach { digest ->
                    digest.update(buffer, 0, bytesRead)
                }
            }
        }
        
        return digests.mapValues { (_, digest) ->
            CryptoUtils.bytesToHex(digest.digest())
        }
    }

    /**
     * Get input stream for any URI type without creating temp files
     */
    private fun getInputStream(filePath: String): InputStream {
        val uri = Uri.parse(filePath)

        return if (uri.scheme == null || uri.scheme == "file") {
            FileInputStream(uri.path ?: filePath)
        } else {
            if (!::appContext.isInitialized) {
                throw IllegalStateException("FileUtils.init(context) not called")
            }
            appContext.contentResolver.openInputStream(uri)
                ?: throw IllegalArgumentException("Cannot open input stream for URI: $uri")
        }
    }
}
