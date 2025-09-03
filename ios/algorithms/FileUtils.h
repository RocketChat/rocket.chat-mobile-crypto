#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * File-related cryptographic utilities
 */
@interface FileUtils : NSObject

/**
 * Calculate SHA-256 checksum of a file
 * @param filePath Path to the file (supports file:// prefix)
 * @return Hexadecimal checksum string, nil if calculation fails
 */
+ (nullable NSString *)calculateSha256Checksum:(NSString *)filePath;

/**
 * Calculate SHA-1 checksum of a file
 * @param filePath Path to the file (supports file:// prefix)
 * @return Hexadecimal checksum string, nil if calculation fails
 */
+ (nullable NSString *)calculateSha1Checksum:(NSString *)filePath;

/**
 * Calculate SHA-512 checksum of a file
 * @param filePath Path to the file (supports file:// prefix)
 * @return Hexadecimal checksum string, nil if calculation fails
 */
+ (nullable NSString *)calculateSha512Checksum:(NSString *)filePath;

/**
 * Calculate checksum of a file using specified algorithm
 * @param filePath Path to the file (supports file:// prefix)
 * @param algorithm Hash algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
 * @return Hexadecimal checksum string, nil if calculation fails
 */
+ (nullable NSString *)calculateChecksum:(NSString *)filePath algorithm:(NSString *)algorithm;

/**
 * Calculate checksum of a file using specified algorithm and return Base64
 * @param filePath Path to the file (supports file:// prefix)
 * @param algorithm Hash algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
 * @return Base64-encoded checksum string, nil if calculation fails
 */
+ (nullable NSString *)calculateChecksumBase64:(NSString *)filePath algorithm:(NSString *)algorithm;

/**
 * Get file size in bytes
 * @param filePath Path to the file (supports file:// prefix)
 * @return File size in bytes, -1 if file doesn't exist or error occurs
 */
+ (long long)getFileSize:(NSString *)filePath;

/**
 * Check if file exists
 * @param filePath Path to the file (supports file:// prefix)
 * @return YES if file exists, NO otherwise
 */
+ (BOOL)fileExists:(NSString *)filePath;

/**
 * Verify file integrity by comparing checksums
 * @param filePath Path to the file (supports file:// prefix)
 * @param expectedChecksum Expected checksum in hexadecimal format
 * @param algorithm Hash algorithm to use (default: SHA-256)
 * @return YES if checksums match, NO otherwise
 */
+ (BOOL)verifyFileIntegrity:(NSString *)filePath expectedChecksum:(NSString *)expectedChecksum algorithm:(NSString *)algorithm;

/**
 * Calculate multiple checksums for a file
 * @param filePath Path to the file (supports file:// prefix)
 * @param algorithms Array of hash algorithms to use
 * @return Dictionary of algorithm to checksum (hexadecimal), nil if calculation fails
 */
+ (nullable NSDictionary<NSString *, NSString *> *)calculateMultipleChecksums:(NSString *)filePath algorithms:(NSArray<NSString *> *)algorithms;

/**
 * Normalize file path by removing file:// prefix if present
 * @param filePath Original file path
 * @return Normalized file path
 */
+ (NSString *)normalizeFilePath:(NSString *)filePath;

@end

NS_ASSUME_NONNULL_END
