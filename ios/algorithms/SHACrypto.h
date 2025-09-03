#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * SHA (Secure Hash Algorithm) operations
 */
@interface SHACrypto : NSObject

/**
 * Compute SHA hash of data
 * @param data Input data
 * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
 * @return Hash bytes, nil if algorithm not supported
 */
+ (nullable NSData *)hashData:(NSData *)data withAlgorithm:(NSString *)algorithm;

/**
 * Compute SHA hash of Base64-encoded data and return Base64-encoded result
 * @param dataBase64 Base64-encoded input data
 * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
 * @return Base64-encoded hash, nil if computation fails
 */
+ (nullable NSString *)hashBase64:(NSString *)dataBase64 algorithm:(NSString *)algorithm;

/**
 * Compute SHA hash of UTF-8 string and return hexadecimal result
 * @param data UTF-8 string data
 * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
 * @return Hexadecimal hash, nil if computation fails
 */
+ (nullable NSString *)hashUtf8ToHex:(NSString *)data algorithm:(NSString *)algorithm;

/**
 * Compute SHA hash of UTF-8 string and return Base64-encoded result
 * @param data UTF-8 string data
 * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
 * @return Base64-encoded hash, nil if computation fails
 */
+ (nullable NSString *)hashUtf8ToBase64:(NSString *)data algorithm:(NSString *)algorithm;

/**
 * Compute SHA hash of byte array and return hexadecimal result
 * @param data Input data
 * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
 * @return Hexadecimal hash, nil if computation fails
 */
+ (nullable NSString *)hashToHex:(NSData *)data algorithm:(NSString *)algorithm;

/**
 * Compute SHA hash of byte array and return Base64-encoded result
 * @param data Input data
 * @param algorithm SHA algorithm (SHA-1, SHA-256, SHA-384, SHA-512)
 * @return Base64-encoded hash, nil if computation fails
 */
+ (nullable NSString *)hashToBase64:(NSData *)data algorithm:(NSString *)algorithm;

/**
 * Get list of supported SHA algorithms
 * @return Array of supported algorithm names
 */
+ (NSArray<NSString *> *)supportedAlgorithms;

/**
 * Check if algorithm is supported
 * @param algorithm Algorithm name to check
 * @return YES if supported, NO otherwise
 */
+ (BOOL)isAlgorithmSupported:(NSString *)algorithm;

@end

NS_ASSUME_NONNULL_END
