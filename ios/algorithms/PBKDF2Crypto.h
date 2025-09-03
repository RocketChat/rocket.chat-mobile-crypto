#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * PBKDF2 (Password-Based Key Derivation Function 2) operations
 */
@interface PBKDF2Crypto : NSObject

/**
 * Derive a key using PBKDF2 with Base64-encoded inputs
 * @param passwordBase64 Base64-encoded password
 * @param saltBase64 Base64-encoded salt
 * @param iterations Number of iterations
 * @param keyLength Desired key length in bytes
 * @param hashAlgorithm Hash algorithm (SHA1, SHA224, SHA256, SHA384, SHA512)
 * @return Base64-encoded derived key, nil if derivation fails
 */
+ (nullable NSString *)deriveKeyBase64:(NSString *)passwordBase64
                            saltBase64:(NSString *)saltBase64
                            iterations:(NSUInteger)iterations
                             keyLength:(NSUInteger)keyLength
                         hashAlgorithm:(NSString *)hashAlgorithm;

/**
 * Derive a key using PBKDF2 with raw data
 * @param passwordData Password data
 * @param saltData Salt data
 * @param iterations Number of iterations
 * @param keyLength Desired key length in bytes
 * @param hashAlgorithm Hash algorithm (SHA1, SHA224, SHA256, SHA384, SHA512)
 * @return Derived key data, nil if derivation fails
 */
+ (nullable NSData *)deriveKey:(NSData *)passwordData
                      saltData:(NSData *)saltData
                    iterations:(NSUInteger)iterations
                     keyLength:(NSUInteger)keyLength
                 hashAlgorithm:(NSString *)hashAlgorithm;

/**
 * Get supported hash algorithms
 * @return Array of supported algorithm names
 */
+ (NSArray<NSString *> *)supportedAlgorithms;

@end

NS_ASSUME_NONNULL_END
