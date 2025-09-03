#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * Random value generation utilities
 */
@interface RandomUtils : NSObject

/**
 * Generate a random UUID string
 * @return UUID string
 */
+ (NSString *)generateUuid;

/**
 * Generate a random key as hexadecimal string
 * @param length Key length in bytes
 * @return Hexadecimal key string, nil if generation fails
 */
+ (nullable NSString *)generateRandomKeyHex:(NSUInteger)length;

/**
 * Generate random bytes as Base64 string
 * @param size Number of bytes to generate
 * @return Base64-encoded random bytes, nil if generation fails
 */
+ (nullable NSString *)generateRandomBytesBase64:(NSUInteger)size;

/**
 * Generate random bytes as NSData
 * @param size Number of bytes to generate
 * @return Random NSData, nil if generation fails
 */
+ (nullable NSData *)generateRandomBytes:(NSUInteger)size;

/**
 * Generate random alphanumeric string
 * @param length Length of the string to generate
 * @return Random alphanumeric string
 */
+ (NSString *)generateRandomAlphanumeric:(NSUInteger)length;

/**
 * Generate random integer within specified range
 * @param min Minimum value (inclusive)
 * @param max Maximum value (exclusive)
 * @return Random integer
 */
+ (NSInteger)generateRandomIntMin:(NSInteger)min max:(NSInteger)max;

/**
 * Generate cryptographically secure random boolean
 * @return Random boolean value
 */
+ (BOOL)generateRandomBoolean;

/**
 * Generate random IV (Initialization Vector) for AES
 * @param size IV size in bytes (default: 16 for AES)
 * @return Random IV as NSData, nil if generation fails
 */
+ (nullable NSData *)generateRandomIV:(NSUInteger)size;

/**
 * Generate random IV (Initialization Vector) for AES as hex string
 * @param size IV size in bytes (default: 16 for AES)
 * @return Random IV as hexadecimal string, nil if generation fails
 */
+ (nullable NSString *)generateRandomIVHex:(NSUInteger)size;

/**
 * Generate random salt for password hashing
 * @param size Salt size in bytes (default: 32)
 * @return Random salt as NSData, nil if generation fails
 */
+ (nullable NSData *)generateRandomSalt:(NSUInteger)size;

/**
 * Generate random salt for password hashing as Base64 string
 * @param size Salt size in bytes (default: 32)
 * @return Random salt as Base64 string, nil if generation fails
 */
+ (nullable NSString *)generateRandomSaltBase64:(NSUInteger)size;

@end

NS_ASSUME_NONNULL_END
