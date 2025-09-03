#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * HMAC (Hash-based Message Authentication Code) operations
 */
@interface HMACCrypto : NSObject

/**
 * Supported HMAC algorithms
 */
typedef NS_ENUM(NSInteger, HMACAlgorithm) {
    HMACAlgorithmSHA1,
    HMACAlgorithmSHA224,
    HMACAlgorithmSHA256,
    HMACAlgorithmSHA384,
    HMACAlgorithmSHA512
};

/**
 * Compute HMAC-SHA256 with hex input/output
 * @param dataHex Data in hexadecimal format
 * @param keyHex Key in hexadecimal format
 * @return HMAC result in hexadecimal format, nil if computation fails
 */
+ (nullable NSString *)hmacSha256Hex:(NSString *)dataHex keyHex:(NSString *)keyHex;

/**
 * Compute HMAC with specified algorithm
 * @param data Data to authenticate
 * @param key Secret key
 * @param algorithm HMAC algorithm to use
 * @return HMAC bytes, nil if computation fails
 */
+ (nullable NSData *)computeHmac:(NSData *)data key:(NSData *)key algorithm:(HMACAlgorithm)algorithm;

/**
 * Compute HMAC with Base64 input/output
 * @param dataBase64 Base64-encoded data
 * @param keyBase64 Base64-encoded key
 * @param algorithm HMAC algorithm to use
 * @return Base64-encoded HMAC result, nil if computation fails
 */
+ (nullable NSString *)hmacBase64:(NSString *)dataBase64 keyBase64:(NSString *)keyBase64 algorithm:(HMACAlgorithm)algorithm;

/**
 * Compute HMAC with UTF-8 string input
 * @param data UTF-8 string data
 * @param keyBase64 Base64-encoded key
 * @param algorithm HMAC algorithm to use
 * @return Base64-encoded HMAC result, nil if computation fails
 */
+ (nullable NSString *)hmacStringBase64:(NSString *)data keyBase64:(NSString *)keyBase64 algorithm:(HMACAlgorithm)algorithm;

/**
 * Get algorithm by name string
 * @param name Algorithm name (case-insensitive)
 * @return Algorithm enum value, -1 if not supported
 */
+ (HMACAlgorithm)algorithmByName:(NSString *)name;

/**
 * Get supported algorithm names
 * @return Array of supported algorithm names
 */
+ (NSArray<NSString *> *)supportedAlgorithms;

@end

NS_ASSUME_NONNULL_END
