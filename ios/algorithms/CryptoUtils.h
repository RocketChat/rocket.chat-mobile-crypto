#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * Common utility functions used across cryptographic algorithms
 */
@interface CryptoUtils : NSObject

/**
 * Convert hexadecimal string to NSData
 * @param string Hexadecimal string
 * @return NSData representation of hex string
 */
+ (NSData *)fromHex:(NSString *)string;

/**
 * Convert NSData to hexadecimal string
 * @param data NSData to convert
 * @return Hexadecimal string representation
 */
+ (NSString *)bytesToHex:(NSData *)data;

/**
 * Convert Base64URL string to standard Base64 string
 * @param base64URL Base64URL encoded string
 * @return Standard Base64 encoded string
 */
+ (NSString *)base64FromBase64URL:(NSString *)base64URL;

/**
 * Convert string to UTF-8 encoded NSData
 * @param string String to convert
 * @return UTF-8 encoded NSData
 */
+ (NSData *)stringToUtf8Data:(NSString *)string;

/**
 * Convert UTF-8 encoded NSData to string
 * @param data UTF-8 encoded NSData
 * @return String representation
 */
+ (NSString *)utf8DataToString:(NSData *)data;

/**
 * Encode NSData to Base64 string with no options
 * @param data NSData to encode
 * @return Base64 encoded string
 */
+ (NSString *)encodeBase64:(NSData *)data;

/**
 * Decode Base64 string to NSData
 * @param base64String Base64 encoded string
 * @return NSData representation, nil if invalid
 */
+ (nullable NSData *)decodeBase64:(NSString *)base64String;

@end

NS_ASSUME_NONNULL_END
