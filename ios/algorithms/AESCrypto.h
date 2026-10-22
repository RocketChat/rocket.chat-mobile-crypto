#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * AES encryption and decryption operations
 */
@interface AESCrypto : NSObject

/**
 * Encrypt a file using AES-CTR mode
 * @param filePath Path to the file to encrypt
 * @param base64UrlKey Base64URL-encoded key
 * @param base64Iv Base64-encoded initialization vector
 * @return File path of encrypted file, nil if encryption fails
 */
+ (nullable NSString *)encryptFile:(NSString *)filePath base64UrlKey:(NSString *)base64UrlKey base64Iv:(NSString *)base64Iv;

/**
 * Decrypt a file using AES-CTR mode
 * @param filePath Path to the file to decrypt
 * @param base64UrlKey Base64URL-encoded key
 * @param base64Iv Base64-encoded initialization vector
 * @return File path of decrypted file, nil if decryption fails
 */
+ (nullable NSString *)decryptFile:(NSString *)filePath base64UrlKey:(NSString *)base64UrlKey base64Iv:(NSString *)base64Iv;

/**
 * Process file with AES-CTR mode
 * @param filePath Path to the file
 * @param operation CCOperation (encrypt or decrypt)
 * @param base64UrlKey Base64URL-encoded key
 * @param base64Iv Base64-encoded initialization vector
 * @return Processed file path, nil if operation fails
 */
+ (nullable NSString *)processFile:(NSString *)filePath operation:(CCOperation)operation base64UrlKey:(NSString *)base64UrlKey base64Iv:(NSString *)base64Iv;

@end

NS_ASSUME_NONNULL_END
