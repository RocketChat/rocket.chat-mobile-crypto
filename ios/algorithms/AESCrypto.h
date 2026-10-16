#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * AES encryption and decryption operations
 */
@interface AESCrypto : NSObject

/**
 * Encrypt Base64-encoded data using AES-CBC with PKCS7 padding
 * @param dataBase64 Base64-encoded data to encrypt
 * @param keyHex Hexadecimal key
 * @param ivHex Hexadecimal initialization vector
 * @return Base64-encoded encrypted data, nil if encryption fails
 */
+ (nullable NSString *)encryptBase64:(NSString *)dataBase64 keyHex:(NSString *)keyHex ivHex:(NSString *)ivHex;

/**
 * Decrypt Base64-encoded data using AES-CBC with PKCS7 padding
 * @param dataBase64 Base64-encoded data to decrypt
 * @param keyHex Hexadecimal key
 * @param ivHex Hexadecimal initialization vector
 * @return Base64-encoded decrypted data, nil if decryption fails
 */
+ (nullable NSString *)decryptBase64:(NSString *)dataBase64 keyHex:(NSString *)keyHex ivHex:(NSString *)ivHex;

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
 * Core AES-CBC encryption/decryption function
 * @param operation Encrypt or decrypt operation
 * @param data Data to process
 * @param key Hexadecimal key
 * @param iv Hexadecimal initialization vector
 * @return Processed data, nil if operation fails
 */
+ (nullable NSData *)aes128CBC:(NSString *)operation data:(NSData *)data key:(NSString *)key iv:(NSString *)iv;

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
