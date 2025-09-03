#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * RSA encryption, decryption, signing and key format conversion operations
 */
@interface RSACrypto : NSObject

/**
 * Generate RSA key pair
 * @param keySize Key size in bits (default: 2048)
 * @return Dictionary containing PEM-formatted public and private keys, nil if generation fails
 */
+ (nullable NSDictionary *)generateKeyPair:(NSInteger)keySize;

/**
 * Encrypt message with RSA public key
 * @param message Plain text message
 * @param publicKeyPem PEM-formatted public key
 * @return Base64-encoded encrypted data, nil if encryption fails
 */
+ (nullable NSString *)encrypt:(NSString *)message publicKeyPem:(NSString *)publicKeyPem;

/**
 * Encrypt Base64-encoded message with RSA public key
 * @param messageBase64 Base64-encoded message
 * @param publicKeyPem PEM-formatted public key
 * @return Base64-encoded encrypted data, nil if encryption fails
 */
+ (nullable NSString *)encryptBase64:(NSString *)messageBase64 publicKeyPem:(NSString *)publicKeyPem;

/**
 * Decrypt message with RSA private key
 * @param encryptedMessage Base64-encoded encrypted message
 * @param privateKeyPem PEM-formatted private key
 * @return Plain text message, nil if decryption fails
 */
+ (nullable NSString *)decrypt:(NSString *)encryptedMessage privateKeyPem:(NSString *)privateKeyPem;

/**
 * Decrypt message with RSA private key, return Base64
 * @param encryptedMessage Base64-encoded encrypted message
 * @param privateKeyPem PEM-formatted private key
 * @return Base64-encoded decrypted data, nil if decryption fails
 */
+ (nullable NSString *)decryptToBase64:(NSString *)encryptedMessage privateKeyPem:(NSString *)privateKeyPem;

/**
 * Sign message with RSA private key
 * @param message Message to sign
 * @param privateKeyPem PEM-formatted private key
 * @param hashAlgorithm Hash algorithm (default: SHA1)
 * @return Base64-encoded signature, nil if signing fails
 */
+ (nullable NSString *)sign:(NSString *)message privateKeyPem:(NSString *)privateKeyPem hashAlgorithm:(nullable NSString *)hashAlgorithm;

/**
 * Sign Base64-encoded message with RSA private key
 * @param messageBase64 Base64-encoded message to sign
 * @param privateKeyPem PEM-formatted private key
 * @param hashAlgorithm Hash algorithm (default: SHA1)
 * @return Base64-encoded signature, nil if signing fails
 */
+ (nullable NSString *)signBase64:(NSString *)messageBase64 privateKeyPem:(NSString *)privateKeyPem hashAlgorithm:(nullable NSString *)hashAlgorithm;

/**
 * Verify signature with RSA public key
 * @param signatureBase64 Base64-encoded signature
 * @param message Original message
 * @param publicKeyPem PEM-formatted public key
 * @param hashAlgorithm Hash algorithm (default: SHA1)
 * @return YES if signature is valid, NO otherwise
 */
+ (BOOL)verify:(NSString *)signatureBase64 message:(NSString *)message publicKeyPem:(NSString *)publicKeyPem hashAlgorithm:(nullable NSString *)hashAlgorithm;

/**
 * Verify signature with RSA public key for Base64-encoded message
 * @param signatureBase64 Base64-encoded signature
 * @param messageBase64 Base64-encoded original message
 * @param publicKeyPem PEM-formatted public key
 * @param hashAlgorithm Hash algorithm (default: SHA1)
 * @return YES if signature is valid, NO otherwise
 */
+ (BOOL)verifyBase64:(NSString *)signatureBase64 messageBase64:(NSString *)messageBase64 publicKeyPem:(NSString *)publicKeyPem hashAlgorithm:(nullable NSString *)hashAlgorithm;

/**
 * Import JWK format key to PEM format
 * @param jwk JWK key data
 * @return PEM-formatted key, nil if conversion fails
 */
+ (nullable NSString *)importJwkKey:(NSDictionary *)jwk;

/**
 * Export PEM key to JWK format
 * @param pemKey PEM-formatted key
 * @return JWK key data, nil if conversion fails
 */
+ (nullable NSDictionary *)exportPemKey:(NSString *)pemKey;

// Helper methods
+ (nullable NSString *)pemFormat:(NSData *)keyData tag:(NSString *)tag;
+ (nullable NSData *)pemParse:(NSString *)pemString;
+ (nullable SecKeyRef)createKeyFromPem:(NSString *)pemString isPublic:(BOOL)isPublic;
+ (SecKeyAlgorithm)algorithmFromHash:(nullable NSString *)hash forSigning:(BOOL)forSigning;

// JWK Helper methods
+ (NSData *)base64URLDecodeString:(NSString *)string;
+ (NSString *)base64URLEncodeData:(NSData *)data;
+ (NSData *)createASN1IntegerFromBigInteger:(NSData *)integerData;
+ (NSData *)createRSAPublicKeyASN1:(NSData *)modulus exponent:(NSData *)exponent;
+ (NSData *)createRSAPrivateKeyASN1:(NSData *)modulus exponent:(NSData *)publicExponent d:(NSData *)privateExponent p:(NSData *)p q:(NSData *)q dp:(NSData *)dp dq:(NSData *)dq qi:(NSData *)qi;
+ (NSData *)parseASN1Integer:(NSData *)data offset:(NSUInteger *)offset;
+ (NSDictionary *)parseRSAPublicKeyASN1:(NSData *)asn1Data;
+ (NSDictionary *)parseRSAPrivateKeyASN1:(NSData *)asn1Data;

@end

NS_ASSUME_NONNULL_END
