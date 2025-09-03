#import "PBKDF2Crypto.h"
#import "CryptoUtils.h"
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonCryptoError.h>

@implementation PBKDF2Crypto

+ (nullable NSString *)deriveKeyBase64:(NSString *)passwordBase64
                            saltBase64:(NSString *)saltBase64
                            iterations:(NSUInteger)iterations
                             keyLength:(NSUInteger)keyLength
                         hashAlgorithm:(NSString *)hashAlgorithm {
    
    NSData *passwordData = [CryptoUtils decodeBase64:passwordBase64];
    NSData *saltData = [CryptoUtils decodeBase64:saltBase64];
    
    if (!passwordData || !saltData || keyLength == 0 || iterations == 0) {
        return nil;
    }
    
    NSData *derivedKey = [self deriveKey:passwordData
                                saltData:saltData
                              iterations:iterations
                               keyLength:keyLength
                           hashAlgorithm:hashAlgorithm];
    
    if (derivedKey) {
        return [CryptoUtils encodeBase64:derivedKey];
    }
    return nil;
}

+ (nullable NSData *)deriveKey:(NSData *)passwordData
                      saltData:(NSData *)saltData
                    iterations:(NSUInteger)iterations
                     keyLength:(NSUInteger)keyLength
                 hashAlgorithm:(NSString *)hashAlgorithm {
    
    // Algorithm mapping using dictionary like the original code
    NSDictionary *algMap = @{
        @"SHA1" : [NSNumber numberWithInt:kCCPRFHmacAlgSHA1],
        @"SHA224" : [NSNumber numberWithInt:kCCPRFHmacAlgSHA224],
        @"SHA256" : [NSNumber numberWithInt:kCCPRFHmacAlgSHA256],
        @"SHA384" : [NSNumber numberWithInt:kCCPRFHmacAlgSHA384],
        @"SHA512" : [NSNumber numberWithInt:kCCPRFHmacAlgSHA512],
    };
    
    NSNumber *algNumber = [algMap valueForKey:hashAlgorithm];
    if (!algNumber) {
        algNumber = [algMap valueForKey:@"SHA1"]; // Default to SHA1
    }
    int alg = [algNumber intValue];
    
    // Hash key data length - using same variable name as original
    NSMutableData *hashKeyData = [NSMutableData dataWithLength:keyLength];
    if (!hashKeyData || hashKeyData.length == 0) {
        return nil;
    }
    
    // Key Derivation using PBKDF2 algorithm
    int status = CCKeyDerivationPBKDF(
        kCCPBKDF2,
        (const char *)passwordData.bytes,
        passwordData.length,
        (const uint8_t *)saltData.bytes,
        saltData.length,
        (CCPseudoRandomAlgorithm)alg,
        (unsigned)(int)iterations,
        (uint8_t *)hashKeyData.mutableBytes,
        hashKeyData.length
    );
    
    if (status == kCCSuccess) {
        return hashKeyData;
    } else {
        NSLog(@"PBKDF2 derivation failed with status: %d", status);
        return nil;
    }
}

+ (NSArray<NSString *> *)supportedAlgorithms {
    return @[@"SHA1", @"SHA224", @"SHA256", @"SHA384", @"SHA512"];
}

@end
