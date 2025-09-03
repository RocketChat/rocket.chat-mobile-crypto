#import "RandomUtils.h"
#import "CryptoUtils.h"
#import <Security/Security.h>

@implementation RandomUtils

static NSString * const ALPHANUMERIC_CHARS = @"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

+ (NSString *)generateUuid {
    return [[NSUUID UUID] UUIDString];
}

+ (nullable NSString *)generateRandomKeyHex:(NSUInteger)length {
    NSData *keyData = [self generateRandomBytes:length];
    if (keyData) {
        return [CryptoUtils bytesToHex:keyData];
    }
    return nil;
}

+ (nullable NSString *)generateRandomBytesBase64:(NSUInteger)size {
    NSData *randomData = [self generateRandomBytes:size];
    if (randomData) {
        return [CryptoUtils encodeBase64:randomData];
    }
    return nil;
}

+ (nullable NSData *)generateRandomBytes:(NSUInteger)size {
    NSMutableData *randomData = [NSMutableData dataWithLength:size];
    int result = SecRandomCopyBytes(kSecRandomDefault, randomData.length, randomData.mutableBytes);
    if (result == errSecSuccess) {
        return randomData;
    } else {
        NSLog(@"Failed to generate random bytes");
        return nil;
    }
}

+ (NSString *)generateRandomAlphanumeric:(NSUInteger)length {
    NSMutableString *result = [NSMutableString stringWithCapacity:length];
    
    for (NSUInteger i = 0; i < length; i++) {
        uint32_t randomIndex = arc4random_uniform((uint32_t)[ALPHANUMERIC_CHARS length]);
        [result appendFormat:@"%C", [ALPHANUMERIC_CHARS characterAtIndex:randomIndex]];
    }
    
    return [NSString stringWithString:result];
}

+ (NSInteger)generateRandomIntMin:(NSInteger)min max:(NSInteger)max {
    if (max <= min) {
        return min;
    }
    uint32_t range = (uint32_t)(max - min);
    return min + (NSInteger)arc4random_uniform(range);
}

+ (BOOL)generateRandomBoolean {
    return arc4random_uniform(2) == 1;
}

+ (nullable NSData *)generateRandomIV:(NSUInteger)size {
    if (size == 0) {
        size = 16; // Default AES block size
    }
    return [self generateRandomBytes:size];
}

+ (nullable NSString *)generateRandomIVHex:(NSUInteger)size {
    if (size == 0) {
        size = 16; // Default AES block size
    }
    return [self generateRandomKeyHex:size];
}

+ (nullable NSData *)generateRandomSalt:(NSUInteger)size {
    if (size == 0) {
        size = 32; // Default salt size
    }
    return [self generateRandomBytes:size];
}

+ (nullable NSString *)generateRandomSaltBase64:(NSUInteger)size {
    if (size == 0) {
        size = 32; // Default salt size
    }
    return [self generateRandomBytesBase64:size];
}

@end
