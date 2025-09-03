#import "SHACrypto.h"
#import "CryptoUtils.h"
#import <CommonCrypto/CommonDigest.h>

@implementation SHACrypto

+ (nullable NSData *)hashData:(NSData *)data withAlgorithm:(NSString *)algorithm {
    if ([algorithm isEqualToString:@"SHA-1"]) {
        unsigned char hash[CC_SHA1_DIGEST_LENGTH];
        CC_SHA1(data.bytes, (CC_LONG)data.length, hash);
        return [NSData dataWithBytes:hash length:CC_SHA1_DIGEST_LENGTH];
    } else if ([algorithm isEqualToString:@"SHA-256"]) {
        unsigned char hash[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
        return [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
    } else if ([algorithm isEqualToString:@"SHA-384"]) {
        unsigned char hash[CC_SHA384_DIGEST_LENGTH];
        CC_SHA384(data.bytes, (CC_LONG)data.length, hash);
        return [NSData dataWithBytes:hash length:CC_SHA384_DIGEST_LENGTH];
    } else if ([algorithm isEqualToString:@"SHA-512"]) {
        unsigned char hash[CC_SHA512_DIGEST_LENGTH];
        CC_SHA512(data.bytes, (CC_LONG)data.length, hash);
        return [NSData dataWithBytes:hash length:CC_SHA512_DIGEST_LENGTH];
    }
    return nil;
}

+ (nullable NSString *)hashBase64:(NSString *)dataBase64 algorithm:(NSString *)algorithm {
    NSData *inputData = [CryptoUtils decodeBase64:dataBase64];
    if (!inputData) {
        return nil;
    }
    
    NSData *hashData = [self hashData:inputData withAlgorithm:algorithm];
    if (hashData) {
        return [CryptoUtils encodeBase64:hashData];
    }
    return nil;
}

+ (nullable NSString *)hashUtf8ToHex:(NSString *)data algorithm:(NSString *)algorithm {
    NSData *inputData = [CryptoUtils stringToUtf8Data:data];
    NSData *hashData = [self hashData:inputData withAlgorithm:algorithm];
    if (hashData) {
        return [CryptoUtils bytesToHex:hashData];
    }
    return nil;
}

+ (nullable NSString *)hashUtf8ToBase64:(NSString *)data algorithm:(NSString *)algorithm {
    NSData *inputData = [CryptoUtils stringToUtf8Data:data];
    NSData *hashData = [self hashData:inputData withAlgorithm:algorithm];
    if (hashData) {
        return [CryptoUtils encodeBase64:hashData];
    }
    return nil;
}

+ (nullable NSString *)hashToHex:(NSData *)data algorithm:(NSString *)algorithm {
    NSData *hashData = [self hashData:data withAlgorithm:algorithm];
    if (hashData) {
        return [CryptoUtils bytesToHex:hashData];
    }
    return nil;
}

+ (nullable NSString *)hashToBase64:(NSData *)data algorithm:(NSString *)algorithm {
    NSData *hashData = [self hashData:data withAlgorithm:algorithm];
    if (hashData) {
        return [CryptoUtils encodeBase64:hashData];
    }
    return nil;
}

+ (NSArray<NSString *> *)supportedAlgorithms {
    return @[@"SHA-1", @"SHA-256", @"SHA-384", @"SHA-512"];
}

+ (BOOL)isAlgorithmSupported:(NSString *)algorithm {
    return [[self supportedAlgorithms] containsObject:algorithm];
}

@end
