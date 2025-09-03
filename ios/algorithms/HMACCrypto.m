#import "HMACCrypto.h"
#import "CryptoUtils.h"
#import <CommonCrypto/CommonHMAC.h>

@implementation HMACCrypto

+ (nullable NSString *)hmacSha256Hex:(NSString *)dataHex keyHex:(NSString *)keyHex {
    NSData *contentData = [CryptoUtils fromHex:dataHex];
    NSData *keyData = [CryptoUtils fromHex:keyHex];
    
    NSData *hmacData = [self computeHmac:contentData key:keyData algorithm:HMACAlgorithmSHA256];
    if (hmacData) {
        return [CryptoUtils bytesToHex:hmacData];
    }
    return nil;
}

+ (nullable NSData *)computeHmac:(NSData *)data key:(NSData *)key algorithm:(HMACAlgorithm)algorithm {
    CCHmacAlgorithm ccAlgorithm;
    NSUInteger digestLength;
    
    switch (algorithm) {
        case HMACAlgorithmSHA1:
            ccAlgorithm = kCCHmacAlgSHA1;
            digestLength = CC_SHA1_DIGEST_LENGTH;
            break;
        case HMACAlgorithmSHA224:
            ccAlgorithm = kCCHmacAlgSHA224;
            digestLength = CC_SHA224_DIGEST_LENGTH;
            break;
        case HMACAlgorithmSHA256:
            ccAlgorithm = kCCHmacAlgSHA256;
            digestLength = CC_SHA256_DIGEST_LENGTH;
            break;
        case HMACAlgorithmSHA384:
            ccAlgorithm = kCCHmacAlgSHA384;
            digestLength = CC_SHA384_DIGEST_LENGTH;
            break;
        case HMACAlgorithmSHA512:
            ccAlgorithm = kCCHmacAlgSHA512;
            digestLength = CC_SHA512_DIGEST_LENGTH;
            break;
        default:
            return nil;
    }
    
    NSMutableData *hash = [NSMutableData dataWithLength:digestLength];
    CCHmac(ccAlgorithm, key.bytes, key.length, data.bytes, data.length, hash.mutableBytes);
    
    return hash;
}

+ (nullable NSString *)hmacBase64:(NSString *)dataBase64 keyBase64:(NSString *)keyBase64 algorithm:(HMACAlgorithm)algorithm {
    NSData *dataBytes = [CryptoUtils decodeBase64:dataBase64];
    NSData *keyBytes = [CryptoUtils decodeBase64:keyBase64];
    
    if (!dataBytes || !keyBytes) {
        return nil;
    }
    
    NSData *hmacBytes = [self computeHmac:dataBytes key:keyBytes algorithm:algorithm];
    if (hmacBytes) {
        return [CryptoUtils encodeBase64:hmacBytes];
    }
    return nil;
}

+ (nullable NSString *)hmacStringBase64:(NSString *)data keyBase64:(NSString *)keyBase64 algorithm:(HMACAlgorithm)algorithm {
    NSData *dataBytes = [CryptoUtils stringToUtf8Data:data];
    NSData *keyBytes = [CryptoUtils decodeBase64:keyBase64];
    
    if (!dataBytes || !keyBytes) {
        return nil;
    }
    
    NSData *hmacBytes = [self computeHmac:dataBytes key:keyBytes algorithm:algorithm];
    if (hmacBytes) {
        return [CryptoUtils encodeBase64:hmacBytes];
    }
    return nil;
}

+ (HMACAlgorithm)algorithmByName:(NSString *)name {
    NSString *upperName = [name uppercaseString];
    
    if ([upperName isEqualToString:@"SHA1"] || [upperName isEqualToString:@"HMACSHA1"]) {
        return HMACAlgorithmSHA1;
    } else if ([upperName isEqualToString:@"SHA224"] || [upperName isEqualToString:@"HMACSHA224"]) {
        return HMACAlgorithmSHA224;
    } else if ([upperName isEqualToString:@"SHA256"] || [upperName isEqualToString:@"HMACSHA256"]) {
        return HMACAlgorithmSHA256;
    } else if ([upperName isEqualToString:@"SHA384"] || [upperName isEqualToString:@"HMACSHA384"]) {
        return HMACAlgorithmSHA384;
    } else if ([upperName isEqualToString:@"SHA512"] || [upperName isEqualToString:@"HMACSHA512"]) {
        return HMACAlgorithmSHA512;
    }
    
    return -1; // Unsupported algorithm
}

+ (NSArray<NSString *> *)supportedAlgorithms {
    return @[@"SHA1", @"SHA224", @"SHA256", @"SHA384", @"SHA512"];
}

@end
