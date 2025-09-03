#import "FileUtils.h"
#import "CryptoUtils.h"
#import "SHACrypto.h"
#import <CommonCrypto/CommonDigest.h>

@implementation FileUtils

static const NSUInteger BUFFER_SIZE = 4096;

+ (nullable NSString *)calculateSha256Checksum:(NSString *)filePath {
    return [self calculateChecksum:filePath algorithm:@"SHA-256"];
}

+ (nullable NSString *)calculateSha1Checksum:(NSString *)filePath {
    return [self calculateChecksum:filePath algorithm:@"SHA-1"];
}

+ (nullable NSString *)calculateSha512Checksum:(NSString *)filePath {
    return [self calculateChecksum:filePath algorithm:@"SHA-512"];
}

+ (nullable NSString *)calculateChecksum:(NSString *)filePath algorithm:(NSString *)algorithm {
    NSString *normalizedPath = [self normalizeFilePath:filePath];
    
    NSInputStream *inputStream = [NSInputStream inputStreamWithFileAtPath:normalizedPath];
    if (!inputStream) {
        return nil;
    }
    
    [inputStream open];
    
    // Initialize the appropriate context based on algorithm
    CC_SHA1_CTX sha1Context;
    CC_SHA256_CTX sha256Context;
    CC_SHA512_CTX sha512Context;
    
    if ([algorithm isEqualToString:@"SHA-1"]) {
        CC_SHA1_Init(&sha1Context);
    } else if ([algorithm isEqualToString:@"SHA-256"]) {
        CC_SHA256_Init(&sha256Context);
    } else if ([algorithm isEqualToString:@"SHA-512"]) {
        CC_SHA512_Init(&sha512Context);
    } else {
        [inputStream close];
        return nil;
    }
    
    uint8_t buffer[BUFFER_SIZE];
    NSInteger bytesRead;
    
    while ((bytesRead = [inputStream read:buffer maxLength:sizeof(buffer)]) > 0) {
        if ([algorithm isEqualToString:@"SHA-1"]) {
            CC_SHA1_Update(&sha1Context, buffer, (CC_LONG)bytesRead);
        } else if ([algorithm isEqualToString:@"SHA-256"]) {
            CC_SHA256_Update(&sha256Context, buffer, (CC_LONG)bytesRead);
        } else if ([algorithm isEqualToString:@"SHA-512"]) {
            CC_SHA512_Update(&sha512Context, buffer, (CC_LONG)bytesRead);
        }
    }
    
    [inputStream close];
    
    if (bytesRead < 0) {
        return nil;
    }
    
    NSData *hashData = nil;
    
    if ([algorithm isEqualToString:@"SHA-1"]) {
        unsigned char hash[CC_SHA1_DIGEST_LENGTH];
        CC_SHA1_Final(hash, &sha1Context);
        hashData = [NSData dataWithBytes:hash length:CC_SHA1_DIGEST_LENGTH];
    } else if ([algorithm isEqualToString:@"SHA-256"]) {
        unsigned char hash[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256_Final(hash, &sha256Context);
        hashData = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
    } else if ([algorithm isEqualToString:@"SHA-512"]) {
        unsigned char hash[CC_SHA512_DIGEST_LENGTH];
        CC_SHA512_Final(hash, &sha512Context);
        hashData = [NSData dataWithBytes:hash length:CC_SHA512_DIGEST_LENGTH];
    }
    
    if (hashData) {
        return [CryptoUtils bytesToHex:hashData];
    }
    return nil;
}

+ (nullable NSString *)calculateChecksumBase64:(NSString *)filePath algorithm:(NSString *)algorithm {
    NSString *hexChecksum = [self calculateChecksum:filePath algorithm:algorithm];
    if (hexChecksum) {
        NSData *checksumData = [CryptoUtils fromHex:hexChecksum];
        return [CryptoUtils encodeBase64:checksumData];
    }
    return nil;
}

+ (long long)getFileSize:(NSString *)filePath {
    NSString *normalizedPath = [self normalizeFilePath:filePath];
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSError *error = nil;
    NSDictionary *attributes = [fileManager attributesOfItemAtPath:normalizedPath error:&error];
    
    if (error) {
        return -1;
    }
    
    NSNumber *fileSize = attributes[NSFileSize];
    return [fileSize longLongValue];
}

+ (BOOL)fileExists:(NSString *)filePath {
    NSString *normalizedPath = [self normalizeFilePath:filePath];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    return [fileManager fileExistsAtPath:normalizedPath];
}

+ (BOOL)verifyFileIntegrity:(NSString *)filePath expectedChecksum:(NSString *)expectedChecksum algorithm:(NSString *)algorithm {
    NSString *actualChecksum = [self calculateChecksum:filePath algorithm:algorithm];
    if (!actualChecksum) {
        return NO;
    }
    
    return [actualChecksum.lowercaseString isEqualToString:expectedChecksum.lowercaseString];
}

+ (nullable NSDictionary<NSString *, NSString *> *)calculateMultipleChecksums:(NSString *)filePath algorithms:(NSArray<NSString *> *)algorithms {
    NSString *normalizedPath = [self normalizeFilePath:filePath];
    
    NSInputStream *inputStream = [NSInputStream inputStreamWithFileAtPath:normalizedPath];
    if (!inputStream) {
        return nil;
    }
    
    [inputStream open];
    
    // Initialize contexts for all requested algorithms
    NSMutableDictionary *contexts = [NSMutableDictionary dictionary];
    
    for (NSString *algorithm in algorithms) {
        if ([algorithm isEqualToString:@"SHA-1"]) {
            CC_SHA1_CTX *context = malloc(sizeof(CC_SHA1_CTX));
            CC_SHA1_Init(context);
            contexts[algorithm] = [NSValue valueWithPointer:context];
        } else if ([algorithm isEqualToString:@"SHA-256"]) {
            CC_SHA256_CTX *context = malloc(sizeof(CC_SHA256_CTX));
            CC_SHA256_Init(context);
            contexts[algorithm] = [NSValue valueWithPointer:context];
        } else if ([algorithm isEqualToString:@"SHA-512"]) {
            CC_SHA512_CTX *context = malloc(sizeof(CC_SHA512_CTX));
            CC_SHA512_Init(context);
            contexts[algorithm] = [NSValue valueWithPointer:context];
        }
    }
    
    uint8_t buffer[BUFFER_SIZE];
    NSInteger bytesRead;
    
    while ((bytesRead = [inputStream read:buffer maxLength:sizeof(buffer)]) > 0) {
        for (NSString *algorithm in algorithms) {
            NSValue *contextValue = contexts[algorithm];
            if (contextValue) {
                void *context = [contextValue pointerValue];
                if ([algorithm isEqualToString:@"SHA-1"]) {
                    CC_SHA1_Update((CC_SHA1_CTX *)context, buffer, (CC_LONG)bytesRead);
                } else if ([algorithm isEqualToString:@"SHA-256"]) {
                    CC_SHA256_Update((CC_SHA256_CTX *)context, buffer, (CC_LONG)bytesRead);
                } else if ([algorithm isEqualToString:@"SHA-512"]) {
                    CC_SHA512_Update((CC_SHA512_CTX *)context, buffer, (CC_LONG)bytesRead);
                }
            }
        }
    }
    
    [inputStream close];
    
    if (bytesRead < 0) {
        // Cleanup contexts
        for (NSString *algorithm in algorithms) {
            NSValue *contextValue = contexts[algorithm];
            if (contextValue) {
                free([contextValue pointerValue]);
            }
        }
        return nil;
    }
    
    NSMutableDictionary *results = [NSMutableDictionary dictionary];
    
    for (NSString *algorithm in algorithms) {
        NSValue *contextValue = contexts[algorithm];
        if (contextValue) {
            void *context = [contextValue pointerValue];
            NSData *hashData = nil;
            
            if ([algorithm isEqualToString:@"SHA-1"]) {
                unsigned char hash[CC_SHA1_DIGEST_LENGTH];
                CC_SHA1_Final(hash, (CC_SHA1_CTX *)context);
                hashData = [NSData dataWithBytes:hash length:CC_SHA1_DIGEST_LENGTH];
            } else if ([algorithm isEqualToString:@"SHA-256"]) {
                unsigned char hash[CC_SHA256_DIGEST_LENGTH];
                CC_SHA256_Final(hash, (CC_SHA256_CTX *)context);
                hashData = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
            } else if ([algorithm isEqualToString:@"SHA-512"]) {
                unsigned char hash[CC_SHA512_DIGEST_LENGTH];
                CC_SHA512_Final(hash, (CC_SHA512_CTX *)context);
                hashData = [NSData dataWithBytes:hash length:CC_SHA512_DIGEST_LENGTH];
            }
            
            if (hashData) {
                results[algorithm] = [CryptoUtils bytesToHex:hashData];
            }
            
            free(context);
        }
    }
    
    return results;
}

+ (NSString *)normalizeFilePath:(NSString *)filePath {
    if ([filePath hasPrefix:@"file://"]) {
        return [filePath substringFromIndex:7];
    }
    return filePath;
}

@end
