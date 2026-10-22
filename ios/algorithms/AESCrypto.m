#import "AESCrypto.h"
#import "CryptoUtils.h"
#import "FileUtils.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation AESCrypto

+ (nullable NSString *)encryptFile:(NSString *)filePath base64UrlKey:(NSString *)base64UrlKey base64Iv:(NSString *)base64Iv {
    return [self processFile:filePath operation:kCCEncrypt base64UrlKey:base64UrlKey base64Iv:base64Iv];
}

+ (nullable NSString *)decryptFile:(NSString *)filePath base64UrlKey:(NSString *)base64UrlKey base64Iv:(NSString *)base64Iv {
    return [self processFile:filePath operation:kCCDecrypt base64UrlKey:base64UrlKey base64Iv:base64Iv];
}

+ (nullable NSString *)processFile:(NSString *)filePath operation:(CCOperation)operation base64UrlKey:(NSString *)base64UrlKey base64Iv:(NSString *)base64Iv {
    NSString *keyBase64 = [CryptoUtils base64FromBase64URL:base64UrlKey];
    NSData *keyData = [CryptoUtils decodeBase64:keyBase64];
    NSData *ivData = [CryptoUtils decodeBase64:base64Iv];

    NSString *normalizedFilePath = [FileUtils normalizeFilePath:filePath];

    // Check if input file exists
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:normalizedFilePath]) {
        return nil;
    }

    NSString *outputFileName = [@"processed_" stringByAppendingString:[normalizedFilePath lastPathComponent]];
    NSString *outputFilePath = [[normalizedFilePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:outputFileName];

    NSInputStream *inputStream = [NSInputStream inputStreamWithFileAtPath:normalizedFilePath];
    NSOutputStream *outputStream = [NSOutputStream outputStreamToFileAtPath:outputFilePath append:NO];

    // Validate stream creation
    if (!inputStream || !outputStream) {
        return nil;
    }

    [inputStream open];
    [outputStream open];

    // Validate stream opening
    if ([inputStream streamStatus] != NSStreamStatusOpen || [outputStream streamStatus] != NSStreamStatusOpen) {
        [inputStream close];
        [outputStream close];
        [fileManager removeItemAtPath:outputFilePath error:nil];
        return nil;
    }

    size_t bufferSize = 65536;
    uint8_t buffer[bufferSize];
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = CCCryptorCreateWithMode(operation, kCCModeCTR, kCCAlgorithmAES, ccNoPadding, ivData.bytes, keyData.bytes, keyData.length, NULL, 0, 0, kCCModeOptionCTR_BE, &cryptor);
    if (status != kCCSuccess) {
        NSLog(@"Failed to create cryptor: %d", status);
        [inputStream close];
        [outputStream close];
        [fileManager removeItemAtPath:outputFilePath error:nil];
        return nil;
    }

    BOOL loopSuccess = YES;

    while ([inputStream hasBytesAvailable]) {
        NSInteger bytesRead = [inputStream read:buffer maxLength:sizeof(buffer)];
        if (bytesRead > 0) {

            size_t dataOutMoved;
            status = CCCryptorUpdate(cryptor, buffer, bytesRead, buffer, bufferSize, &dataOutMoved);
            if (status == kCCSuccess) {
                NSInteger bytesWritten = [outputStream write:buffer maxLength:dataOutMoved];
                if (bytesWritten != (NSInteger)dataOutMoved) {
                    loopSuccess = NO;
                    break;
                }
            } else {
                NSLog(@"Cryptor update failed: %d", status);
                loopSuccess = NO;
                break;
            }
        } else if (bytesRead < 0) {
            NSLog(@"Input stream read error");
            loopSuccess = NO;
            break;
        }
    }

    if (loopSuccess) {
        size_t finalBytesOut;
        status = CCCryptorFinal(cryptor, buffer, bufferSize, &finalBytesOut);
        if (status == kCCSuccess && finalBytesOut > 0) {
            NSInteger finalBytesWritten = [outputStream write:buffer maxLength:finalBytesOut];
            if (finalBytesWritten != (NSInteger)finalBytesOut) {
                NSLog(@"Output stream write error on final block");
                loopSuccess = NO;
            }
        } else if (status != kCCSuccess) {
            NSLog(@"Cryptor final failed: %d", status);
        }
    }

    CCCryptorRelease(cryptor);
    [inputStream close];
    [outputStream close];

    if (status != kCCSuccess || !loopSuccess) {
        [[NSFileManager defaultManager] removeItemAtPath:outputFilePath error:nil];
        return nil;
    }

    if (operation == kCCDecrypt) {
        // For decrypt: atomically replace the original file with decrypted content
        NSURL *originalFileURL = [NSURL fileURLWithPath:normalizedFilePath];
        NSURL *outputFileURL = [NSURL fileURLWithPath:outputFilePath];
        NSError *error = nil;
        BOOL success = [[NSFileManager defaultManager] replaceItemAtURL:originalFileURL
                                                           withItemAtURL:outputFileURL
                                                          backupItemName:nil
                                                                 options:NSFileManagerItemReplacementUsingNewMetadataOnly
                                                        resultingItemURL:nil
                                                                   error:&error];
        if (!success) {
            NSLog(@"Failed to replace original file: %@", error);
            [[NSFileManager defaultManager] removeItemAtPath:outputFilePath error:nil];
            return nil;
        }
        return [NSString stringWithFormat:@"file://%@", normalizedFilePath];
    } else {
        // For encrypt: return the processed file path
        return [NSString stringWithFormat:@"file://%@", outputFilePath];
    }
}

@end
