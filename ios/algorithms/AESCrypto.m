#import "AESCrypto.h"
#import "CryptoUtils.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation AESCrypto

+ (nullable NSString *)encryptBase64:(NSString *)dataBase64 keyHex:(NSString *)keyHex ivHex:(NSString *)ivHex {
    if (!dataBase64 || dataBase64.length == 0) {
        return nil;
    }
    
    NSData *clearData = [CryptoUtils decodeBase64:dataBase64];
    if (!clearData) {
        return nil;
    }
    
    NSData *result = [self aes128CBC:@"encrypt" data:clearData key:keyHex iv:ivHex];
    if (result) {
        return [CryptoUtils encodeBase64:result];
    }
    return nil;
}

+ (nullable NSString *)decryptBase64:(NSString *)dataBase64 keyHex:(NSString *)keyHex ivHex:(NSString *)ivHex {
    if (!dataBase64 || dataBase64.length == 0) {
        return nil;
    }
    
    NSData *cipherData = [CryptoUtils decodeBase64:dataBase64];
    if (!cipherData) {
        return nil;
    }
    
    NSData *result = [self aes128CBC:@"decrypt" data:cipherData key:keyHex iv:ivHex];
    if (result) {
        return [CryptoUtils encodeBase64:result];
    }
    return nil;
}

+ (nullable NSString *)encryptFile:(NSString *)filePath base64UrlKey:(NSString *)base64UrlKey base64Iv:(NSString *)base64Iv {
    return [self processFile:filePath operation:kCCEncrypt base64UrlKey:base64UrlKey base64Iv:base64Iv];
}

+ (nullable NSString *)decryptFile:(NSString *)filePath base64UrlKey:(NSString *)base64UrlKey base64Iv:(NSString *)base64Iv {
    return [self processFile:filePath operation:kCCDecrypt base64UrlKey:base64UrlKey base64Iv:base64Iv];
}

+ (nullable NSData *)aes128CBC:(NSString *)operation data:(NSData *)data key:(NSString *)key iv:(NSString *)iv {
    NSData *keyData = [CryptoUtils fromHex:key];
    NSData *ivData = [CryptoUtils fromHex:iv];
    size_t numBytes = 0;
    NSMutableData *buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];

    CCCryptorStatus cryptStatus = CCCrypt(
        [operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
        kCCAlgorithmAES128,
        kCCOptionPKCS7Padding,
        keyData.bytes,
        keyData.length,
        ivData.bytes,
        data.bytes, data.length,
        buffer.mutableBytes,
        buffer.length,
        &numBytes);

    if (cryptStatus == kCCSuccess) {
        [buffer setLength:numBytes];
        return buffer;
    }
    NSLog(@"AES error, %d", cryptStatus);
    return nil;
}

+ (nullable NSString *)processFile:(NSString *)filePath operation:(CCOperation)operation base64UrlKey:(NSString *)base64UrlKey base64Iv:(NSString *)base64Iv {
    NSString *keyBase64 = [CryptoUtils base64FromBase64URL:base64UrlKey];
    NSData *keyData = [CryptoUtils decodeBase64:keyBase64];
    NSData *ivData = [CryptoUtils decodeBase64:base64Iv];

    NSString *normalizedFilePath = [filePath stringByReplacingOccurrencesOfString:@"file://" withString:@""];
    NSString *outputFileName = [@"processed_" stringByAppendingString:[normalizedFilePath lastPathComponent]];
    NSString *outputFilePath = [[normalizedFilePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:outputFileName];
    
    NSInputStream *inputStream = [NSInputStream inputStreamWithFileAtPath:normalizedFilePath];
    NSOutputStream *outputStream = [NSOutputStream outputStreamToFileAtPath:outputFilePath append:NO];
    [inputStream open];
    [outputStream open];

    size_t bufferSize = 4096;
    uint8_t buffer[bufferSize];
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = CCCryptorCreateWithMode(operation, kCCModeCTR, kCCAlgorithmAES, ccNoPadding, ivData.bytes, keyData.bytes, keyData.length, NULL, 0, 0, kCCModeOptionCTR_BE, &cryptor);
    if (status != kCCSuccess) {
        NSLog(@"Failed to create cryptor: %d", status);
        [inputStream close];
        [outputStream close];
        return nil;
    }

    while ([inputStream hasBytesAvailable]) {
        NSInteger bytesRead = [inputStream read:buffer maxLength:sizeof(buffer)];
        if (bytesRead > 0) {
            size_t dataOutMoved;
            status = CCCryptorUpdate(cryptor, buffer, bytesRead, buffer, bufferSize, &dataOutMoved);
            if (status == kCCSuccess) {
                [outputStream write:buffer maxLength:dataOutMoved];
            } else {
                NSLog(@"Cryptor update failed: %d", status);
                CCCryptorRelease(cryptor);
                [inputStream close];
                [outputStream close];
                return nil;
            }
        } else if (bytesRead < 0) {
            NSLog(@"Input stream read error");
            CCCryptorRelease(cryptor);
            [inputStream close];
            [outputStream close];
            return nil;
        }
    }

    if (status == kCCSuccess) {
        size_t finalBytesOut;
        status = CCCryptorFinal(cryptor, buffer, bufferSize, &finalBytesOut);
        if (status == kCCSuccess) {
            [outputStream write:buffer maxLength:finalBytesOut];
        } else {
            NSLog(@"Cryptor final failed: %d", status);
            CCCryptorRelease(cryptor);
            [inputStream close];
            [outputStream close];
            return nil;
        }
    }

    CCCryptorRelease(cryptor);
    [inputStream close];
    [outputStream close];

    if (status == kCCSuccess) {
        NSURL *originalFileURL = [NSURL fileURLWithPath:normalizedFilePath];
        NSURL *outputFileURL = [NSURL fileURLWithPath:outputFilePath];
        NSError *error = nil;
        [[NSFileManager defaultManager] replaceItemAtURL:originalFileURL
                                          withItemAtURL:outputFileURL
                                         backupItemName:nil
                                                options:NSFileManagerItemReplacementUsingNewMetadataOnly
                                       resultingItemURL:nil
                                                  error:&error];
        if (error) {
            NSLog(@"Failed to replace original file: %@", error);
            return nil;
        }
        return [NSString stringWithFormat:@"file://%@", normalizedFilePath];
    } else {
        [[NSFileManager defaultManager] removeItemAtPath:outputFilePath error:nil];
        return nil;
    }
}

@end
