#import "MobileCrypto.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>

@implementation MobileCrypto
RCT_EXPORT_MODULE()

// MARK: - Helper Methods

- (NSData *)hexToBytes:(NSString *)hex {
    NSMutableData *data = [[NSMutableData alloc] init];
    unsigned char byte[2] = {0, 0};
    
    for (NSInteger i = 0; i < [hex length]; i += 2) {
        byte[0] = [hex characterAtIndex:i];
        byte[1] = [hex characterAtIndex:i + 1];
        
        unsigned char wholeByte = strtol((char *)byte, NULL, 16);
        [data appendBytes:&wholeByte length:1];
    }
    
    return [NSData dataWithData:data];
}

- (NSString *)bytesToHex:(NSData *)data {
    const unsigned char *bytes = (const unsigned char *)[data bytes];
    NSMutableString *hex = [[NSMutableString alloc] init];
    
    for (NSInteger i = 0; i < [data length]; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    
    return [NSString stringWithString:hex];
}

- (NSString *)base64FromBase64URL:(NSString *)base64URL {
    NSString *base64 = [base64URL stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    
    // Add padding if needed
    NSInteger paddingLength = (4 - ([base64 length] % 4)) % 4;
    if (paddingLength > 0) {
        base64 = [base64 stringByPaddingToLength:([base64 length] + paddingLength)
                                      withString:@"="
                                 startingAtIndex:0];
    }
    
    return base64;
}

// MARK: - Basic Method
- (NSNumber *)multiply:(double)a b:(double)b {
    return @(a * b);
}

// MARK: - SHA Methods
- (void)shaBase64:(NSString *)data 
        algorithm:(NSString *)algorithm 
          resolve:(RCTPromiseResolveBlock)resolve 
           reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSData *inputData = [[NSData alloc] initWithBase64EncodedString:data options:0];
        if (!inputData) {
            reject(@"-1", @"Invalid base64 input", nil);
            return;
        }
        
        NSData *hashData = [self hashData:inputData withAlgorithm:algorithm];
        if (hashData) {
            NSString *result = [hashData base64EncodedStringWithOptions:0];
            resolve(result);
        } else {
            reject(@"-1", @"Invalid algorithm", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)shaUtf8:(NSString *)data 
      algorithm:(NSString *)algorithm 
        resolve:(RCTPromiseResolveBlock)resolve 
         reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSData *inputData = [data dataUsingEncoding:NSUTF8StringEncoding];
        NSData *hashData = [self hashData:inputData withAlgorithm:algorithm];
        if (hashData) {
            NSString *result = [self bytesToHex:hashData];
            resolve(result);
        } else {
            reject(@"-1", @"Invalid algorithm", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (NSData *)hashData:(NSData *)data withAlgorithm:(NSString *)algorithm {
    if ([algorithm isEqualToString:@"SHA-1"]) {
        unsigned char hash[CC_SHA1_DIGEST_LENGTH];
        CC_SHA1(data.bytes, (CC_LONG)data.length, hash);
        return [NSData dataWithBytes:hash length:CC_SHA1_DIGEST_LENGTH];
    } else if ([algorithm isEqualToString:@"SHA-256"]) {
        unsigned char hash[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
        return [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
    } else if ([algorithm isEqualToString:@"SHA-512"]) {
        unsigned char hash[CC_SHA512_DIGEST_LENGTH];
        CC_SHA512(data.bytes, (CC_LONG)data.length, hash);
        return [NSData dataWithBytes:hash length:CC_SHA512_DIGEST_LENGTH];
    }
    return nil;
}

// MARK: - PBKDF2 Method
- (void)pbkdf2Hash:(NSString *)pwdBase64
         saltBase64:(NSString *)saltBase64
         iterations:(double)iterations
             keyLen:(double)keyLen
               hash:(NSString *)hash
            resolve:(RCTPromiseResolveBlock)resolve
             reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSData *passwordData = [[NSData alloc] initWithBase64EncodedString:pwdBase64 options:0];
        NSData *saltData = [[NSData alloc] initWithBase64EncodedString:saltBase64 options:0];
        
        if (!passwordData || !saltData || keyLen <= 0 || iterations <= 0) {
            reject(@"-1", @"Invalid input parameters", nil);
            return;
        }
        
        // Algorithm mapping using dictionary like the original code
        NSDictionary *algMap = @{
            @"SHA1" : [NSNumber numberWithInt:kCCPRFHmacAlgSHA1],
            @"SHA224" : [NSNumber numberWithInt:kCCPRFHmacAlgSHA224],
            @"SHA256" : [NSNumber numberWithInt:kCCPRFHmacAlgSHA256],
            @"SHA384" : [NSNumber numberWithInt:kCCPRFHmacAlgSHA384],
            @"SHA512" : [NSNumber numberWithInt:kCCPRFHmacAlgSHA512],
        };
        
        NSNumber *algNumber = [algMap valueForKey:hash];
        if (!algNumber) {
            algNumber = [algMap valueForKey:@"SHA1"]; // Default to SHA1
        }
        int alg = [algNumber intValue];
        
        // Hash key data length - using same variable name as original
        NSMutableData *hashKeyData = [NSMutableData dataWithLength:(NSUInteger)keyLen];
        if (!hashKeyData || hashKeyData.length == 0) {
            reject(@"-1", @"Failed to allocate memory for derived key", nil);
            return;
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
        
        if (status == kCCParamError) {
            NSLog(@"Key derivation error");
            reject(@"-1", @"PBKDF2 parameter error", nil);
        } else if (status == kCCSuccess) {
            NSString *result = [hashKeyData base64EncodedStringWithOptions:0];
            resolve(result);
        } else {
            reject(@"-1", [NSString stringWithFormat:@"PBKDF2 derivation failed with status: %d", status], nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

// MARK: - HMAC256 Method
- (void)hmac256:(NSString *)data
            key:(NSString *)key
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSData *contentData = [self hexToBytes:data];
        NSData *keyData = [self hexToBytes:key];
        
        NSMutableData *hash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
        CCHmac(kCCHmacAlgSHA256, keyData.bytes, keyData.length, contentData.bytes, contentData.length, hash.mutableBytes);
        
        NSString *result = [self bytesToHex:hash];
        resolve(result);
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

// MARK: - AES Methods
- (NSData *)aes128CBC:(NSString *)operation data:(NSData *)data key:(NSString *)key iv:(NSString *)iv {
    NSData *keyData = [self hexToBytes:key];
    NSData *ivData = [self hexToBytes:iv];
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

- (void)aesEncrypt:(NSString *)dataBase64
            keyHex:(NSString *)keyHex
             ivHex:(NSString *)ivHex
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject {
    @try {
        if (!dataBase64 || dataBase64.length == 0) {
            resolve([NSNull null]);
            return;
        }
        
        NSData *clearData = [[NSData alloc] initWithBase64EncodedString:dataBase64 options:0];
        if (!clearData) {
            reject(@"-1", @"Invalid base64 input", nil);
            return;
        }
        
        NSData *result = [self aes128CBC:@"encrypt" data:clearData key:keyHex iv:ivHex];
        if (result) {
            NSString *encryptedBase64 = [result base64EncodedStringWithOptions:0];
            resolve(encryptedBase64);
        } else {
            reject(@"-1", @"Encryption failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)aesDecrypt:(NSString *)dataBase64
            keyHex:(NSString *)keyHex
             ivHex:(NSString *)ivHex
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject {
    @try {
        if (!dataBase64 || dataBase64.length == 0) {
            resolve([NSNull null]);
            return;
        }
        
        NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:dataBase64 options:0];
        if (!cipherData) {
            reject(@"-1", @"Invalid base64 input", nil);
            return;
        }
        
        NSData *result = [self aes128CBC:@"decrypt" data:cipherData key:keyHex iv:ivHex];
        if (result) {
            NSString *decryptedBase64 = [result base64EncodedStringWithOptions:0];
            resolve(decryptedBase64);
        } else {
            reject(@"-1", @"Decryption failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (NSString *)processFile:(NSString *)filePath
                operation:(CCOperation)operation
             base64UrlKey:(NSString *)base64UrlKey
                 base64Iv:(NSString *)base64Iv {
    NSString *keyBase64 = [self base64FromBase64URL:base64UrlKey];
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyBase64 options:0];
    NSData *ivData = [[NSData alloc] initWithBase64EncodedString:base64Iv options:0];

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

- (void)aesEncryptFile:(NSString *)filePath
          base64UrlKey:(NSString *)base64UrlKey
              base64Iv:(NSString *)base64Iv
               resolve:(RCTPromiseResolveBlock)resolve
                reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSString *result = [self processFile:filePath operation:kCCEncrypt base64UrlKey:base64UrlKey base64Iv:base64Iv];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"File encryption failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)aesDecryptFile:(NSString *)filePath
          base64UrlKey:(NSString *)base64UrlKey
              base64Iv:(NSString *)base64Iv
               resolve:(RCTPromiseResolveBlock)resolve
                reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSString *result = [self processFile:filePath operation:kCCDecrypt base64UrlKey:base64UrlKey base64Iv:base64Iv];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"File decryption failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

// MARK: - Random/Utility Methods
- (void)randomUuid:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSString *uuid = [[NSUUID UUID] UUIDString];
        resolve(uuid);
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)randomKey:(double)length
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSMutableData *keyData = [NSMutableData dataWithLength:(NSUInteger)length];
        int result = SecRandomCopyBytes(kSecRandomDefault, keyData.length, keyData.mutableBytes);
        if (result == errSecSuccess) {
            NSString *keyHex = [self bytesToHex:keyData];
            resolve(keyHex);
        } else {
            reject(@"-1", @"Failed to generate random key", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)randomBytes:(double)size
            resolve:(RCTPromiseResolveBlock)resolve
             reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSMutableData *randomData = [NSMutableData dataWithLength:(NSUInteger)size];
        int result = SecRandomCopyBytes(kSecRandomDefault, randomData.length, randomData.mutableBytes);
        if (result == errSecSuccess) {
            NSString *base64Result = [randomData base64EncodedStringWithOptions:0];
            resolve(base64Result);
        } else {
            reject(@"-1", @"Failed to generate random bytes", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)getRandomValues:(double)length
                resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSString *alphanumericChars = @"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        NSMutableString *result = [NSMutableString stringWithCapacity:(NSUInteger)length];
        
        for (int i = 0; i < (int)length; i++) {
            uint32_t randomIndex = arc4random_uniform((uint32_t)[alphanumericChars length]);
            [result appendFormat:@"%C", [alphanumericChars characterAtIndex:randomIndex]];
        }
        
        resolve([NSString stringWithString:result]);
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

// MARK: - File Checksum Method
- (void)calculateFileChecksum:(NSString *)filePath
                      resolve:(RCTPromiseResolveBlock)resolve
                       reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSString *normalizedPath = [filePath stringByReplacingOccurrencesOfString:@"file://" withString:@""];
        
        NSInputStream *inputStream = [NSInputStream inputStreamWithFileAtPath:normalizedPath];
        if (!inputStream) {
            reject(@"-1", @"Cannot open file", nil);
            return;
        }
        
        [inputStream open];
        
        CC_SHA256_CTX sha256Context;
        CC_SHA256_Init(&sha256Context);
        
        uint8_t buffer[4096];
        NSInteger bytesRead;
        
        while ((bytesRead = [inputStream read:buffer maxLength:sizeof(buffer)]) > 0) {
            CC_SHA256_Update(&sha256Context, buffer, (CC_LONG)bytesRead);
        }
        
        [inputStream close];
        
        if (bytesRead < 0) {
            reject(@"-1", @"Error reading file", nil);
            return;
        }
        
        unsigned char hash[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256_Final(hash, &sha256Context);
        
        NSData *hashData = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
        NSString *result = [self bytesToHex:hashData];
        resolve(result);
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

// MARK: - RSA Helper Methods
- (SecKeyAlgorithm)getAlgorithmFromHash:(NSString *)hash {
    if ([hash isEqualToString:@"Raw"]) {
        return kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw;
    } else if ([hash isEqualToString:@"SHA1"]) {
        return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA1;
    } else if ([hash isEqualToString:@"SHA224"]) {
        return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA224;
    } else if ([hash isEqualToString:@"SHA256"]) {
        return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
    } else if ([hash isEqualToString:@"SHA384"]) {
        return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA384;
    } else {
        return kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA512;
    }
}

- (NSString *)pemFormat:(NSData *)keyData tag:(NSString *)tag {
    NSString *header = [NSString stringWithFormat:@"-----BEGIN %@ KEY-----", tag];
    NSString *footer = [NSString stringWithFormat:@"-----END %@ KEY-----", tag];
    NSString *base64Key = [keyData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    return [NSString stringWithFormat:@"%@\n%@\n%@", header, base64Key, footer];
}

- (NSString *)stripPemHeaders:(NSString *)pemString {
    // Check in the order from the original RsaFormatter implementation
    NSArray *tags = @[@"RSA PRIVATE", @"RSA PUBLIC", @"PRIVATE", @"PUBLIC"];
    
    for (NSString *tag in tags) {
        NSString *header = [NSString stringWithFormat:@"-----BEGIN %@ KEY-----", tag];
        NSString *footer = [NSString stringWithFormat:@"-----END %@ KEY-----", tag];
        
        NSRange headerRange = [pemString rangeOfString:header];
        NSRange footerRange = [pemString rangeOfString:footer];
        
        if (headerRange.location != NSNotFound && footerRange.location != NSNotFound) {
            NSUInteger start = headerRange.location + headerRange.length;
            NSUInteger end = footerRange.location;
            NSRange range = NSMakeRange(start, end - start);
            NSString *strippedKey = [pemString substringWithRange:range];
            // Clean up whitespace and newlines
            strippedKey = [strippedKey stringByReplacingOccurrencesOfString:@"\n" withString:@""];
            strippedKey = [strippedKey stringByReplacingOccurrencesOfString:@"\r" withString:@""];
            strippedKey = [strippedKey stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            return strippedKey;
        }
    }
    return pemString;
}

- (NSData *)dataFromPemKey:(NSString *)pemKey {
    NSString *strippedKey = [self stripPemHeaders:pemKey];
    return [[NSData alloc] initWithBase64EncodedString:strippedKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

- (SecKeyRef)createKeyFromPemString:(NSString *)pemKey isPublic:(BOOL)isPublic {
    NSData *keyData = [self dataFromPemKey:pemKey];
    if (!keyData) {
        return NULL;
    }
    
    NSDictionary *options = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
        (id)kSecAttrKeyClass: isPublic ? (id)kSecAttrKeyClassPublic : (id)kSecAttrKeyClassPrivate
    };
    
    CFErrorRef error = NULL;
    SecKeyRef key = SecKeyCreateWithData((__bridge CFDataRef)keyData, (__bridge CFDictionaryRef)options, &error);
    
    if (error) {
        CFRelease(error);
    }
    
    return key;
}

// MARK: - RSA Methods
- (void)rsaGenerateKeys:(NSNumber *)keySize
                resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSInteger actualKeySize = keySize ? [keySize integerValue] : 2048;
        
        // Create key generation attributes
        NSMutableDictionary *privateKeyAttributes = [NSMutableDictionary dictionary];
        NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
        [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [attributes setObject:[NSNumber numberWithInteger:actualKeySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
        [attributes setObject:privateKeyAttributes forKey:(__bridge id)kSecPrivateKeyAttrs];
        
        CFErrorRef error = NULL;
        SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);
        
        if (!privateKey) {
            NSError *err = CFBridgingRelease(error);
            reject(@"-1", [NSString stringWithFormat:@"Key generation failed: %@", err.localizedDescription], err);
            return;
        }
        
        SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
        if (!publicKey) {
            CFRelease(privateKey);
            reject(@"-1", @"Failed to extract public key", nil);
            return;
        }
        
        // Get external representations
        CFDataRef privateKeyData = SecKeyCopyExternalRepresentation(privateKey, &error);
        if (!privateKeyData) {
            NSError *err = CFBridgingRelease(error);
            CFRelease(privateKey);
            CFRelease(publicKey);
            reject(@"-1", [NSString stringWithFormat:@"Failed to export private key: %@", err.localizedDescription], err);
            return;
        }
        
        CFDataRef publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error);
        if (!publicKeyData) {
            NSError *err = CFBridgingRelease(error);
            CFRelease(privateKey);
            CFRelease(publicKey);
            CFRelease(privateKeyData);
            reject(@"-1", [NSString stringWithFormat:@"Failed to export public key: %@", err.localizedDescription], err);
            return;
        }
        
        // Format as PEM
        NSString *publicPem = [self pemFormat:(__bridge NSData *)publicKeyData tag:@"PUBLIC"];
        NSString *privatePem = [self pemFormat:(__bridge NSData *)privateKeyData tag:@"PRIVATE"];
        
        NSDictionary *result = @{
            @"public": publicPem,
            @"private": privatePem
        };
        
        // Cleanup
        CFRelease(privateKey);
        CFRelease(publicKey);
        CFRelease(privateKeyData);
        CFRelease(publicKeyData);
        
        resolve(result);
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (NSData *)rsaEncryptData:(NSData *)data withKey:(SecKeyRef)publicKey {
    BOOL canEncrypt = SecKeyIsAlgorithmSupported(publicKey,
                                                kSecKeyOperationTypeEncrypt,
                                                kSecKeyAlgorithmRSAEncryptionOAEPSHA256);
    if (!canEncrypt) {
        NSLog(@"RSA encryption algorithm not supported");
        return nil;
    }
    
    CFErrorRef error = NULL;
    NSData *cipherText = (__bridge_transfer NSData *)SecKeyCreateEncryptedData(publicKey,
                                                                              kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
                                                                              (__bridge CFDataRef)data,
                                                                              &error);
    if (!cipherText) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"RSA encryption failed: %@", err);
    }
    
    return cipherText;
}

- (NSData *)rsaDecryptData:(NSData *)data withKey:(SecKeyRef)privateKey {
    BOOL canDecrypt = SecKeyIsAlgorithmSupported(privateKey,
                                                kSecKeyOperationTypeDecrypt,
                                                kSecKeyAlgorithmRSAEncryptionOAEPSHA256);
    if (!canDecrypt) {
        NSLog(@"RSA decryption algorithm not supported");
        return nil;
    }
    
    CFErrorRef error = NULL;
    NSData *clearText = (__bridge_transfer NSData *)SecKeyCreateDecryptedData(privateKey,
                                                                             kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
                                                                             (__bridge CFDataRef)data,
                                                                             &error);
    if (!clearText) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"RSA decryption failed: %@", err);
    }
    
    return clearText;
}

- (NSString *)rsaSignData:(NSData *)messageData withKey:(SecKeyRef)privateKey algorithm:(SecKeyAlgorithm)algorithm {
    // Check for Raw signing with message length
    if (algorithm == kSecKeyAlgorithmRSASignatureDigestPKCS1v15Raw) {
        NSUInteger keyLength = SecKeyGetBlockSize(privateKey);
        if ([messageData length] > keyLength) {
            NSLog(@"Message length %lu is bigger than key length %lu", (unsigned long)[messageData length], (unsigned long)keyLength);
            return nil;
        }
    }
    
    BOOL canSign = SecKeyIsAlgorithmSupported(privateKey,
                                             kSecKeyOperationTypeSign,
                                             algorithm);
    if (!canSign) {
        NSLog(@"RSA signing algorithm not supported");
        return nil;
    }
    
    CFErrorRef error = NULL;
    NSData *signature = (__bridge_transfer NSData *)SecKeyCreateSignature(privateKey,
                                                                         algorithm,
                                                                         (__bridge CFDataRef)messageData,
                                                                         &error);
    if (!signature) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"RSA signing failed: %@", err);
        return nil;
    }
    
    return [signature base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

- (BOOL)rsaVerifySignature:(NSData *)signatureData message:(NSData *)messageData withKey:(SecKeyRef)publicKey algorithm:(SecKeyAlgorithm)algorithm {
    BOOL canVerify = SecKeyIsAlgorithmSupported(publicKey,
                                               kSecKeyOperationTypeVerify,
                                               algorithm);
    if (!canVerify) {
        NSLog(@"RSA verification algorithm not supported");
        return NO;
    }
    
    CFErrorRef error = NULL;
    BOOL result = SecKeyVerifySignature(publicKey,
                                       algorithm,
                                       (__bridge CFDataRef)messageData,
                                       (__bridge CFDataRef)signatureData,
                                       &error);
    if (!result) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"RSA verification failed: %@", err);
    }
    
    return result;
}

- (void)rsaEncrypt:(NSString *)message
         publicKey:(NSString *)publicKeyString
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject {
    @try {
        SecKeyRef publicKey = [self createKeyFromPemString:publicKeyString isPublic:YES];
        if (!publicKey) {
            reject(@"-1", @"Invalid public key", nil);
            return;
        }
        
        NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
        NSData *encryptedData = [self rsaEncryptData:data withKey:publicKey];
        
        CFRelease(publicKey);
        
        if (encryptedData) {
            NSString *result = [encryptedData base64EncodedStringWithOptions:0];
            resolve(result);
        } else {
            reject(@"-1", @"Encryption failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)rsaEncrypt64:(NSString *)message
           publicKey:(NSString *)publicKeyString
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject {
    @try {
        SecKeyRef publicKey = [self createKeyFromPemString:publicKeyString isPublic:YES];
        if (!publicKey) {
            reject(@"-1", @"Invalid public key", nil);
            return;
        }
        
        NSData *data = [[NSData alloc] initWithBase64EncodedString:message options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (!data) {
            CFRelease(publicKey);
            reject(@"-1", @"Invalid base64 input", nil);
            return;
        }
        
        NSData *encryptedData = [self rsaEncryptData:data withKey:publicKey];
        
        CFRelease(publicKey);
        
        if (encryptedData) {
            NSString *result = [encryptedData base64EncodedStringWithOptions:0];
            resolve(result);
        } else {
            reject(@"-1", @"Encryption failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)rsaDecrypt:(NSString *)encodedMessage
        privateKey:(NSString *)privateKeyString
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject {
    @try {
        SecKeyRef privateKey = [self createKeyFromPemString:privateKeyString isPublic:NO];
        if (!privateKey) {
            reject(@"-1", @"Invalid private key", nil);
            return;
        }
        
        NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:encodedMessage options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (!encryptedData) {
            CFRelease(privateKey);
            reject(@"-1", @"Invalid base64 input", nil);
            return;
        }
        
        NSData *decryptedData = [self rsaDecryptData:encryptedData withKey:privateKey];
        
        CFRelease(privateKey);
        
        if (decryptedData) {
            NSString *result = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
            resolve(result);
        } else {
            reject(@"-1", @"Decryption failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)rsaDecrypt64:(NSString *)encodedMessage
          privateKey:(NSString *)privateKeyString
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject {
    @try {
        SecKeyRef privateKey = [self createKeyFromPemString:privateKeyString isPublic:NO];
        if (!privateKey) {
            reject(@"-1", @"Invalid private key", nil);
            return;
        }
        
        NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:encodedMessage options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (!encryptedData) {
            CFRelease(privateKey);
            reject(@"-1", @"Invalid base64 input", nil);
            return;
        }
        
        NSData *decryptedData = [self rsaDecryptData:encryptedData withKey:privateKey];
        
        CFRelease(privateKey);
        
        if (decryptedData) {
            NSString *result = [decryptedData base64EncodedStringWithOptions:0];
            resolve(result);
        } else {
            reject(@"-1", @"Decryption failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)rsaSign:(NSString *)message
     privateKey:(NSString *)privateKeyString
           hash:(NSString *)hash
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject {
    @try {
        SecKeyRef privateKey = [self createKeyFromPemString:privateKeyString isPublic:NO];
        if (!privateKey) {
            reject(@"-1", @"Invalid private key", nil);
            return;
        }
        
        NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
        SecKeyAlgorithm algorithm = [self getAlgorithmFromHash:hash];
        
        NSString *signature = [self rsaSignData:messageData withKey:privateKey algorithm:algorithm];
        
        CFRelease(privateKey);
        
        if (signature) {
            resolve(signature);
        } else {
            reject(@"-1", @"Signing failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)rsaSign64:(NSString *)message
       privateKey:(NSString *)privateKeyString
             hash:(NSString *)hash
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject {
    @try {
        SecKeyRef privateKey = [self createKeyFromPemString:privateKeyString isPublic:NO];
        if (!privateKey) {
            reject(@"-1", @"Invalid private key", nil);
            return;
        }
        
        NSData *messageData = [[NSData alloc] initWithBase64EncodedString:message options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (!messageData) {
            CFRelease(privateKey);
            reject(@"-1", @"Invalid base64 input", nil);
            return;
        }
        
        SecKeyAlgorithm algorithm = [self getAlgorithmFromHash:hash];
        NSString *signature = [self rsaSignData:messageData withKey:privateKey algorithm:algorithm];
        
        CFRelease(privateKey);
        
        if (signature) {
            resolve(signature);
        } else {
            reject(@"-1", @"Signing failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)rsaVerify:(NSString *)signature
          message:(NSString *)message
        publicKey:(NSString *)publicKeyString
             hash:(NSString *)hash
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject {
    @try {
        SecKeyRef publicKey = [self createKeyFromPemString:publicKeyString isPublic:YES];
        if (!publicKey) {
            reject(@"-1", @"Invalid public key", nil);
            return;
        }
        
        NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];
        NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:signature options:NSDataBase64DecodingIgnoreUnknownCharacters];
        
        if (!signatureData) {
            CFRelease(publicKey);
            reject(@"-1", @"Invalid signature format", nil);
            return;
        }
        
        SecKeyAlgorithm algorithm = [self getAlgorithmFromHash:hash];
        BOOL isValid = [self rsaVerifySignature:signatureData message:messageData withKey:publicKey algorithm:algorithm];
        
        CFRelease(publicKey);
        resolve(@(isValid));
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)rsaVerify64:(NSString *)signature
            message:(NSString *)message
          publicKey:(NSString *)publicKeyString
               hash:(NSString *)hash
            resolve:(RCTPromiseResolveBlock)resolve
             reject:(RCTPromiseRejectBlock)reject {
    @try {
        SecKeyRef publicKey = [self createKeyFromPemString:publicKeyString isPublic:YES];
        if (!publicKey) {
            reject(@"-1", @"Invalid public key", nil);
            return;
        }
        
        NSData *messageData = [[NSData alloc] initWithBase64EncodedString:message options:NSDataBase64DecodingIgnoreUnknownCharacters];
        NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:signature options:NSDataBase64DecodingIgnoreUnknownCharacters];
        
        if (!messageData || !signatureData) {
            CFRelease(publicKey);
            reject(@"-1", @"Invalid base64 input", nil);
            return;
        }
        
        SecKeyAlgorithm algorithm = [self getAlgorithmFromHash:hash];
        BOOL isValid = [self rsaVerifySignature:signatureData message:messageData withKey:publicKey algorithm:algorithm];
        
        CFRelease(publicKey);
        resolve(@(isValid));
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeMobileCryptoSpecJSI>(params);
}

@end
