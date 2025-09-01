#import "MobileCrypto.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <Security/Security.h>

@implementation MobileCrypto
RCT_EXPORT_MODULE()

// MARK: - Helper Methods

- (NSData *)fromHex: (NSString *)string {
    NSMutableData *data = [[NSMutableData alloc] init];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    for (int i = 0; i < ([string length] / 2); i++) {
        byte_chars[0] = [string characterAtIndex:i*2];
        byte_chars[1] = [string characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
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
        NSData *contentData = [self fromHex:data];
        NSData *keyData = [self fromHex:key];
        
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
    NSData *keyData = [self fromHex:key];
    NSData *ivData = [self fromHex:iv];
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

// MARK: - RSA Key Format Conversion Methods

- (NSData *)base64URLDecodeString:(NSString *)string {
    // Convert base64url to base64
    NSString *base64String = [self base64FromBase64URL:string];
    return [[NSData alloc] initWithBase64EncodedString:base64String options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

- (NSString *)base64URLEncodeData:(NSData *)data {
    NSString *base64String = [data base64EncodedStringWithOptions:0];
    // Convert base64 to base64url (replace + with -, / with _, remove padding)
    base64String = [base64String stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"=" withString:@""];
    return base64String;
}

- (NSData *)createASN1IntegerFromBigInteger:(NSData *)integerData {
    // Create ASN.1 INTEGER encoding for the big integer
    NSMutableData *asn1Integer = [NSMutableData data];
    
    // Add padding byte if the most significant bit is 1 (to keep it positive)
    NSData *valueData = integerData;
    if (integerData.length > 0 && ((uint8_t *)integerData.bytes)[0] & 0x80) {
        NSMutableData *paddedData = [NSMutableData dataWithBytes:"\x00" length:1];
        [paddedData appendData:integerData];
        valueData = paddedData;
    }
    
    // ASN.1 INTEGER tag
    [asn1Integer appendBytes:"\x02" length:1];
    
    // Length encoding
    NSUInteger length = valueData.length;
    if (length < 0x80) {
        uint8_t shortLength = (uint8_t)length;
        [asn1Integer appendBytes:&shortLength length:1];
    } else {
        // Long form length encoding
        uint8_t lengthBytes = 0;
        NSUInteger tempLength = length;
        while (tempLength > 0) {
            lengthBytes++;
            tempLength >>= 8;
        }
        
        uint8_t longFormPrefix = 0x80 | lengthBytes;
        [asn1Integer appendBytes:&longFormPrefix length:1];
        
        for (int i = lengthBytes - 1; i >= 0; i--) {
            uint8_t lengthByte = (length >> (i * 8)) & 0xFF;
            [asn1Integer appendBytes:&lengthByte length:1];
        }
    }
    
    // Value
    [asn1Integer appendData:valueData];
    
    return asn1Integer;
}

- (NSData *)createRSAPublicKeyASN1:(NSData *)modulus exponent:(NSData *)exponent {
    // Create RSAPublicKey ASN.1 structure: SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    NSData *modulusASN1 = [self createASN1IntegerFromBigInteger:modulus];
    NSData *exponentASN1 = [self createASN1IntegerFromBigInteger:exponent];
    
    NSMutableData *sequence = [NSMutableData data];
    [sequence appendData:modulusASN1];
    [sequence appendData:exponentASN1];
    
    // Wrap in SEQUENCE
    NSMutableData *result = [NSMutableData data];
    [result appendBytes:"\x30" length:1]; // SEQUENCE tag
    
    // Length encoding for sequence
    NSUInteger seqLength = sequence.length;
    if (seqLength < 0x80) {
        uint8_t shortLength = (uint8_t)seqLength;
        [result appendBytes:&shortLength length:1];
    } else {
        uint8_t lengthBytes = 0;
        NSUInteger tempLength = seqLength;
        while (tempLength > 0) {
            lengthBytes++;
            tempLength >>= 8;
        }
        
        uint8_t longFormPrefix = 0x80 | lengthBytes;
        [result appendBytes:&longFormPrefix length:1];
        
        for (int i = lengthBytes - 1; i >= 0; i--) {
            uint8_t lengthByte = (seqLength >> (i * 8)) & 0xFF;
            [result appendBytes:&lengthByte length:1];
        }
    }
    
    [result appendData:sequence];
    return result;
}

- (NSData *)createRSAPrivateKeyASN1:(NSData *)modulus 
                           exponent:(NSData *)publicExponent
                                  d:(NSData *)privateExponent
                                  p:(NSData *)p
                                  q:(NSData *)q
                                 dp:(NSData *)dp
                                 dq:(NSData *)dq
                                 qi:(NSData *)qi {
    // Create RSAPrivateKey ASN.1 structure
    // RSAPrivateKey ::= SEQUENCE {
    //   version           INTEGER,          -- version (0)
    //   modulus           INTEGER,          -- n
    //   publicExponent    INTEGER,          -- e
    //   privateExponent   INTEGER,          -- d
    //   prime1            INTEGER,          -- p
    //   prime2            INTEGER,          -- q
    //   exponent1         INTEGER,          -- d mod (p-1) [dp]
    //   exponent2         INTEGER,          -- d mod (q-1) [dq]
    //   coefficient       INTEGER           -- (inverse of q) mod p [qi]
    // }
    
    NSMutableData *sequence = [NSMutableData data];
    
    // Version (0)
    NSData *version = [NSData dataWithBytes:"\x00" length:1];
    [sequence appendData:[self createASN1IntegerFromBigInteger:version]];
    
    // Add all the RSA parameters
    [sequence appendData:[self createASN1IntegerFromBigInteger:modulus]];
    [sequence appendData:[self createASN1IntegerFromBigInteger:publicExponent]];
    [sequence appendData:[self createASN1IntegerFromBigInteger:privateExponent]];
    [sequence appendData:[self createASN1IntegerFromBigInteger:p]];
    [sequence appendData:[self createASN1IntegerFromBigInteger:q]];
    [sequence appendData:[self createASN1IntegerFromBigInteger:dp]];
    [sequence appendData:[self createASN1IntegerFromBigInteger:dq]];
    [sequence appendData:[self createASN1IntegerFromBigInteger:qi]];
    
    // Wrap in SEQUENCE
    NSMutableData *result = [NSMutableData data];
    [result appendBytes:"\x30" length:1]; // SEQUENCE tag
    
    // Length encoding for sequence
    NSUInteger seqLength = sequence.length;
    if (seqLength < 0x80) {
        uint8_t shortLength = (uint8_t)seqLength;
        [result appendBytes:&shortLength length:1];
    } else {
        uint8_t lengthBytes = 0;
        NSUInteger tempLength = seqLength;
        while (tempLength > 0) {
            lengthBytes++;
            tempLength >>= 8;
        }
        
        uint8_t longFormPrefix = 0x80 | lengthBytes;
        [result appendBytes:&longFormPrefix length:1];
        
        for (int i = lengthBytes - 1; i >= 0; i--) {
            uint8_t lengthByte = (seqLength >> (i * 8)) & 0xFF;
            [result appendBytes:&lengthByte length:1];
        }
    }
    
    [result appendData:sequence];
    return result;
}

- (void)rsaImportKey:(JS::NativeMobileCrypto::JWK &)jwk
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSString *kty = jwk.kty();
        if (![kty isEqualToString:@"RSA"]) {
            reject(@"-1", @"Only RSA keys are supported", nil);
            return;
        }
        
        NSString *nStr = jwk.n();
        NSString *eStr = jwk.e();
        
        if (!nStr || !eStr) {
            reject(@"-1", @"Missing required parameters 'n' or 'e'", nil);
            return;
        }
        
        NSData *modulus = [self base64URLDecodeString:nStr];
        NSData *exponent = [self base64URLDecodeString:eStr];
        
        if (!modulus || !exponent) {
            reject(@"-1", @"Invalid base64url encoding in JWK parameters", nil);
            return;
        }
        
        // Check if this is a private key (has 'd' parameter)
        NSString *dStr = jwk.d();
        BOOL hasPrivateExponent = dStr != nil && dStr.length > 0;
        
        if (hasPrivateExponent) {
            // Create private key from JWK parameters
            NSString *pStr = jwk.p();
            NSString *qStr = jwk.q();
            NSString *dpStr = jwk.dp();
            NSString *dqStr = jwk.dq();
            NSString *qiStr = jwk.qi();
            
            if (!pStr || !qStr || !dpStr || !dqStr || !qiStr) {
                reject(@"-1", @"Missing private key parameters", nil);
                return;
            }
            
            NSData *d = [self base64URLDecodeString:dStr];
            NSData *p = [self base64URLDecodeString:pStr];
            NSData *q = [self base64URLDecodeString:qStr];
            NSData *dp = [self base64URLDecodeString:dpStr];
            NSData *dq = [self base64URLDecodeString:dqStr];
            NSData *qi = [self base64URLDecodeString:qiStr];
            
            if (!d || !p || !q || !dp || !dq || !qi) {
                reject(@"-1", @"Invalid base64url encoding in private key parameters", nil);
                return;
            }
            
            // Create private key ASN.1 structure
            NSData *privateKeyASN1 = [self createRSAPrivateKeyASN1:modulus exponent:exponent d:d p:p q:q dp:dp dq:dq qi:qi];
            if (!privateKeyASN1) {
                reject(@"-1", @"Failed to create private key ASN.1 structure", nil);
                return;
            }
            
            NSString *pemPrivateKey = [self pemFormat:privateKeyASN1 tag:@"RSA PRIVATE"];
            resolve(pemPrivateKey);
        } else {
            // Create public key from modulus and exponent
            NSData *publicKeyASN1 = [self createRSAPublicKeyASN1:modulus exponent:exponent];
            NSString *pemPublicKey = [self pemFormat:publicKeyASN1 tag:@"RSA PUBLIC"];
            resolve(pemPublicKey);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (NSData *)parseASN1Integer:(NSData *)data offset:(NSUInteger *)offset {
    if (*offset >= data.length) return nil;
    
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    
    // Check for INTEGER tag
    if (bytes[*offset] != 0x02) return nil;
    (*offset)++;
    
    if (*offset >= data.length) return nil;
    
    // Parse length
    NSUInteger length;
    uint8_t firstLengthByte = bytes[*offset];
    (*offset)++;
    
    if (firstLengthByte & 0x80) {
        // Long form
        NSUInteger lengthBytes = firstLengthByte & 0x7F;
        if (lengthBytes == 0 || *offset + lengthBytes > data.length) return nil;
        
        length = 0;
        for (NSUInteger i = 0; i < lengthBytes; i++) {
            length = (length << 8) | bytes[*offset + i];
        }
        *offset += lengthBytes;
    } else {
        // Short form
        length = firstLengthByte;
    }
    
    if (*offset + length > data.length) return nil;
    
    NSData *integerData = [NSData dataWithBytes:bytes + *offset length:length];
    *offset += length;
    
    // Remove leading zero if present (ASN.1 padding)
    if (length > 1 && ((uint8_t *)integerData.bytes)[0] == 0x00) {
        integerData = [NSData dataWithBytes:(uint8_t *)integerData.bytes + 1 length:length - 1];
    }
    
    return integerData;
}

- (NSDictionary *)parseRSAPublicKeyASN1:(NSData *)asn1Data {
    NSUInteger offset = 0;
    const uint8_t *bytes = (const uint8_t *)asn1Data.bytes;
    
    // Check for SEQUENCE tag
    if (offset >= asn1Data.length || bytes[offset] != 0x30) return nil;
    offset++;
    
    // Parse sequence length (we don't need to validate it exactly)
    uint8_t lengthByte = bytes[offset];
    if (lengthByte & 0x80) {
        NSUInteger lengthBytes = lengthByte & 0x7F;
        offset += lengthBytes + 1;
    } else {
        offset++;
    }
    
    // Parse modulus
    NSData *modulus = [self parseASN1Integer:asn1Data offset:&offset];
    if (!modulus) return nil;
    
    // Parse exponent
    NSData *exponent = [self parseASN1Integer:asn1Data offset:&offset];
    if (!exponent) return nil;
    
    return @{
        @"n": [self base64URLEncodeData:modulus],
        @"e": [self base64URLEncodeData:exponent]
    };
}

- (NSDictionary *)parseRSAPrivateKeyASN1:(NSData *)asn1Data {
    NSUInteger offset = 0;
    const uint8_t *bytes = (const uint8_t *)asn1Data.bytes;
    
    // Check for SEQUENCE tag
    if (offset >= asn1Data.length || bytes[offset] != 0x30) return nil;
    offset++;
    
    // Parse sequence length (we don't need to validate it exactly)
    uint8_t lengthByte = bytes[offset];
    if (lengthByte & 0x80) {
        NSUInteger lengthBytes = lengthByte & 0x7F;
        offset += lengthBytes + 1;
    } else {
        offset++;
    }
    
    // RSA Private Key ASN.1 structure:
    // RSAPrivateKey ::= SEQUENCE {
    //   version           INTEGER,          -- version 
    //   modulus           INTEGER,          -- n
    //   publicExponent    INTEGER,          -- e
    //   privateExponent   INTEGER,          -- d
    //   prime1            INTEGER,          -- p
    //   prime2            INTEGER,          -- q
    //   exponent1         INTEGER,          -- d mod (p-1) [dp]
    //   exponent2         INTEGER,          -- d mod (q-1) [dq]
    //   coefficient       INTEGER           -- (inverse of q) mod p [qi]
    // }
    
    // Parse version (should be 0)
    NSData *version = [self parseASN1Integer:asn1Data offset:&offset];
    if (!version) return nil;
    
    // Parse modulus (n)
    NSData *modulus = [self parseASN1Integer:asn1Data offset:&offset];
    if (!modulus) return nil;
    
    // Parse public exponent (e)
    NSData *publicExponent = [self parseASN1Integer:asn1Data offset:&offset];
    if (!publicExponent) return nil;
    
    // Parse private exponent (d)
    NSData *privateExponent = [self parseASN1Integer:asn1Data offset:&offset];
    if (!privateExponent) return nil;
    
    // Parse prime1 (p)
    NSData *prime1 = [self parseASN1Integer:asn1Data offset:&offset];
    if (!prime1) return nil;
    
    // Parse prime2 (q)
    NSData *prime2 = [self parseASN1Integer:asn1Data offset:&offset];
    if (!prime2) return nil;
    
    // Parse exponent1 (dp)
    NSData *exponent1 = [self parseASN1Integer:asn1Data offset:&offset];
    if (!exponent1) return nil;
    
    // Parse exponent2 (dq)
    NSData *exponent2 = [self parseASN1Integer:asn1Data offset:&offset];
    if (!exponent2) return nil;
    
    // Parse coefficient (qi)
    NSData *coefficient = [self parseASN1Integer:asn1Data offset:&offset];
    if (!coefficient) return nil;
    
    return @{
        @"n": [self base64URLEncodeData:modulus],
        @"e": [self base64URLEncodeData:publicExponent],
        @"d": [self base64URLEncodeData:privateExponent],
        @"p": [self base64URLEncodeData:prime1],
        @"q": [self base64URLEncodeData:prime2],
        @"dp": [self base64URLEncodeData:exponent1],
        @"dq": [self base64URLEncodeData:exponent2],
        @"qi": [self base64URLEncodeData:coefficient]
    };
}

- (void)rsaExportKey:(NSString *)pem
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSData *keyData = [self dataFromPemKey:pem];
        if (!keyData) {
            reject(@"-1", @"Invalid PEM format", nil);
            return;
        }
        
        BOOL isPublic = [pem containsString:@"PUBLIC"];
        BOOL isRsaPkcs1 = [pem containsString:@"RSA"];
        
        NSMutableDictionary *jwk = [[NSMutableDictionary alloc] init];
        
        if (isPublic) {
            if (isRsaPkcs1) {
                // PKCS#1 RSA PUBLIC KEY - parse ASN.1 directly
                NSDictionary *keyComponents = [self parseRSAPublicKeyASN1:keyData];
                if (!keyComponents) {
                    reject(@"-1", @"Failed to parse RSA public key ASN.1 structure", nil);
                    return;
                }
                [jwk addEntriesFromDictionary:keyComponents];
            } else {
                // X.509 SubjectPublicKeyInfo - extract the public key and parse it
                SecKeyRef publicKey = [self createKeyFromPemString:pem isPublic:YES];
                if (!publicKey) {
                    reject(@"-1", @"Failed to create public key from PEM", nil);
                    return;
                }
                
                // Get the raw public key data 
                CFErrorRef error = NULL;
                NSData *publicKeyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(publicKey, &error);
                CFRelease(publicKey);
                
                if (!publicKeyData) {
                    NSError *err = CFBridgingRelease(error);
                    reject(@"-1", [NSString stringWithFormat:@"Failed to export public key: %@", err.localizedDescription], err);
                    return;
                }
                
                // Parse the raw RSA public key data
                NSDictionary *keyComponents = [self parseRSAPublicKeyASN1:publicKeyData];
                if (!keyComponents) {
                    reject(@"-1", @"Failed to parse public key components", nil);
                    return;
                }
                [jwk addEntriesFromDictionary:keyComponents];
            }
            
            // Add standard JWK fields for public key
            jwk[@"key_ops"] = @[@"encrypt"];
        } else {
            // Private key export - try to parse the private key
            SecKeyRef privateKey = [self createKeyFromPemString:pem isPublic:NO];
            if (!privateKey) {
                reject(@"-1", @"Failed to create private key from PEM", nil);
                return;
            }
            
            // Get the external representation of the private key
            CFErrorRef error = NULL;
            NSData *privateKeyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(privateKey, &error);
            CFRelease(privateKey);
            
            if (!privateKeyData) {
                NSError *err = CFBridgingRelease(error);
                reject(@"-1", [NSString stringWithFormat:@"Failed to export private key: %@", err.localizedDescription], err);
                return;
            }
            
            // Parse the private key ASN.1 structure
            NSDictionary *privateKeyComponents = [self parseRSAPrivateKeyASN1:privateKeyData];
            if (!privateKeyComponents) {
                reject(@"-1", @"Failed to parse private key components", nil);
                return;
            }
            [jwk addEntriesFromDictionary:privateKeyComponents];
            
            // Add standard JWK fields for private key
            jwk[@"key_ops"] = @[@"decrypt"];
        }
        
        // Add common JWK fields
        jwk[@"kty"] = @"RSA";
        jwk[@"alg"] = @"RSA-OAEP-256";
        jwk[@"ext"] = @YES;
        
        resolve(jwk);
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
