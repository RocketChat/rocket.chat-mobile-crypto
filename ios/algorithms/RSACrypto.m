#import "RSACrypto.h"
#import "CryptoUtils.h"

@implementation RSACrypto

+ (nullable NSDictionary *)generateKeyPair:(NSInteger)keySize {
    // Create key generation attributes
    NSMutableDictionary *privateKeyAttributes = [NSMutableDictionary dictionary];
    NSMutableDictionary *attributes = [[NSMutableDictionary alloc] init];
    [attributes setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [attributes setObject:[NSNumber numberWithInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
    [attributes setObject:privateKeyAttributes forKey:(__bridge id)kSecPrivateKeyAttrs];
    
    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);
    
    if (!privateKey) {
        if (error) CFRelease(error);
        return nil;
    }
    
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) {
        CFRelease(privateKey);
        return nil;
    }
    
    // Get external representations
    CFDataRef privateKeyData = SecKeyCopyExternalRepresentation(privateKey, &error);
    if (!privateKeyData) {
        CFRelease(privateKey);
        CFRelease(publicKey);
        if (error) CFRelease(error);
        return nil;
    }
    
    CFDataRef publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error);
    if (!publicKeyData) {
        CFRelease(privateKey);
        CFRelease(publicKey);
        CFRelease(privateKeyData);
        if (error) CFRelease(error);
        return nil;
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
    
    return result;
}

+ (nullable NSString *)encrypt:(NSString *)message publicKeyPem:(NSString *)publicKeyPem {
    SecKeyRef publicKey = [self createKeyFromPem:publicKeyPem isPublic:YES];
    if (!publicKey) return nil;
    
    NSData *messageData = [CryptoUtils stringToUtf8Data:message];
    NSData *encryptedData = [self rsaEncryptData:messageData withKey:publicKey];
    
    CFRelease(publicKey);
    
    if (encryptedData) {
        return [CryptoUtils encodeBase64:encryptedData];
    }
    return nil;
}

+ (nullable NSString *)encryptBase64:(NSString *)messageBase64 publicKeyPem:(NSString *)publicKeyPem {
    SecKeyRef publicKey = [self createKeyFromPem:publicKeyPem isPublic:YES];
    if (!publicKey) return nil;
    
    NSData *messageData = [CryptoUtils decodeBase64:messageBase64];
    if (!messageData) {
        CFRelease(publicKey);
        return nil;
    }
    
    NSData *encryptedData = [self rsaEncryptData:messageData withKey:publicKey];
    CFRelease(publicKey);
    
    if (encryptedData) {
        return [CryptoUtils encodeBase64:encryptedData];
    }
    return nil;
}

+ (nullable NSString *)decrypt:(NSString *)encryptedMessage privateKeyPem:(NSString *)privateKeyPem {
    SecKeyRef privateKey = [self createKeyFromPem:privateKeyPem isPublic:NO];
    if (!privateKey) return nil;
    
    NSData *encryptedData = [CryptoUtils decodeBase64:encryptedMessage];
    if (!encryptedData) {
        CFRelease(privateKey);
        return nil;
    }
    
    NSData *decryptedData = [self rsaDecryptData:encryptedData withKey:privateKey];
    CFRelease(privateKey);
    
    if (decryptedData) {
        return [CryptoUtils utf8DataToString:decryptedData];
    }
    return nil;
}

+ (nullable NSString *)decryptToBase64:(NSString *)encryptedMessage privateKeyPem:(NSString *)privateKeyPem {
    SecKeyRef privateKey = [self createKeyFromPem:privateKeyPem isPublic:NO];
    if (!privateKey) return nil;
    
    NSData *encryptedData = [CryptoUtils decodeBase64:encryptedMessage];
    if (!encryptedData) {
        CFRelease(privateKey);
        return nil;
    }
    
    NSData *decryptedData = [self rsaDecryptData:encryptedData withKey:privateKey];
    CFRelease(privateKey);
    
    if (decryptedData) {
        return [CryptoUtils encodeBase64:decryptedData];
    }
    return nil;
}

+ (nullable NSString *)sign:(NSString *)message privateKeyPem:(NSString *)privateKeyPem hashAlgorithm:(nullable NSString *)hashAlgorithm {
    SecKeyRef privateKey = [self createKeyFromPem:privateKeyPem isPublic:NO];
    if (!privateKey) return nil;
    
    NSData *messageData = [CryptoUtils stringToUtf8Data:message];
    SecKeyAlgorithm algorithm = [self algorithmFromHash:hashAlgorithm forSigning:YES];
    
    CFErrorRef error = NULL;
    NSData *signature = (__bridge_transfer NSData *)SecKeyCreateSignature(privateKey, algorithm, (__bridge CFDataRef)messageData, &error);
    
    CFRelease(privateKey);
    
    if (signature) {
        return [CryptoUtils encodeBase64:signature];
    }
    
    if (error) CFRelease(error);
    return nil;
}

+ (nullable NSString *)signBase64:(NSString *)messageBase64 privateKeyPem:(NSString *)privateKeyPem hashAlgorithm:(nullable NSString *)hashAlgorithm {
    SecKeyRef privateKey = [self createKeyFromPem:privateKeyPem isPublic:NO];
    if (!privateKey) return nil;
    
    NSData *messageData = [CryptoUtils decodeBase64:messageBase64];
    if (!messageData) {
        CFRelease(privateKey);
        return nil;
    }
    
    SecKeyAlgorithm algorithm = [self algorithmFromHash:hashAlgorithm forSigning:YES];
    
    CFErrorRef error = NULL;
    NSData *signature = (__bridge_transfer NSData *)SecKeyCreateSignature(privateKey, algorithm, (__bridge CFDataRef)messageData, &error);
    
    CFRelease(privateKey);
    
    if (signature) {
        return [CryptoUtils encodeBase64:signature];
    }
    
    if (error) CFRelease(error);
    return nil;
}

+ (BOOL)verify:(NSString *)signatureBase64 message:(NSString *)message publicKeyPem:(NSString *)publicKeyPem hashAlgorithm:(nullable NSString *)hashAlgorithm {
    SecKeyRef publicKey = [self createKeyFromPem:publicKeyPem isPublic:YES];
    if (!publicKey) return NO;
    
    NSData *messageData = [CryptoUtils stringToUtf8Data:message];
    NSData *signatureData = [CryptoUtils decodeBase64:signatureBase64];
    
    if (!messageData || !signatureData) {
        CFRelease(publicKey);
        return NO;
    }
    
    SecKeyAlgorithm algorithm = [self algorithmFromHash:hashAlgorithm forSigning:YES];
    
    CFErrorRef error = NULL;
    Boolean result = SecKeyVerifySignature(publicKey, algorithm, (__bridge CFDataRef)messageData, (__bridge CFDataRef)signatureData, &error);
    
    CFRelease(publicKey);
    if (error) CFRelease(error);
    
    return result;
}

+ (BOOL)verifyBase64:(NSString *)signatureBase64 messageBase64:(NSString *)messageBase64 publicKeyPem:(NSString *)publicKeyPem hashAlgorithm:(nullable NSString *)hashAlgorithm {
    SecKeyRef publicKey = [self createKeyFromPem:publicKeyPem isPublic:YES];
    if (!publicKey) return NO;
    
    NSData *messageData = [CryptoUtils decodeBase64:messageBase64];
    NSData *signatureData = [CryptoUtils decodeBase64:signatureBase64];
    
    if (!messageData || !signatureData) {
        CFRelease(publicKey);
        return NO;
    }
    
    SecKeyAlgorithm algorithm = [self algorithmFromHash:hashAlgorithm forSigning:YES];
    
    CFErrorRef error = NULL;
    Boolean result = SecKeyVerifySignature(publicKey, algorithm, (__bridge CFDataRef)messageData, (__bridge CFDataRef)signatureData, &error);
    
    CFRelease(publicKey);
    if (error) CFRelease(error);
    
    return result;
}

+ (nullable NSString *)importJwkKey:(NSDictionary *)jwk {
    @try {
        NSString *kty = jwk[@"kty"];
        if (![kty isEqualToString:@"RSA"]) {
            NSLog(@"Only RSA keys are supported");
            return nil;
        }
        
        NSString *nStr = jwk[@"n"];
        NSString *eStr = jwk[@"e"];
        
        if (!nStr || !eStr) {
            NSLog(@"Missing required parameters 'n' or 'e'");
            return nil;
        }
        
        NSData *modulus = [self base64URLDecodeString:nStr];
        NSData *exponent = [self base64URLDecodeString:eStr];
        
        if (!modulus || !exponent) {
            NSLog(@"Invalid base64url encoding in JWK parameters");
            return nil;
        }
        
        // Check if this is a private key (has 'd' parameter)
        NSString *dStr = jwk[@"d"];
        BOOL hasPrivateExponent = dStr != nil && dStr.length > 0;
        
        if (hasPrivateExponent) {
            // Create private key from JWK parameters
            NSString *pStr = jwk[@"p"];
            NSString *qStr = jwk[@"q"];
            NSString *dpStr = jwk[@"dp"];
            NSString *dqStr = jwk[@"dq"];
            NSString *qiStr = jwk[@"qi"];
            
            if (!pStr || !qStr || !dpStr || !dqStr || !qiStr) {
                NSLog(@"Missing private key parameters");
                return nil;
            }
            
            NSData *d = [self base64URLDecodeString:dStr];
            NSData *p = [self base64URLDecodeString:pStr];
            NSData *q = [self base64URLDecodeString:qStr];
            NSData *dp = [self base64URLDecodeString:dpStr];
            NSData *dq = [self base64URLDecodeString:dqStr];
            NSData *qi = [self base64URLDecodeString:qiStr];
            
            if (!d || !p || !q || !dp || !dq || !qi) {
                NSLog(@"Invalid base64url encoding in private key parameters");
                return nil;
            }
            
            // Create private key ASN.1 structure
            NSData *privateKeyASN1 = [self createRSAPrivateKeyASN1:modulus exponent:exponent d:d p:p q:q dp:dp dq:dq qi:qi];
            if (!privateKeyASN1) {
                NSLog(@"Failed to create private key ASN.1 structure");
                return nil;
            }
            
            return [self pemFormat:privateKeyASN1 tag:@"RSA PRIVATE"];
        } else {
            // Create public key from modulus and exponent
            NSData *publicKeyASN1 = [self createRSAPublicKeyASN1:modulus exponent:exponent];
            return [self pemFormat:publicKeyASN1 tag:@"RSA PUBLIC"];
        }
    } @catch (NSException *exception) {
        NSLog(@"Exception in importJwkKey: %@", exception.reason);
        return nil;
    }
}

+ (nullable NSDictionary *)exportPemKey:(NSString *)pemKey {
    @try {
        NSData *keyData = [self pemParse:pemKey];
        if (!keyData) {
            NSLog(@"Invalid PEM format");
            return nil;
        }
        
        BOOL isPublic = [pemKey containsString:@"PUBLIC"];
        BOOL isRsaPkcs1 = [pemKey containsString:@"RSA"];
        
        NSMutableDictionary *jwk = [[NSMutableDictionary alloc] init];
        
        if (isPublic) {
            if (isRsaPkcs1) {
                // PKCS#1 RSA PUBLIC KEY - parse ASN.1 directly
                NSDictionary *keyComponents = [self parseRSAPublicKeyASN1:keyData];
                if (!keyComponents) {
                    NSLog(@"Failed to parse RSA public key ASN.1 structure");
                    return nil;
                }
                [jwk addEntriesFromDictionary:keyComponents];
            } else {
                // X.509 SubjectPublicKeyInfo - extract the public key and parse it
                SecKeyRef publicKey = [self createKeyFromPem:pemKey isPublic:YES];
                if (!publicKey) {
                    NSLog(@"Failed to create public key from PEM");
                    return nil;
                }
                
                // Get the raw public key data 
                CFErrorRef error = NULL;
                NSData *publicKeyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(publicKey, &error);
                CFRelease(publicKey);
                
                if (!publicKeyData) {
                    if (error) CFRelease(error);
                    NSLog(@"Failed to export public key");
                    return nil;
                }
                
                // Parse the raw RSA public key data
                NSDictionary *keyComponents = [self parseRSAPublicKeyASN1:publicKeyData];
                if (!keyComponents) {
                    NSLog(@"Failed to parse public key components");
                    return nil;
                }
                [jwk addEntriesFromDictionary:keyComponents];
            }
            
            // Add standard JWK fields for public key
            jwk[@"key_ops"] = @[@"encrypt"];
        } else {
            // Private key export - try to parse the private key
            SecKeyRef privateKey = [self createKeyFromPem:pemKey isPublic:NO];
            if (!privateKey) {
                NSLog(@"Failed to create private key from PEM");
                return nil;
            }
            
            // Get the external representation of the private key
            CFErrorRef error = NULL;
            NSData *privateKeyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(privateKey, &error);
            CFRelease(privateKey);
            
            if (!privateKeyData) {
                if (error) CFRelease(error);
                NSLog(@"Failed to export private key");
                return nil;
            }
            
            // Parse the private key ASN.1 structure
            NSDictionary *privateKeyComponents = [self parseRSAPrivateKeyASN1:privateKeyData];
            if (!privateKeyComponents) {
                NSLog(@"Failed to parse private key components");
                return nil;
            }
            [jwk addEntriesFromDictionary:privateKeyComponents];
            
            // Add standard JWK fields for private key
            jwk[@"key_ops"] = @[@"decrypt"];
        }
        
        // Add common JWK fields
        jwk[@"kty"] = @"RSA";
        jwk[@"alg"] = @"RSA-OAEP-256";
        jwk[@"ext"] = @YES;
        
        return jwk;
    } @catch (NSException *exception) {
        NSLog(@"Exception in exportPemKey: %@", exception.reason);
        return nil;
    }
}

// Helper methods

+ (nullable NSString *)pemFormat:(NSData *)keyData tag:(NSString *)tag {
    NSString *header = [NSString stringWithFormat:@"-----BEGIN %@ KEY-----", tag];
    NSString *footer = [NSString stringWithFormat:@"-----END %@ KEY-----", tag];
    NSString *base64Key = [keyData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    return [NSString stringWithFormat:@"%@\n%@\n%@", header, base64Key, footer];
}

+ (nullable NSData *)pemParse:(NSString *)pemString {
    // Check in the order from the original implementation
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
            return [[NSData alloc] initWithBase64EncodedString:strippedKey options:NSDataBase64DecodingIgnoreUnknownCharacters];
        }
    }
    return [[NSData alloc] initWithBase64EncodedString:pemString options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

+ (nullable SecKeyRef)createKeyFromPem:(NSString *)pemString isPublic:(BOOL)isPublic {
    NSData *keyData = [self pemParse:pemString];
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

+ (SecKeyAlgorithm)algorithmFromHash:(nullable NSString *)hash forSigning:(BOOL)forSigning {
    if (forSigning) {
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
    } else {
        return kSecKeyAlgorithmRSAEncryptionOAEPSHA256;
    }
}

+ (nullable NSData *)rsaEncryptData:(NSData *)data withKey:(SecKeyRef)publicKey {
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
        if (error) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"RSA encryption failed: %@", err);
        }
    }
    
    return cipherText;
}

+ (nullable NSData *)rsaDecryptData:(NSData *)data withKey:(SecKeyRef)privateKey {
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
        if (error) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"RSA decryption failed: %@", err);
        }
    }
    
    return clearText;
}

// MARK: - JWK Helper Methods

+ (NSData *)base64URLDecodeString:(NSString *)string {
    // Convert base64url to base64
    NSString *base64String = [CryptoUtils base64FromBase64URL:string];
    return [CryptoUtils decodeBase64:base64String];
}

+ (NSString *)base64URLEncodeData:(NSData *)data {
    NSString *base64String = [CryptoUtils encodeBase64:data];
    // Convert base64 to base64url (replace + with -, / with _, remove padding)
    base64String = [base64String stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    base64String = [base64String stringByReplacingOccurrencesOfString:@"=" withString:@""];
    return base64String;
}

+ (NSData *)createASN1IntegerFromBigInteger:(NSData *)integerData {
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

+ (NSData *)createRSAPublicKeyASN1:(NSData *)modulus exponent:(NSData *)exponent {
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

+ (NSData *)createRSAPrivateKeyASN1:(NSData *)modulus 
                            exponent:(NSData *)publicExponent
                                   d:(NSData *)privateExponent
                                   p:(NSData *)p
                                   q:(NSData *)q
                                  dp:(NSData *)dp
                                  dq:(NSData *)dq
                                  qi:(NSData *)qi {
    // Create RSAPrivateKey ASN.1 structure
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

+ (NSData *)parseASN1Integer:(NSData *)data offset:(NSUInteger *)offset {
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

+ (NSDictionary *)parseRSAPublicKeyASN1:(NSData *)asn1Data {
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

+ (NSDictionary *)parseRSAPrivateKeyASN1:(NSData *)asn1Data {
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

@end
