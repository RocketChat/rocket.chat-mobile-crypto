#import "MobileCrypto.h"
#import "algorithms/CryptoUtils.h"
#import "algorithms/AESCrypto.h"
#import "algorithms/PBKDF2Crypto.h"
#import "algorithms/HMACCrypto.h"
#import "algorithms/SHACrypto.h"
#import "algorithms/RSACrypto.h"
#import "algorithms/RandomUtils.h"
#import "algorithms/FileUtils.h"



@implementation MobileCrypto
RCT_EXPORT_MODULE(MobileCrypto)

// MARK: - SHA Methods
- (void)shaBase64:(NSString *)data 
        algorithm:(NSString *)algorithm 
          resolve:(RCTPromiseResolveBlock)resolve 
           reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSString *result = [SHACrypto hashBase64:data algorithm:algorithm];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"Invalid algorithm or input", nil);
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
        NSString *result = [SHACrypto hashUtf8ToHex:data algorithm:algorithm];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"Invalid algorithm", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
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
        NSString *result = [PBKDF2Crypto deriveKeyBase64:pwdBase64
                                              saltBase64:saltBase64
                                              iterations:(NSUInteger)iterations
                                               keyLength:(NSUInteger)keyLen
                                           hashAlgorithm:hash];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"PBKDF2 derivation failed", nil);
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
        NSString *result = [HMACCrypto hmacSha256Hex:data keyHex:key];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"HMAC computation failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

// MARK: - AES Methods
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
        
        NSString *result = [AESCrypto encryptBase64:dataBase64 keyHex:keyHex ivHex:ivHex];
        if (result) {
            resolve(result);
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
        
        NSString *result = [AESCrypto decryptBase64:dataBase64 keyHex:keyHex ivHex:ivHex];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"Decryption failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)aesGcmEncrypt:(NSString *)dataBase64
               keyHex:(NSString *)keyHex
                ivHex:(NSString *)ivHex
              resolve:(RCTPromiseResolveBlock)resolve
               reject:(RCTPromiseRejectBlock)reject {
    @try {
        if (!dataBase64 || dataBase64.length == 0) {
            resolve([NSNull null]);
            return;
        }
        
        NSString *result = [AESCrypto encryptGcmBase64:dataBase64 keyHex:keyHex ivHex:ivHex];
        resolve(result ?: [NSNull null]);
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)aesGcmDecrypt:(NSString *)dataBase64
               keyHex:(NSString *)keyHex
                ivHex:(NSString *)ivHex
              resolve:(RCTPromiseResolveBlock)resolve
               reject:(RCTPromiseRejectBlock)reject {
    @try {
        if (!dataBase64 || dataBase64.length == 0) {
            resolve([NSNull null]);
            return;
        }
        
        NSString *result = [AESCrypto decryptGcmBase64:dataBase64 keyHex:keyHex ivHex:ivHex];
        resolve(result ?: [NSNull null]);
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)aesEncryptFile:(NSString *)filePath
          base64UrlKey:(NSString *)base64UrlKey
              base64Iv:(NSString *)base64Iv
               resolve:(RCTPromiseResolveBlock)resolve
                reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSString *result = [AESCrypto encryptFile:filePath base64UrlKey:base64UrlKey base64Iv:base64Iv];
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
        NSString *result = [AESCrypto decryptFile:filePath base64UrlKey:base64UrlKey base64Iv:base64Iv];
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
        NSString *result = [RandomUtils generateUuid];
        resolve(result);
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)randomKey:(double)length
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSString *result = [RandomUtils generateRandomKeyHex:(NSUInteger)length];
        if (result) {
            resolve(result);
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
        NSString *result = [RandomUtils generateRandomBytesBase64:(NSUInteger)size];
        if (result) {
            resolve(result);
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
        NSString *result = [RandomUtils generateRandomAlphanumeric:(NSUInteger)length];
        resolve(result);
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

// MARK: - File Checksum Method
- (void)calculateFileChecksum:(NSString *)filePath
                      resolve:(RCTPromiseResolveBlock)resolve
                       reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSString *result = [FileUtils calculateSha256Checksum:filePath];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"File checksum calculation failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

// MARK: - RSA Methods
- (void)rsaGenerateKeys:(NSNumber *)keySize
                resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSInteger actualKeySize = keySize ? [keySize integerValue] : 2048;
        NSDictionary *result = [RSACrypto generateKeyPair:actualKeySize];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"Key generation failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)rsaEncrypt:(NSString *)message
         publicKey:(NSString *)publicKeyString
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSString *result = [RSACrypto encrypt:message publicKeyPem:publicKeyString];
        if (result) {
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
        NSString *result = [RSACrypto encryptBase64:message publicKeyPem:publicKeyString];
        if (result) {
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
        NSString *result = [RSACrypto decrypt:encodedMessage privateKeyPem:privateKeyString];
        if (result) {
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
        NSString *result = [RSACrypto decryptToBase64:encodedMessage privateKeyPem:privateKeyString];
        if (result) {
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
        NSString *result = [RSACrypto sign:message privateKeyPem:privateKeyString hashAlgorithm:hash];
        if (result) {
            resolve(result);
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
        NSString *result = [RSACrypto signBase64:message privateKeyPem:privateKeyString hashAlgorithm:hash];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"Signing failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)rsaVerify:(NSString *)signatureString
          message:(NSString *)message
        publicKey:(NSString *)publicKeyString
             hash:(NSString *)hash
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject {
    @try {
        BOOL result = [RSACrypto verify:signatureString message:message publicKeyPem:publicKeyString hashAlgorithm:hash];
        resolve(@(result));
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)rsaVerify64:(NSString *)signatureString
            message:(NSString *)message
          publicKey:(NSString *)publicKeyString
               hash:(NSString *)hash
            resolve:(RCTPromiseResolveBlock)resolve
             reject:(RCTPromiseRejectBlock)reject {
    @try {
        BOOL result = [RSACrypto verifyBase64:signatureString messageBase64:message publicKeyPem:publicKeyString hashAlgorithm:hash];
        resolve(@(result));
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

// MARK: - RSA Key Format Conversion Methods
- (void)rsaImportKey:(JS::NativeMobileCrypto::JWK &)jwk
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject {
    @try {
        // Convert JWK struct to NSDictionary
        NSMutableDictionary *jwkDict = [[NSMutableDictionary alloc] init];
        
        // Required parameters
        jwkDict[@"kty"] = jwk.kty();
        jwkDict[@"n"] = jwk.n();
        jwkDict[@"e"] = jwk.e();
        
        // Optional parameters
        if (jwk.alg()) {
            jwkDict[@"alg"] = jwk.alg();
        }
        if (jwk.ext().has_value()) {
            jwkDict[@"ext"] = @(jwk.ext().value());
        }
        if (jwk.key_ops().has_value()) {
            NSMutableArray *keyOps = [[NSMutableArray alloc] init];
            auto keyOpsVector = jwk.key_ops().value();
            for (size_t i = 0; i < keyOpsVector.size(); i++) {
                [keyOps addObject:keyOpsVector[i]];
            }
            jwkDict[@"key_ops"] = keyOps;
        }
        if (jwk.d()) {
            jwkDict[@"d"] = jwk.d();
        }
        if (jwk.p()) {
            jwkDict[@"p"] = jwk.p();
        }
        if (jwk.q()) {
            jwkDict[@"q"] = jwk.q();
        }
        if (jwk.dp()) {
            jwkDict[@"dp"] = jwk.dp();
        }
        if (jwk.dq()) {
            jwkDict[@"dq"] = jwk.dq();
        }
        if (jwk.qi()) {
            jwkDict[@"qi"] = jwk.qi();
        }
        
        NSString *result = [RSACrypto importJwkKey:jwkDict];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"Key import failed", nil);
        }
    } @catch (NSException *exception) {
        reject(@"-1", exception.reason, nil);
    }
}

- (void)rsaExportKey:(NSString *)pem
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSDictionary *result = [RSACrypto exportPemKey:pem];
        if (result) {
            resolve(result);
        } else {
            reject(@"-1", @"Key export failed", nil);
        }
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
