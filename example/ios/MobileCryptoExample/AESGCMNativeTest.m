#import "AESGCMNativeTest.h"
#import <MobileCrypto/AESCrypto.h>

@implementation AESGCMNativeTest

+ (void)runTests {
    NSLog(@"🔐 Starting Native Objective-C AES-GCM Tests...");
    
    // Test data
    NSString *testMessage = @"Hello World from Native Objective-C!";
    NSData *testMessageData = [testMessage dataUsingEncoding:NSUTF8StringEncoding];
    NSString *testMessageBase64 = [testMessageData base64EncodedStringWithOptions:0];
    NSString *testKey = @"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // 256-bit key
    NSString *testIV = @"fedcba9876543210fedcba98"; // 96-bit IV (12 bytes)
    
    NSLog(@"📝 Test Data:");
    NSLog(@"  Original message: %@", testMessage);
    NSLog(@"  Base64 message: %@", testMessageBase64);
    NSLog(@"  Key (hex): %@", testKey);
    NSLog(@"  IV (hex): %@", testIV);
    NSLog(@"");
    
    // Test 1: Basic Encryption
    NSLog(@"🧪 Test 1: AES-GCM Encryption");
    NSString *encrypted = [AESCrypto encryptGcmBase64:testMessageBase64 keyHex:testKey ivHex:testIV];
    
    if (encrypted) {
        NSLog(@"  ✅ Encryption successful!");
        NSLog(@"  📦 Encrypted data: %@", encrypted);
        
        // Test 2: Basic Decryption
        NSLog(@"");
        NSLog(@"🧪 Test 2: AES-GCM Decryption");
        NSString *decrypted = [AESCrypto decryptGcmBase64:encrypted keyHex:testKey ivHex:testIV];
        
        if (decrypted) {
            NSLog(@"  ✅ Decryption successful!");
            NSLog(@"  📄 Decrypted data: %@", decrypted);
            
            // Verify the roundtrip
            if ([decrypted isEqualToString:testMessageBase64]) {
                NSLog(@"  🎉 Roundtrip test PASSED! Original and decrypted data match.");
            } else {
                NSLog(@"  ❌ Roundtrip test FAILED! Data doesn't match.");
            }
        } else {
            NSLog(@"  ❌ Decryption failed!");
        }
    } else {
        NSLog(@"  ❌ Encryption failed!");
    }
    
    // Test 3: Authentication Test (Wrong Key)
    NSLog(@"");
    NSLog(@"🧪 Test 3: Authentication Test (Wrong Key)");
    NSString *wrongKey = @"1111111111111111111111111111111111111111111111111111111111111111";
    
    NSString *encryptedForAuth = [AESCrypto encryptGcmBase64:testMessageBase64 keyHex:testKey ivHex:testIV];
    if (encryptedForAuth) {
        // Try to decrypt with wrong key
        NSString *decryptedWithWrongKey = [AESCrypto decryptGcmBase64:encryptedForAuth keyHex:wrongKey ivHex:testIV];
        
        if (!decryptedWithWrongKey) {
            NSLog(@"  ✅ Authentication test PASSED! Wrong key correctly rejected.");
        } else {
            NSLog(@"  ❌ Authentication test FAILED! Wrong key should be rejected.");
        }
    }
    
    NSLog(@"");
    NSLog(@"🎉 Native Objective-C AES-GCM Tests Completed!");
    NSLog(@"");
}

@end
