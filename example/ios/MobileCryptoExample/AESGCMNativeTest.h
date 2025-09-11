#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * Native Objective-C test class for AES-GCM encryption/decryption
 * This demonstrates how to use the MobileCrypto AES-GCM functionality directly from Objective-C
 */
@interface AESGCMNativeTest : NSObject

/**
 * Run comprehensive AES-GCM tests using the native iOS crypto implementation
 * This method tests encryption, decryption, authentication, and edge cases
 */
+ (void)runTests;

@end

NS_ASSUME_NONNULL_END
