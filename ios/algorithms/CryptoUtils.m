#import "CryptoUtils.h"

@implementation CryptoUtils

+ (NSData *)fromHex:(NSString *)string {
    NSData *hexCharacters = [string dataUsingEncoding:NSASCIIStringEncoding allowLossyConversion:YES];
    const char *characters = hexCharacters.bytes;
    NSUInteger byteCount = hexCharacters.length / 2;
    NSMutableData *bytes = [NSMutableData dataWithLength:byteCount];
    unsigned char *byteBuffer = bytes.mutableBytes;
    char hexPair[3] = {'\0','\0','\0'};
    for (NSUInteger index = 0; index < byteCount; index++) {
        hexPair[0] = characters[index * 2];
        hexPair[1] = characters[index * 2 + 1];
        byteBuffer[index] = strtol(hexPair, NULL, 16);
    }
    return bytes;
}

+ (NSString *)bytesToHex:(NSData *)data {
    static const char hexDigits[] = "0123456789abcdef";
    const unsigned char *bytes = (const unsigned char *)[data bytes];
    NSMutableData *hexCharacters = [NSMutableData dataWithLength:data.length * 2];
    char *hexBuffer = hexCharacters.mutableBytes;
    for (NSUInteger index = 0; index < data.length; index++) {
        hexBuffer[index * 2] = hexDigits[bytes[index] >> 4];
        hexBuffer[index * 2 + 1] = hexDigits[bytes[index] & 0x0F];
    }
    return [[NSString alloc] initWithData:hexCharacters encoding:NSASCIIStringEncoding];
}

+ (NSString *)base64FromBase64URL:(NSString *)base64URL {
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

+ (NSData *)stringToUtf8Data:(NSString *)string {
    return [string dataUsingEncoding:NSUTF8StringEncoding];
}

+ (NSString *)utf8DataToString:(NSData *)data {
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

+ (NSString *)encodeBase64:(NSData *)data {
    return [data base64EncodedStringWithOptions:0];
}

+ (nullable NSData *)decodeBase64:(NSString *)base64String {
    return [[NSData alloc] initWithBase64EncodedString:base64String options:0];
}

@end
