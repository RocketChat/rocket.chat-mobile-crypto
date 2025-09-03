#import "CryptoUtils.h"

@implementation CryptoUtils

+ (NSData *)fromHex:(NSString *)string {
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

+ (NSString *)bytesToHex:(NSData *)data {
    const unsigned char *bytes = (const unsigned char *)[data bytes];
    NSMutableString *hex = [[NSMutableString alloc] init];
    
    for (NSInteger i = 0; i < [data length]; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    
    return [NSString stringWithString:hex];
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
