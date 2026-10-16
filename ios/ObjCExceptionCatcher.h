#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ObjCExceptionCatcher : NSObject

+ (nullable NSString *)exceptionReasonDuringBlock:(NS_NOESCAPE void (^)(void))block
    NS_SWIFT_NAME(exceptionReason(during:));

@end

NS_ASSUME_NONNULL_END
