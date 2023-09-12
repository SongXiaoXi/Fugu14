#ifndef _UTIL_H_
#define _UTIL_H_

#if __OBJC__
#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>

#define JBLogDebug(...)  NSLog(@__VA_ARGS__)
#define JBLogError(...)  NSLog(@__VA_ARGS__)

// #define JBLogDebug(...) 
// #define JBLogError(...) 

NSString *prebootPath(NSString *path);
int evaluateSignature(NSURL* fileURL, NSData **cdHashOut, BOOL *isAdhocSignedOut);
BOOL isCdHashInTrustCache(NSData *cdHash);
#endif

#endif // _UTIL_H_