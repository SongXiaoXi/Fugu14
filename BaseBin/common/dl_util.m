#include <unistd.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <Foundation/Foundation.h>

void log_dlerror(void) {
    NSLog(@"failed to load TweakLoader.dylib: %s", dlerror());
}