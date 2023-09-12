//
//  core_symbolication.c
//  CRJailbreakUtilities
//
//  Created by SXX on 2023/4/26.
//  Copyright © 2023 SXX. All rights reserved.
//

#include <mach/mach_types.h>
#include <mach/mach_init.h>
#include <stddef.h>
#include <string.h>
#include <dlfcn.h>
#include "CoreSymbolication.h"

CSSymbolicatorRef (*CSSymbolicatorCreateWithTask)(task_t task);

static bool (*CSIsNull)(CSTypeRef cs);
static int (*CSSymbolicatorForeachSymbolOwnerWithNameAtTime)(CSSymbolicatorRef cs, const char* name, uint64_t time, CSSymbolOwnerIterator it);
static long (*CSSymbolOwnerForeachSymbol)(CSSymbolOwnerRef owner, CSSymbolIterator each);
static const char* (*CSSymbolGetMangledName)(CSSymbolRef sym);
CSRange (*CSSymbolGetRange)(CSSymbolRef sym);

static void (*CSRelease)(CSTypeRef cs);

static void *CoreSymbolicationHandle;

int CRJUSymbolicationInit(void) {
    if (CoreSymbolicationHandle != NULL) {
        return true;
    }
    CoreSymbolicationHandle = dlopen("/System/Library/PrivateFrameworks/CoreSymbolication.framework/CoreSymbolication", RTLD_LAZY);
    if (CoreSymbolicationHandle == NULL) {
        goto failed;
    }
    void *h = CoreSymbolicationHandle;
    CSSymbolicatorCreateWithTask = dlsym(h, "CSSymbolicatorCreateWithTask");
    CSIsNull = dlsym(h, "CSIsNull");
    CSSymbolicatorForeachSymbolOwnerWithNameAtTime = dlsym(h, "CSSymbolicatorForeachSymbolOwnerWithNameAtTime");
    CSRelease = dlsym(h, "CSRelease");
    CSSymbolOwnerForeachSymbol = dlsym(h, "CSSymbolOwnerForeachSymbol");
    CSSymbolGetMangledName = dlsym(h, "CSSymbolGetMangledName");
    CSSymbolGetRange = dlsym(h, "CSSymbolGetRange");
    
    if (CSSymbolicatorCreateWithTask == NULL ||
        CSIsNull == NULL ||
        CSSymbolicatorForeachSymbolOwnerWithNameAtTime == NULL ||
        CSRelease == NULL ||
        CSSymbolOwnerForeachSymbol == NULL ||
        CSSymbolGetMangledName == NULL ||
        CSSymbolGetRange == NULL) {
        goto failed;
    }
    
    return true;
failed:
    if (CoreSymbolicationHandle) {
        dlclose(CoreSymbolicationHandle);
        CoreSymbolicationHandle = NULL;
    }
    return false;
}

void *CRJUFindSymbol(const char *symbol_owner, const char *symbol_to_resolve) {
    task_t targetTask = mach_task_self();
    CSSymbolicatorRef targetSymbolicator;

    targetSymbolicator = CSSymbolicatorCreateWithTask(targetTask);
    if(CSIsNull(targetSymbolicator)) {
        return NULL;
    }

    __block CSSymbolOwnerRef symbolOwner = kCSNull;
    CSSymbolicatorForeachSymbolOwnerWithNameAtTime(targetSymbolicator,
                                                   symbol_owner,
                                                   kCSNow,
                                                   ^(CSSymbolOwnerRef owner) {
                                                       symbolOwner = owner;
                                                   });
    if (CSIsNull(symbolOwner)) {
        CSRelease(targetSymbolicator);
        return NULL;
    }

    __block uintptr_t p = (uintptr_t)NULL;
    CSSymbolOwnerForeachSymbol(symbolOwner, ^(CSSymbolRef symbol) {
        const char *symbol_name = CSSymbolGetMangledName(symbol);
        if (symbol_name != NULL) {
            if (0 == strcmp(symbol_name, symbol_to_resolve)) {
                p = CSSymbolGetRange(symbol).location;
            }
        }
    });

    CSRelease(targetSymbolicator);
    if ((uintptr_t)NULL == p) {
        return NULL;
    } else {
        return (void *)p;
    }
}
