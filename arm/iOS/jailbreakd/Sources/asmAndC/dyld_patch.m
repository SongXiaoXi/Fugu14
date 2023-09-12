#include <stdio.h>
#include <mach/machine.h>
#import <Foundation/Foundation.h>
#include "CoreSymbolication.h"
#include "codesign.h"
#include "util.h"
#include <dlfcn.h>

int applyDyldPatches(NSString *dyldPath) {
	// Find offsets by abusing CoreSymbolication APIs
	void *csHandle = dlopen("/System/Library/PrivateFrameworks/CoreSymbolication.framework/CoreSymbolication", RTLD_NOW);
	CSSymbolicatorRef (*__CSSymbolicatorCreateWithPathAndArchitecture)(const char* path, cpu_type_t type) = dlsym(csHandle, "CSSymbolicatorCreateWithPathAndArchitecture");
	CSSymbolRef (*__CSSymbolicatorGetSymbolWithMangledNameAtTime)(CSSymbolicatorRef cs, const char* name, uint64_t time) = dlsym(csHandle, "CSSymbolicatorGetSymbolWithMangledNameAtTime");
	CSRange (*__CSSymbolGetRange)(CSSymbolRef sym) = dlsym(csHandle, "CSSymbolGetRange");
	//void (*__CSRelease)(CSTypeRef ptr) = dlsym(csHandle, "CSRelease");

	CSSymbolicatorRef symbolicator = __CSSymbolicatorCreateWithPathAndArchitecture("/usr/lib/dyld", CPU_TYPE_ARM64);
	CSSymbolRef symbol = __CSSymbolicatorGetSymbolWithMangledNameAtTime(symbolicator, "_amfi_check_dyld_policy_self", 0);
	CSRange range = __CSSymbolGetRange(symbol);
	//__CSRelease(symbolicator);
	//__CSRelease(symbol);
	uint64_t getAMFIOffset = range.location;
	if (getAMFIOffset == 0) {
		return 100;
	}

	FILE *dyldFile = fopen(dyldPath.fileSystemRepresentation, "rb+");
	if (!dyldFile) return 101;
	fseek(dyldFile, getAMFIOffset, SEEK_SET);
	uint32_t patchInstr[4] = {
        0xd2801be2,  // mov x2, 0xDF
        0xb9000022,  // str w2, [x1]
        0xd2800000,  // mov x0, 0
        0xd65f03c0,  // ret
	};
	extern char **environ;
	fwrite(patchInstr, sizeof(patchInstr), 1, dyldFile); 
	fclose(dyldFile);

	const char *argv[] = {"/var/jb/basebin/ldid", "-M", "-S", dyldPath.fileSystemRepresentation, NULL};
	pid_t pid = fork();
    if (pid == 0) {
		execve(argv[0], argv, environ);
		exit(-1);
	}
	int status;
	waitpid(pid, &status, 0);
	if (status != 0) {
		return status;
	}

	return 0;
}