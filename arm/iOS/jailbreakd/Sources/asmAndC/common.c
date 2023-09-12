#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <objc/objc.h>
#include <errno.h>
#include <paths.h>
#include <spawn.h>

#include "../../xpc/xpc.h"
#include "../../xpc/private.h"


#define POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE 0x48
#define POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE 0x4C
#define JETSAM_MULTIPLIER 3

extern int processBinary(const char *path);

typedef enum 
{
	kBinaryConfigDontInject = 1 << 0,
	kBinaryConfigDontProcess = 1 << 1
} kBinaryConfig;

#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t * __restrict, int * __restrict) __API_AVAILABLE(macos(10.8), ios(6.0));

#define HOOK_DYLIB_PATH "/usr/lib/systemhook.dylib"

bool stringEndsWith(const char* str, const char* suffix) {
	if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}


static int64_t jbdswProcessBinary(const char *filePath) {
	// if file doesn't exist, bail out
	if (access(filePath, F_OK) != 0) return 0;

	// if file is on rootfs mount point, it doesn't need to be
	// processed as it's guaranteed to be in static trust cache
	// same goes for our /usr/lib bind mount
	struct statfs fs;
	int sfsret = statfs(filePath, &fs);
	if (sfsret == 0) {
		if (!strcmp(fs.f_mntonname, "/") || !strcmp(fs.f_mntonname, "/usr/lib")) return -1;
	}
    #warning Path should modified

	char absolutePath[PATH_MAX];
	if (realpath(filePath, absolutePath) == NULL) return -1;

	int result = processBinary(filePath);
	return result;
}

static int64_t jbdswProcessLibrary(const char *filePath)
{
	if (_dyld_shared_cache_contains_path(filePath)) return 0;
	return jbdswProcessBinary(filePath);
}

kBinaryConfig configForBinary(const char* path, char *const argv[restrict])
{
	// Don't do anything for jailbreakd because this wanting to launch implies it's not running currently
	if (stringEndsWith(path, "/jailbreakd")) {
		return (kBinaryConfigDontInject | kBinaryConfigDontProcess);
	}
#if 0
	// Don't do anything for xpcproxy if it's called on jailbreakd because this also implies jbd is not running currently
	if (!strcmp(path, "/usr/libexec/xpcproxy")) {
		if (argv) {
			if (argv[0]) {
				if (argv[1]) {
					if (!strcmp(argv[1], "com.opa334.jailbreakd")) {
						return (kBinaryConfigDontInject | kBinaryConfigDontProcess);
					}
				}
			}
		}
	}
#endif

	// Blacklist to ensure general system stability
	// I don't like this but for some processes it seems neccessary
	const char *processBlacklist[] = {
		"/System/Library/Frameworks/GSS.framework/Helpers/GSSCred",
		"/System/Library/PrivateFrameworks/IDSBlastDoorSupport.framework/XPCServices/IDSBlastDoorService.xpc/IDSBlastDoorService",
		"/System/Library/PrivateFrameworks/MessagesBlastDoorSupport.framework/XPCServices/MessagesBlastDoorService.xpc/MessagesBlastDoorService",
		"/usr/sbin/wifid"
	};
	size_t blacklistCount = sizeof(processBlacklist) / sizeof(processBlacklist[0]);
	for (size_t i = 0; i < blacklistCount; i++)
	{
		if (!strcmp(processBlacklist[i], path)) return (kBinaryConfigDontInject | kBinaryConfigDontProcess);
	}

	return 0;
}

int spawn_hook_common(pid_t *restrict pid, const char *restrict path,
					   const posix_spawn_file_actions_t *restrict file_actions,
					   const posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict],
					   void *orig)
{
	int (*pspawn_orig)(pid_t *restrict, const char *restrict, const posix_spawn_file_actions_t *restrict, const posix_spawnattr_t *restrict, char *const[restrict], char *const[restrict]) = orig;
	if (!path) {
		return pspawn_orig(pid, path, file_actions, attrp, argv, envp);
	}

	kBinaryConfig binaryConfig = configForBinary(path, argv);
	
	if (!(binaryConfig & kBinaryConfigDontProcess)) {
		// jailbreakd: Upload binary to trustcache if needed
		jbdswProcessBinary(path);
	}

	// Determine length envp passed
	char **ogEnv = (char **)envp;
	size_t ogEnvCount = 0;
	if (ogEnv) {
		while (ogEnv[ogEnvCount++] != NULL);
	}

	bool shouldInject = true;
	int existingSafeModeIndex = -1;
	int existingMSSafeModeIndex = -1;

	if (shouldInject) {
		// Check if we can find a _SafeMode or _MSSafeMode variable
		// In this case we do not want to inject anything
		// But we also want to remove the variables before spawning the process
		
		const char *safeModeVar = "_SafeMode=1";
		if (ogEnvCount > 0) {
			for (int i = 0; i < ogEnvCount-1; i++) {
				if(strncmp(ogEnv[i], safeModeVar, strlen(safeModeVar)) == 0) {
					shouldInject = false;
					existingSafeModeIndex = i;
					break;
				}
			}
		}
		
		const char *msSafeModeVar = "_MSSafeMode=1";
		if (ogEnvCount > 0) {
			for (int i = 0; i < ogEnvCount-1; i++) {
				if(strncmp(ogEnv[i], msSafeModeVar, strlen(msSafeModeVar)) == 0) {
					shouldInject = false;
					existingMSSafeModeIndex = i;
					break;
				}
			}
		}
	}
	
	if (binaryConfig & kBinaryConfigDontInject) {
		shouldInject = false;
	}
	
	if (attrp) {
		int proctype = 0;
		posix_spawnattr_getprocesstype_np(attrp, &proctype);
		if (proctype == POSIX_SPAWN_PROC_TYPE_DRIVER) {
			// Do not inject hook into DriverKit drivers
			shouldInject = false;
		}
	}
	
	if (shouldInject) {
		if (access(HOOK_DYLIB_PATH, F_OK) != 0) {
			// If the hook dylib doesn't exist, don't try to inject it (would crash the process)
			shouldInject = false;
		}
	}

	// Check if we can find an existing "DYLD_INSERT_LIBRARIES" env variable
	int existingLibraryInsertIndex = -1;
	const char *insertVarPrefix = "DYLD_INSERT_LIBRARIES=";
	if (ogEnvCount > 0) {
		for (int i = 0; i < ogEnvCount-1; i++) {
			if(strncmp(ogEnv[i], insertVarPrefix, strlen(insertVarPrefix)) == 0) {
				existingLibraryInsertIndex = i;
				break;
			}
		}
	}

	// If we have found an existing DYLD_INSERT_LIBRARIES variable, check if the systemwide.dylib is already in there
	// Also, all other libraries in that variable need to be processed with jailbreakd to ensure they are in trustcache
	bool isAlreadyInjected = false;
	if (existingLibraryInsertIndex != -1) {
		char *const existingEnv = ogEnv[existingLibraryInsertIndex];
		char *libPaths = strdup(&existingEnv[strlen(insertVarPrefix)]);
		char *libPath = strtok(libPaths, ":");
		while (libPath != NULL) {
			if (!strcmp(libPath, HOOK_DYLIB_PATH)) {
				isAlreadyInjected = true;
			}
			else {
				if (!(binaryConfig & kBinaryConfigDontProcess)) {
					jbdswProcessLibrary(libPath);
				}
			}
			libPath = strtok(NULL, ":");
		}
		free(libPaths);
	}

	// If systemhook is being injected and Jetsam limits are set, increase them by a factor of JETSAM_MULTIPLIER
	if (shouldInject) {
		if (attrp) {
			uint8_t *attrStruct = *attrp;
			if (attrStruct) {
				int memlimit_active = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE);
				if (memlimit_active != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE) = memlimit_active * JETSAM_MULTIPLIER;
				}
				int memlimit_inactive = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE);
				if (memlimit_inactive != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE) = memlimit_inactive * JETSAM_MULTIPLIER;
				}
			}
		}
	}

	if (shouldInject == isAlreadyInjected && (existingSafeModeIndex == -1 && existingMSSafeModeIndex == -1)) {
		// we already good, just call orig
		return pspawn_orig(pid, path, file_actions, attrp, argv, envp);
	}
	else {
		// the state we want is not the state we are in right now

		if (shouldInject) {
			// Add dylib insert environment variable
			// If we did not find an existing variable, new size is one bigger than the old size
			size_t newEnvCount = ogEnvCount + (existingLibraryInsertIndex == -1);
			if (ogEnvCount == 0) newEnvCount = 2; // if og is 0, new needs to be 2 (our var + NULL)

			// Create copy of environment to pass to posix_spawn
			// Unlike the environment passed to here, this has to be deallocated later
			char **newEnv = malloc(newEnvCount * sizeof(char *));
			if (ogEnvCount > 0) {
				for (int i = 0; i < ogEnvCount-1; i++) {
					newEnv[i] = strdup(ogEnv[i]);
				}
			}
			newEnv[newEnvCount-1] = NULL;

			if (existingLibraryInsertIndex == -1) {
				//printf("No DYLD_INSERT_LIBRARIES exists, inserting...\n");
				// No DYLD_INSERT_LIBRARIES exists, insert our own at position newEnvCount-2 as we have allocated extra space for it there
				newEnv[newEnvCount-2] = strdup("DYLD_INSERT_LIBRARIES=" HOOK_DYLIB_PATH);
			}
			else {
				//printf("DYLD_INSERT_LIBRARIES already exists, replacing...\n");
				// DYLD_INSERT_LIBRARIES already exists, append systemwide.dylib to existing one
				char *const existingEnv = ogEnv[existingLibraryInsertIndex];
				//printf("Existing env variable: %s\n", existingEnv);

				free(newEnv[existingLibraryInsertIndex]);
				const char *hookDylibInsert = HOOK_DYLIB_PATH ":";
				size_t hookDylibInsertLen = strlen(hookDylibInsert);
				char *newInsertVar = malloc(strlen(existingEnv) + hookDylibInsertLen + 1);

				size_t insertEnvLen = strlen(insertVarPrefix);
				char *const existingEnvPrefix = &existingEnv[strlen(insertVarPrefix)];
				size_t existingEnvPrefixLen = strlen(existingEnvPrefix);

				strncpy(&newInsertVar[0], insertVarPrefix, insertEnvLen);
				strncpy(&newInsertVar[insertEnvLen], hookDylibInsert, hookDylibInsertLen);
				strncpy(&newInsertVar[insertEnvLen+hookDylibInsertLen], &existingEnv[insertEnvLen], existingEnvPrefixLen+1);

				newEnv[existingLibraryInsertIndex] = newInsertVar;
			}

			// Call posix_spawn with new environment
			int orgReturn = pspawn_orig(pid, path, file_actions, attrp, argv, newEnv);

			// Free new environment
			for (int i = 0; i < newEnvCount; i++) {
				free(newEnv[i]);
			}
			free(newEnv);

			return orgReturn;
		}
		else {
			// Remove any existing modifications of environment
			char *replacementLibraryInsertStr = NULL;
			
			if (existingLibraryInsertIndex != -1) {
				
				// If there is an existing DYLD_INSERT_LIBRARIES variable and there is other dylibs in it, just remove systemhook
				// If there are no other dylibs in it, remove it entirely
				
				char *const existingLibraryInsertStr = ogEnv[existingLibraryInsertIndex];
				char *existingLibraryStart = strstr(existingLibraryInsertStr, HOOK_DYLIB_PATH);
				if (existingLibraryStart) {
					size_t hookDylibLen = strlen(HOOK_DYLIB_PATH);
					
					char *afterStart = &existingLibraryStart[hookDylibLen+1];
					
					char charBefore = existingLibraryStart[-1];
					char charAfter = afterStart[-1];
					
					bool hasPathBefore = charBefore == ':';
					bool hasPathAfter = charAfter == ':';
					
					if (hasPathBefore || hasPathAfter) {
						
						size_t newVarSize = (strlen(existingLibraryInsertStr)+1) - (hookDylibLen+1);
						replacementLibraryInsertStr = malloc(newVarSize);
						
						if (hasPathBefore && !hasPathAfter) {
							strncpy(&replacementLibraryInsertStr[0], existingLibraryInsertStr, existingLibraryStart-existingLibraryInsertStr-1);
							replacementLibraryInsertStr[existingLibraryStart-existingLibraryInsertStr-1] = '\0';
						}
						else {
							strncpy(&replacementLibraryInsertStr[0], existingLibraryInsertStr, existingLibraryStart-existingLibraryInsertStr);
							strncpy(&replacementLibraryInsertStr[existingLibraryStart-existingLibraryInsertStr], afterStart, strlen(afterStart));
							replacementLibraryInsertStr[existingLibraryStart-existingLibraryInsertStr+strlen(afterStart)] = '\0';
						}
					}
				}
				else {
					replacementLibraryInsertStr = strdup(existingLibraryInsertStr);
				}
			}
			
			size_t noSafeModeEnvCount = ogEnvCount - (existingSafeModeIndex != -1) - (existingMSSafeModeIndex != -1) - (replacementLibraryInsertStr == NULL);
			char **noSafeModeEnv = malloc((noSafeModeEnvCount+1) * sizeof(char *));
			int ci = 0;
			for (int i = 0; i < ogEnvCount; i++) {
				if (existingSafeModeIndex != -1) {
					if (i == existingSafeModeIndex) continue;
				}
				if (existingMSSafeModeIndex != -1) {
					if (i == existingMSSafeModeIndex) continue;
				}
				if (existingLibraryInsertIndex != -1) {
					if (i == existingLibraryInsertIndex) {
						if (replacementLibraryInsertStr) {
							noSafeModeEnv[ci++] = replacementLibraryInsertStr;
						}
						continue;
					}
				}
				noSafeModeEnv[ci++] = ogEnv[i];
			}
			int ret = pspawn_orig(pid, path, file_actions, attrp, argv, noSafeModeEnv);
			if (replacementLibraryInsertStr) {
				free(replacementLibraryInsertStr);
			}
			free(noSafeModeEnv);
			return ret;
		}
	}
}