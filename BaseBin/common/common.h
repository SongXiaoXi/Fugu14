#ifndef __COMMON_H__
#define __COMMON_H__

#include <spawn.h>
#include <stdbool.h>

#define JAILBREAKD_CMD_FORK_FIX 		  "FORKFIX"
#define JAILBREAKD_CMD_TRUSTCACHE_INJECT  "TCINJECT"
#define JAILBREAKD_CMD_SETUID			  "SETUID"
#define JAILBREAKD_CMD_DEBUG_ME			  "DEBUG_ME"
#define JAILBREAKD_CMD_START_JAILBREAK	  "START_JB"

int spawn_hook_common(pid_t *restrict pid, const char *restrict path,
					   const posix_spawn_file_actions_t *restrict file_actions,
					   const posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict],
					   void *pspawn_org);

bool stringEndsWith(const char* str, const char* suffix);

int64_t jbdswProcessLibrary(const char *filePath);

int resolvePath(const char *file, const char *searchPath, int (^attemptHandler)(char *path));

int64_t jbdswFixSetuid(void);
int64_t jbdswDebugMe(void);

#endif // __COMMON_H__