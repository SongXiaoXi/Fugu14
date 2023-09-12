#include "../../../../../BaseBin/common/util.m"
#include "util.h"
#include "krw.h"
#include "fake_bootInfo.h"
#include "libproc.h"
#import <CoreFoundation/CoreFoundation.h>

int pmap_set_wx_allowed(uint64_t pmap_ptr, bool wx_allowed) {
#warning kernel_el is 8 on iPhone 12
	uint64_t kernel_el = bootInfo_getUInt64(@"kernel_el");;
	uint32_t el2_adjust = (kernel_el == 8) ? 8 : 0;
#warning 0x10A need to be verified
	return kwrite8_ppl(pmap_ptr + 0x102 + el2_adjust, wx_allowed);
}

int pmap_set_cs_enforced(uint64_t pmap_ptr, bool cs_enforced) {
#warning kernel_el is 8 on iPhone 12
	uint64_t kernel_el = bootInfo_getUInt64(@"kernel_el");;
	uint32_t el2_adjust = (kernel_el == 8) ? 8 : 0;
#warning 0x109 need to be verified
	return kwrite8_ppl(pmap_ptr + 0x101 + el2_adjust, cs_enforced);
}

int64_t proc_get_task(uint64_t proc_ptr) {
	return kread_ptr(proc_ptr + 0x10);
}

pid_t proc_get_pid(uint64_t proc_ptr) {
	return kread32(proc_ptr + 0x68);
}

uint64_t proc_get_ucred(uint64_t proc_ptr) {
	return kread_ptr(proc_ptr + 0xf0);
}

void proc_set_svgid(uint64_t proc_ptr, uid_t svgid) {
	#warning offset need to be verified
	kwrite32(proc_ptr + 0x40, svgid);
}

void proc_set_svuid(uint64_t proc_ptr, uid_t svuid) {
#warning  offset need to be verified.
	kwrite32(proc_ptr + 0x3c, svuid); 
}

int ucred_set_svuid(uint64_t ucred_ptr, uint32_t svuid) {
	#warning offset need to be verified
	uint64_t cr_posix_ptr = ucred_ptr + 0x18;
	return kwrite32(cr_posix_ptr + 0x8, svuid);
}

int ucred_set_svgid(uint64_t ucred_ptr, uint32_t svgid) {
	#warning offset need to be verified
	uint64_t cr_posix_ptr = ucred_ptr + 0x18;
	return kwrite32(cr_posix_ptr + 0x54, svgid);
}

int ucred_set_uid(uint64_t ucred_ptr, uint32_t uid) {
	#warning offset need to be verified
	uint64_t cr_posix_ptr = ucred_ptr + 0x18;
	return kwrite32(cr_posix_ptr + 0x0, uid);
}

uint32_t ucred_get_cr_groups(uint64_t ucred_ptr) {
	#warning offset need to be verified
	uint64_t cr_posix_ptr = ucred_ptr + 0x18;
	return kread32(cr_posix_ptr + 0x10);
}

int ucred_set_cr_groups(uint64_t ucred_ptr, uint32_t cr_groups) {
	#warning offset need to be verified
	uint64_t cr_posix_ptr = ucred_ptr + 0x18;
	return kwrite32(cr_posix_ptr + 0x10, cr_groups);
}

uint32_t proc_get_p_flag(uint64_t proc_ptr) {
	#warning offset need to be verified
	return kread32(proc_ptr + 0x144);
}

void proc_set_p_flag(uint64_t proc_ptr, uint32_t p_flag) {
	#warning offset need to be verified
	kwrite32(proc_ptr + 0x144, p_flag);
}

#define P_SUGID 0x00000100

void proc_iterate(void (^itBlock)(uint64_t, BOOL*)) {
	uint64_t allproc = bootInfo_getSlidUInt64(@"allproc");
	uint64_t proc = allproc;
	while((proc = kread_ptr(proc)))
	{
		BOOL stop = NO;
		itBlock(proc, &stop);
		if(stop == 1) return;
	}
}

uint64_t proc_for_pid_unsafe(pid_t pidToFind) {
    __block uint64_t foundProc = 0;

    proc_iterate(^(uint64_t proc, BOOL* stop) {
        pid_t pid = proc_get_pid(proc);
        if(pid == pidToFind) {
            foundProc = proc;
            *stop = YES;
        }
    });

    return foundProc;
}

uint64_t self_proc(void) {
	static uint64_t gSelfProc = 0;
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		bool needsRelease = false;
		gSelfProc = proc_for_pid_unsafe(getpid());
	});
	return gSelfProc;
}

uint64_t self_task(void) {
	static uint64_t gSelfTask = 0;
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		uint64_t _self_proc = self_proc();
		gSelfTask = proc_get_task(self_proc());
	});
	return gSelfTask;
}

uint64_t proc_for_pid(pid_t pidToFind) {
    if (pidToFind == getpid()) {
		return self_proc();
	}
    static uint64_t task_offset_itk_space;
	static uint64_t port_offset_kobject;
	static dispatch_once_t once;
	dispatch_once(&once, ^{
		task_offset_itk_space = bootInfo_getUInt64(@"ITK_SPACE");
		port_offset_kobject = bootInfo_getUInt64(@"PORT_KOBJECT");
	});

    mach_port_t port = MACH_PORT_NULL;
	kern_return_t kr = task_for_pid(mach_task_self(), pidToFind, &port);
	if (kr != KERN_SUCCESS || port == MACH_PORT_NULL) {
		if (port != MACH_PORT_NULL) {
			mach_port_deallocate(mach_task_self(), port);
		}
		return proc_for_pid_unsafe(pidToFind);
	}

	uint64_t task_addr = self_task();
	uint64_t proc_addr = self_proc();

	static uint64_t gTaskBsdInfo = 0;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		uint64_t proc;
		uint64_t offset = 0;
		while (true) {
			proc = kread_ptr(task_addr + offset);
			if (proc == proc_addr) {
				gTaskBsdInfo = offset;
				break;
			}
			offset += 8;
		}
	});

	uint64_t task = get_port_kobject(port);
	uint64_t proc = kread_ptr(task + gTaskBsdInfo);
	mach_port_deallocate(mach_task_self(), port);
	return proc;
}

uint64_t task_get_vm_map(uint64_t task_ptr) {
	return kread_ptr(task_ptr + bootInfo_getUInt64(@"TASK_VM_MAP"));
}

uint64_t vm_map_get_pmap(uint64_t vm_map_ptr) {
	return kread_ptr(vm_map_ptr + bootInfo_getUInt64(@"VM_MAP_PMAP"));
}

NSString *proc_get_path(pid_t pid) {
	char pathbuf[4*MAXPATHLEN];
	int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
	if (ret <= 0) return nil;
	return [[[NSString stringWithUTF8String:pathbuf] stringByResolvingSymlinksInPath] stringByStandardizingPath];
}

int proc_set_debugged(pid_t pid) {
	if (pid > 0) {
		//bool proc_needs_release = false;
		uint64_t proc = proc_for_pid(pid);
		if (proc != 0) {
			
			uint64_t task = proc_get_task(proc);
			uint64_t vm_map = task_get_vm_map(task);
			uint64_t pmap = vm_map_get_pmap(vm_map);

			return pmap_set_wx_allowed(pmap, true);
		}
		return 1;
	}
	return 2;
}

uint64_t vm_map_find_entry(uint64_t vm_map_ptr, uint64_t map_start)
{
	uint64_t header = vm_map_ptr + 0x10;
	uint64_t link = header + 0x0;
	uint64_t entry = kread_ptr(link + 0x8);
	int numentry = kread32(header + 0x20);

	while(entry != 0 && numentry > 0) {
		link = entry + 0x0;
		uint64_t start = kread64(link + 0x10);

		if (start == map_start) return entry;

		entry = kread_ptr(link + 0x8);
		numentry--;
	}

	return 0;
}

#define FLAGS_PROT_SHIFT    7
#define FLAGS_MAXPROT_SHIFT 11
//#define FLAGS_PROT_MASK     0xF << FLAGS_PROT_SHIFT
//#define FLAGS_MAXPROT_MASK  0xF << FLAGS_MAXPROT_SHIFT
#define FLAGS_PROT_MASK    0x780
#define FLAGS_MAXPROT_MASK 0x7800

void vm_map_entry_set_prot(uint64_t entry_ptr, vm_prot_t prot, vm_prot_t max_prot) {
	uint64_t flags = kread64(entry_ptr + 0x48);
	uint64_t new_flags = flags;
	new_flags = (new_flags & ~FLAGS_PROT_MASK) | ((uint64_t)prot << FLAGS_PROT_SHIFT);
	new_flags = (new_flags & ~FLAGS_MAXPROT_MASK) | ((uint64_t)max_prot << FLAGS_MAXPROT_SHIFT);
	if (new_flags != flags) {
		kwrite64(entry_ptr + 0x48, new_flags);
	}
}

extern kern_return_t mach_vm_region_recurse(vm_map_read_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, natural_t *nesting_depth, vm_region_recurse_info_t info, mach_msg_type_number_t *infoCnt);

int64_t apply_fork_fixup(pid_t parentPid, pid_t childPid, bool mightHaveDirtyPages)
{
	int retval = 3;
	// very basic check to make sure this is actually a fork flow
	if (proc_get_ppid(childPid) == parentPid) {
		proc_set_debugged(childPid);
		if (!mightHaveDirtyPages) {
			retval = 0;
		} else {
			uint64_t child_proc = proc_for_pid(childPid);
			uint64_t child_task = proc_get_task(child_proc);
			uint64_t child_vm_map = task_get_vm_map(child_task);

			retval = 2;
			task_t parentTaskPort = -1;
			task_t childTaskPort = -1;
			kern_return_t parentKR = task_for_pid(mach_task_self(), parentPid, &parentTaskPort);
			if (parentKR == KERN_SUCCESS) {
				kern_return_t childKR = task_for_pid(mach_task_self(), childPid, &childTaskPort);
				if (childKR == KERN_SUCCESS) {
					retval = 0;
					mach_vm_address_t start_p = 0x0;
					mach_vm_address_t start_c = 0x0;
					int depth = 64;
					while (1) {
						mach_vm_address_t address_p = start_p;
						mach_vm_size_t size_p = 0;
						uint32_t depth0_p = depth;
						vm_region_submap_info_data_64_t info_p;
						mach_msg_type_number_t count_p = VM_REGION_SUBMAP_INFO_COUNT_64;
						kern_return_t kr_p = mach_vm_region_recurse(parentTaskPort, &address_p, &size_p, &depth0_p, (vm_region_recurse_info_t)&info_p, &count_p);

						mach_vm_address_t address_c = start_c;
						mach_vm_size_t size_c = 0;
						uint32_t depth0_c = depth;
						vm_region_submap_info_data_64_t info_c;
						mach_msg_type_number_t count_c = VM_REGION_SUBMAP_INFO_COUNT_64;
						kern_return_t kr_c = mach_vm_region_recurse(childTaskPort, &address_c, &size_c, &depth0_c, (vm_region_recurse_info_t)&info_c, &count_c);

						if (kr_p != KERN_SUCCESS || kr_c != KERN_SUCCESS) {
							break;
						}

						if (address_p < address_c) {
							start_p = address_p + size_p;
							continue;
						}
						else if (address_p > address_c) {
							start_c = address_c + size_c;
							continue;
						}
						else if (info_p.protection != info_c.protection || info_p.max_protection != info_c.max_protection) {
							uint64_t kchildEntry = vm_map_find_entry(child_vm_map, address_c);
							if (kchildEntry) {
								vm_map_entry_set_prot(kchildEntry, info_p.protection, info_p.max_protection);
							}
						}

						start_p = address_p + size_p;
						start_c = address_c + size_c;
					}
					mach_port_deallocate(mach_task_self(), childTaskPort);
				}
				mach_port_deallocate(mach_task_self(), parentTaskPort);
			}
		}
	}

	return retval;
}

char *sandbox_extension_issue_mach(const char *extension_class, const char *name, uint32_t flags);
char *sandbox_extension_issue_file(const char *extension_class, const char *name, uint32_t flags);

void generate_unsandbox_token_to_fakelib(void) {
	FILE *f = fopen("/var/jb/basebin/.fakelib/unsandbox.txt", "wb+");
	if (f == NULL) {
		return;
	}
	char *extension = sandbox_extension_issue_mach("com.apple.security.exception.mach-lookup.global-name", "com.sxx.jailbreakd", 0);
	if (extension != NULL) {
		fprintf(f, "%s\n", extension);
		free(extension);
	}
	extension = sandbox_extension_issue_mach("com.apple.app-sandbox.mach", "com.sxx.jailbreakd", 0);
	if (extension != NULL) {
		fprintf(f, "%s\n", extension);
		free(extension);
	}
	extension = sandbox_extension_issue_file("com.apple.app-sandbox.read", "/var/jb", 0);
	if (extension != NULL) {
		fprintf(f, "%s\n", extension);
		free(extension);
	}
	extension = sandbox_extension_issue_file("com.apple.sandbox.executable", "/var/jb", 0);
	if (extension != NULL) {
		fprintf(f, "%s\n", extension);
		free(extension);
	}
	fclose(f);
}

int64_t proc_fix_setuid(pid_t pid) {
	NSString *procPath = proc_get_path(pid);
	struct stat sb;
	if(stat(procPath.fileSystemRepresentation, &sb) == 0) {
		if (S_ISREG(sb.st_mode) && (sb.st_mode & (S_ISUID | S_ISGID))) {
			uint64_t proc = proc_for_pid(pid);
			uint64_t ucred = proc_get_ucred(proc);
			if ((sb.st_mode & (S_ISUID))) {
				proc_set_svuid(proc, sb.st_uid);
				ucred_set_svuid(ucred, sb.st_uid);
				ucred_set_uid(ucred, sb.st_uid);
			}
			if ((sb.st_mode & (S_ISGID))) {
				proc_set_svgid(proc, sb.st_gid);
				ucred_set_svgid(ucred, sb.st_gid);
				ucred_set_cr_groups(ucred, sb.st_gid);
			}
			uint32_t p_flag = proc_get_p_flag(proc);
			if ((p_flag & P_SUGID) != 0) {
				p_flag &= ~P_SUGID;
				proc_set_p_flag(proc, p_flag);
			}
			return 0;
		}
		else {
			return 10;
		}
	}
	else {
		return 5;
	}
}

#include "mntopts.h"
#include <sys/mount.h>
#include <unistd.h>

static NSArray *writableFileAttributes(void) {
	static NSArray *attributes = nil;
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		attributes = @[NSFileBusy, NSFileCreationDate, NSFileExtensionHidden, NSFileGroupOwnerAccountID, NSFileGroupOwnerAccountName, NSFileHFSCreatorCode, NSFileHFSTypeCode, NSFileImmutable, NSFileModificationDate, NSFileOwnerAccountID, NSFileOwnerAccountName, NSFilePosixPermissions];
	});
	return attributes;
}

static NSDictionary *writableAttributes(NSDictionary *attributes) {
	NSArray *writableAttributes = writableFileAttributes();
	NSMutableDictionary *newDict = [NSMutableDictionary new];

	[attributes enumerateKeysAndObjectsUsingBlock:^(NSString *attributeKey, NSObject *attribute, BOOL *stop) {
		if([writableAttributes containsObject:attributeKey]) {
			newDict[attributeKey] = attribute;
		}
	}];

	return newDict.copy;
}

static bool fileExistsOrSymlink(NSString *path, BOOL *isDirectory) {
	if ([[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:isDirectory]) return YES;
	if ([[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil]) return YES;
	return NO;
}

static int carbonCopySingle(NSString *sourcePath, NSString *targetPath) {
	BOOL isDirectory = NO;
	BOOL exists = fileExistsOrSymlink(sourcePath, &isDirectory);
	if (!exists) {
		return 1;
	}

	if (fileExistsOrSymlink(targetPath, nil)) {
		[[NSFileManager defaultManager] removeItemAtPath:targetPath error:nil];
	}

	NSDictionary* attributes = writableAttributes([[NSFileManager defaultManager] attributesOfItemAtPath:sourcePath error:nil]);
	if (isDirectory) {
		return [[NSFileManager defaultManager] createDirectoryAtPath:targetPath withIntermediateDirectories:NO attributes:attributes error:nil] != YES;
	}
	else {
		if ([[NSFileManager defaultManager] copyItemAtPath:sourcePath toPath:targetPath error:nil]) {
			[[NSFileManager defaultManager] setAttributes:attributes ofItemAtPath:targetPath error:nil];
			return 0;
		}
		return 1;
	}
}

int carbonCopy(NSString *sourcePath, NSString *targetPath) {
	//setJetsamEnabled(NO);
	int retval = 0;
	BOOL isDirectory = NO;
	BOOL exists = fileExistsOrSymlink(sourcePath, &isDirectory);
	if (exists) {
		if (isDirectory) {
			retval = carbonCopySingle(sourcePath, targetPath);
			if (retval == 0) {
				NSDirectoryEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtPath:sourcePath];
				for (NSString *relativePath in enumerator) {
					@autoreleasepool {
						NSString *subSourcePath = [sourcePath stringByAppendingPathComponent:relativePath];
						NSString *subTargetPath = [targetPath stringByAppendingPathComponent:relativePath];
						retval = carbonCopySingle(subSourcePath, subTargetPath);
						if (retval != 0) break;
					}
				}
			}
			
		}
		else {
			retval = carbonCopySingle(sourcePath, targetPath);
		}
	}
	else {
		retval = 1;
	}
	//setJetsamEnabled(YES);
	return retval;
}


static int setFakeLibVisible(bool visible) {
	bool isCurrentlyVisible = [[NSFileManager defaultManager] fileExistsAtPath:prebootPath(@"basebin/.fakelib/systemhook.dylib")];
	if (isCurrentlyVisible != visible) {
		NSString *stockDyldPath = prebootPath(@"basebin/.dyld");
		NSString *patchedDyldPath = prebootPath(@"basebin/.dyld_patched");
		NSString *dyldFakeLibPath = prebootPath(@"basebin/.fakelib/dyld");

		NSString *systemhookPath = prebootPath(@"basebin/systemhook.dylib");
		NSString *systemhookFakeLibPath = prebootPath(@"basebin/.fakelib/systemhook.dylib");
		NSString *sandboxFakeLibPath = prebootPath(@"basebin/.fakelib/sandbox.plist");

		if (visible) {
			if (![[NSFileManager defaultManager] copyItemAtPath:systemhookPath toPath:systemhookFakeLibPath error:nil]) return 10;
			if (carbonCopy(patchedDyldPath, dyldFakeLibPath) != 0) return 11;
			//generateSystemWideSandboxExtensions(sandboxFakeLibPath);
			//JBLogDebug("Made fakelib visible");
		} else {
			if (![[NSFileManager defaultManager] removeItemAtPath:systemhookFakeLibPath error:nil]) return 12;
			if (carbonCopy(stockDyldPath, dyldFakeLibPath) != 0) return 13;
			if (![[NSFileManager defaultManager] removeItemAtPath:sandboxFakeLibPath error:nil]) return 14;
			//JBLogDebug("Made fakelib not visible");
		}
	}
	return 0;
}

#include "trustcache.h"

int makeFakeLib(void) {
	NSString *libPath = @"/usr/lib";
	NSString *fakeLibPath = prebootPath(@"basebin/.fakelib");
	NSString *dyldBackupPath = prebootPath(@"basebin/.dyld");
	NSString *dyldToPatch = prebootPath(@"basebin/.dyld_patched");

	if (carbonCopy(libPath, fakeLibPath) != 0) return 1;
	//JBLogDebug("copied %s to %s", libPath.UTF8String, fakeLibPath.UTF8String);

	if (carbonCopy(@"/usr/lib/dyld", dyldToPatch) != 0) return 2;
	//JBLogDebug("created patched dyld at %s", dyldToPatch.UTF8String);

	if (carbonCopy(@"/usr/lib/dyld", dyldBackupPath) != 0) return 3;
	//JBLogDebug("created stock dyld backup at %s", dyldBackupPath.UTF8String);

	int dyldRet = applyDyldPatches(dyldToPatch);
	if (dyldRet != 0) return dyldRet;
	//JBLogDebug("patched dyld at %s", dyldToPatch);

	NSData *dyldCDHash;
	int ret = evaluateSignature([NSURL fileURLWithPath:dyldToPatch], &dyldCDHash, nil);
	if (!dyldCDHash) {
		NSLog(@"evaluateSignature: %d", ret);
		return 4;
	}
	JBLogDebug("got dyld cd hash %s", dyldCDHash.description.UTF8String);

	size_t dyldTCSize = 0;
	uint64_t dyldTCKaddr = staticTrustCacheUploadCDHashesFromArray(@[dyldCDHash], &dyldTCSize);
	if(dyldTCSize == 0 || dyldTCKaddr == 0) return 5;
	bootInfo_setObject(@"dyld_trustcache_kaddr", @(dyldTCKaddr));
	bootInfo_setObject(@"dyld_trustcache_size", @(dyldTCSize));
	//JBLogDebug("dyld trust cache inserted, allocated at %llX (size: %zX)", dyldTCKaddr, dyldTCSize);

	return setFakeLibVisible(true);
}

bool isFakeLibBindMountActive(void) {
	struct statfs fs;
	int sfsret = statfs("/usr/lib", &fs);
	if (sfsret == 0) {
		return !strcmp(fs.f_mntonname, "/usr/lib");
	}
	return NO;
}

void run_unsandboxed(void (^block)(void)) {
	extern void fugu14_give_kernel_creds(void);
	extern void fugu14_restore_creds(void);
	fugu14_give_kernel_creds();
	block();
	fugu14_restore_creds();
}

int setFakeLibBindMountActive(bool active) {
	__block int ret = -1;
	bool alreadyActive = isFakeLibBindMountActive();
	if (active != alreadyActive) {
		if (active) {
			run_unsandboxed(^{
				ret = mount("bindfs", "/usr/lib", MNT_RDONLY, (void*)prebootPath(@"basebin/.fakelib").fileSystemRepresentation);
			});
		}
		else {
			run_unsandboxed(^{
				ret = unmount("/usr/lib", 0);
			});
		}
	}
	return ret;
}

struct proc_bsdinfo {
 	uint32_t                pbi_flags;              /* 64bit; emulated etc */
 	uint32_t                pbi_status;
 	uint32_t                pbi_xstatus;
 	uint32_t                pbi_pid;
 	uint32_t                pbi_ppid;
 	uid_t                   pbi_uid;
 	gid_t                   pbi_gid;
 	uid_t                   pbi_ruid;
 	gid_t                   pbi_rgid;
 	uid_t                   pbi_svuid;
 	gid_t                   pbi_svgid;
 	uint32_t                rfu_1;                  /* reserved */
 	char                    pbi_comm[MAXCOMLEN];
 	char                    pbi_name[2 * MAXCOMLEN];  /* empty if no name is registered */
 	uint32_t                pbi_nfiles;
 	uint32_t                pbi_pgid;
 	uint32_t                pbi_pjobc;
 	uint32_t                e_tdev;                 /* controlling tty dev */
 	uint32_t                e_tpgid;                /* tty process group id */
 	int32_t                 pbi_nice;
 	uint64_t                pbi_start_tvsec;
 	uint64_t                pbi_start_tvusec;
 };

 #define PROC_PIDTBSDINFO                3
 #define PROC_PIDTBSDINFO_SIZE           (sizeof(struct proc_bsdinfo))

pid_t proc_get_ppid(pid_t pid) {
 	struct proc_bsdinfo procInfo;
 	if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) <= 0) {
        return -1;
    }
 	return procInfo.pbi_ppid;
}