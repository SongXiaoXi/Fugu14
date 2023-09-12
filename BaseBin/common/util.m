#include "util.h"
#import "../../arm/shared/KernelExploit/Sources/IOKit_iOS/IOKit/IOkitLib.h"
#include "macho.h"

NSString *prebootPath(NSString *path)
{
	static NSString *sPrebootPrefix = nil;
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{
		NSMutableString* bootManifestHashStr;
		io_registry_entry_t registryEntry = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
		if (registryEntry) {
			CFDataRef bootManifestHash = (CFDataRef)IORegistryEntryCreateCFProperty(registryEntry, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
			if (bootManifestHash) {
				const UInt8* buffer = CFDataGetBytePtr(bootManifestHash);
				bootManifestHashStr = [NSMutableString stringWithCapacity:(CFDataGetLength(bootManifestHash) * 2)];
				for (CFIndex i = 0; i < CFDataGetLength(bootManifestHash); i++) {
					[bootManifestHashStr appendFormat:@"%02X", buffer[i]];
				}
				CFRelease(bootManifestHash);
			}
		}

		if (bootManifestHashStr) {
			NSString *activePrebootPath = [@"/private/preboot/" stringByAppendingPathComponent:bootManifestHashStr];
			NSArray *subItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:activePrebootPath error:nil];
			for (NSString *subItem in subItems) {
				if ([subItem hasPrefix:@"jb-"]) {
					sPrebootPrefix = [[activePrebootPath stringByAppendingPathComponent:subItem] stringByAppendingPathComponent:@"procursus"];
					break;
				}
			}
		}
		else {
			sPrebootPrefix = @"/var/jb";
		}
	});

	if (path) {
		return [sPrebootPrefix stringByAppendingPathComponent:path];
	}
	else {
		return sPrebootPrefix;
	}
}

int evaluateSignature(NSURL* fileURL, NSData **cdHashOut, BOOL *isAdhocSignedOut)
{
	if (!fileURL || (!cdHashOut && !isAdhocSignedOut)) return 1;
	if (![fileURL checkResourceIsReachableAndReturnError:nil]) return 2;

	FILE *machoFile = fopen(fileURL.fileSystemRepresentation, "rb");
	if (!machoFile) return 3;

	int ret = 0;

	BOOL isMacho = NO;
	machoGetInfo(machoFile, &isMacho, NULL);

	if (!isMacho) {
		fclose(machoFile);
		return 4;
	}

	int64_t archOffset = machoFindBestArch(machoFile);
	if (archOffset < 0) {
		fclose(machoFile);
		return 5;
	}

	uint32_t CSDataStart = 0, CSDataSize = 0;
	machoFindCSData(machoFile, archOffset, &CSDataStart, &CSDataSize);
	if (CSDataStart == 0 || CSDataSize == 0) {
		fclose(machoFile);
		return 6;
	}

	BOOL isAdhocSigned = machoCSDataIsAdHocSigned(machoFile, CSDataStart, CSDataSize);
	if (isAdhocSignedOut) {
		*isAdhocSignedOut = isAdhocSigned;
	}

	// we only care about the cd hash on stuff that's already verified to be ad hoc signed
	if (isAdhocSigned && cdHashOut) {
		*cdHashOut = machoCSDataCalculateCDHash(machoFile, CSDataStart, CSDataSize);
	}

	fclose(machoFile);
	return 0;
}

#define AMFI_IS_CD_HASH_IN_TRUST_CACHE 6

BOOL isCdHashInTrustCache(NSData *cdHash)
{
	kern_return_t kr;

	CFMutableDictionaryRef amfiServiceDict = IOServiceMatching("AppleMobileFileIntegrity");
	if(amfiServiceDict) {
		io_connect_t connect;
		io_service_t amfiService = IOServiceGetMatchingService(kIOMasterPortDefault, amfiServiceDict);
		kr = IOServiceOpen(amfiService, mach_task_self(), 0, &connect);
		if(kr != KERN_SUCCESS)
		{
			JBLogError("Failed to open amfi service %d %s", kr, mach_error_string(kr));
			return -2;
		}

		uint64_t includeLoadedTC = YES;
		kr = IOConnectCallMethod(connect, AMFI_IS_CD_HASH_IN_TRUST_CACHE, &includeLoadedTC, 1, CFDataGetBytePtr((__bridge CFDataRef)cdHash), CFDataGetLength((__bridge CFDataRef)cdHash), 0, 0, 0, 0);
		JBLogDebug("Is %s in TrustCache? %s", cdHash.description.UTF8String, kr == 0 ? "Yes" : "No");

		IOServiceClose(connect);
		return kr == 0;
	}

	return NO;
}