import asmAndC
import IOKit_iOS
import Darwin
import Foundation

public enum BootstrapError: Error {
	case custom(_: String)
}

private func run(prog: String, args: [String]) -> Int32 {
    var argv = [strdup(prog)]
    for a in args {
        argv.append(strdup(a))
    }
    
    argv.append(nil)
    
    defer { for a in argv { if a != nil { free(a) } } }
    
    typealias fType = @convention(c) () -> pid_t
    let fork = unsafeBitCast(dlsym(dlopen(nil, 0), "fork"), to: fType.self)
    let child: pid_t = fork()
    if child == 0 {
        execve(prog, &argv, environ)
        puts("Failed to exec: \(String(cString: strerror(errno)))")
        exit(-1)
    }
    var status = Int32(0)
    waitpid(child, &status, 0)
    if status != 0 {
        NSLog("subprocess \(prog) failed with status: \(status)")
    }
    return status
}

private func runWithKCreds(pe: PostExploitation, prog: String, args: [String]) -> Int32 {
    var argv = [strdup(prog)]
    for a in args {
        argv.append(strdup(a))
    }
    
    argv.append(nil)
    
    defer { for a in argv { if a != nil { free(a) } } }
    
    var spawnattr: posix_spawnattr_t?
    posix_spawnattr_init(&spawnattr)
    posix_spawnattr_setflags(&spawnattr, Int16(POSIX_SPAWN_START_SUSPENDED))
    
    var child: pid_t = 0
    let res = posix_spawn(&child, prog, nil, &spawnattr, argv, environ)
    if res != 0 {
        return res
    }
    
    usleep(10000)
    var cur = Proc.getFirstProc(pe: pe)
    while cur != nil {
        if cur.unsafelyUnwrapped.pid == child {
            Logger.print("Found child, giving creds")
            let res = (try? pe.giveKernelCreds(toProc: cur.unsafelyUnwrapped)) == nil ? false : true
            Logger.print("Status: \(res)")
            
            break
        }
        
        cur = cur.unsafelyUnwrapped.next
    }
    
    kill(child, SIGCONT)
    
    var status = Int32(0)
    waitpid(child, &status, 0)
    if status != 0 {
        NSLog("subprocess \(prog) failed with status: \(status)")
    }
    return status
}

public class Rootless {
    var bundlePath : String
    //var pe: PostExploitation

    init(bundlePath: String, pe: PostExploitation) {
        self.bundlePath = bundlePath
    //    self.pe = pe
    }

    func remountPrebootPartition(writable: Bool) -> Int32 {
        if writable {
            var statBuf = statfs()
            if statfs("/private/preboot", &statBuf) == 0 {
                if (statBuf.f_flags & UInt32(bitPattern: MNT_RDONLY)) != 0 {
                    
                } else {
                    return 0
                }
            }
            return run(prog: "/sbin/mount", args: ["-u", "-w", "/private/preboot"])
		} else {
			return run(prog: "/sbin/mount", args: ["-u", "/private/preboot"])
		}
    }

	static func wipeSymlink(atPath path: String) {
		let fileManager = FileManager.default
		do {
			let attributes = try fileManager.attributesOfItem(atPath: path)
			if let fileType = attributes[.type] as? FileAttributeType, fileType == .typeSymbolicLink {
				try fileManager.removeItem(atPath: path)
				Logger.print("Deleted symlink at \(path)")
			} else {
				//Logger.print("Wanted to delete symlink at \(path), but it is not a symlink")
			}
		} catch _ {
			//Logger.print("Wanted to delete symlink at \(path), error occured: \(error), but we ignore it")
		}
	}

    static func zstdDecompress(zstdPath: String, targetTarPath: String) -> Int32 {
        return decompress_tar_zstd(zstdPath, targetTarPath)
    }

    static func getBootManifestHash() -> String? {
		let registryEntry = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen")
		if registryEntry == MACH_PORT_NULL {
			return nil
		}
		guard let bootManifestHash = IORegistryEntryCreateCFProperty(registryEntry, "boot-manifest-hash" as CFString, kCFAllocatorDefault, 0) else {
			return nil
		}
		guard let bootManifestHashData = bootManifestHash.takeRetainedValue() as? Data else {
			return nil
		}
		return bootManifestHashData.map { String(format: "%02X", $0) }.joined()
	}

	static func generateFakeRootPath() -> String {
		let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		var result = ""
		for _ in 0..<6 {
			let randomIndex = Int(arc4random_uniform(UInt32(letters.count)))
			let randomCharacter = letters[letters.index(letters.startIndex, offsetBy: randomIndex)]
			result += String(randomCharacter)
		}
		return "/private/preboot/" + getBootManifestHash()! + "/jb-" + result
	}

	public static func locateExistingFakeRoot() -> String? {
		guard let bootManifestHash = getBootManifestHash() else {
			return nil
		}
		let ppURL = URL(fileURLWithPath: "/private/preboot/" + bootManifestHash)
		guard let candidateURLs = try? FileManager.default.contentsOfDirectory(at: ppURL , includingPropertiesForKeys: nil, options: []) else { return nil }
		for candidateURL in candidateURLs {
			if candidateURL.lastPathComponent.hasPrefix("jb-") {
				return candidateURL.path
			}
		}
		return nil
	}

    static func fileOrSymlinkExists(atPath path: String) -> Bool {
		let fileManager = FileManager.default
		if fileManager.fileExists(atPath: path) {
			return true
		}
		do {
			let attributes = try fileManager.attributesOfItem(atPath: path)
			if let fileType = attributes[.type] as? FileAttributeType, fileType == .typeSymbolicLink {
				return true
			}
		} catch _ { }

		return false
	}

    func untar(tarPath: String, target: String) -> Int32 {
		let tarBinary = bundlePath + "/tar"
		try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tarBinary)
        return runWithKCreds(pe:pe, prog:tarBinary, args: ["-xpkf", tarPath, "-C", target])
	}

	final func extractBootstrap() throws {
		let jbPath = "/var/jb"

		if self.remountPrebootPartition(writable: true) != 0 {
			throw BootstrapError.custom("Failed to remount /private/preboot partition as writable")
		}

		// Remove existing /var/jb symlink if it exists (will be recreated later)
		Self.wipeSymlink(atPath: jbPath)
		if FileManager.default.fileExists(atPath: jbPath) {
			try FileManager.default.removeItem(atPath: jbPath)
		}
		
		// Ensure fake root directory inside /private/preboot exists
		var fakeRootPath = Self.locateExistingFakeRoot()
		if fakeRootPath == nil {
			fakeRootPath = Self.generateFakeRootPath()
			try FileManager.default.createDirectory(atPath: fakeRootPath!, withIntermediateDirectories: true)
		}
		
		// Extract Procursus Bootstrap if neccessary
		var bootstrapNeedsExtract = false
		let procursusPath = fakeRootPath! + "/procursus"
		let installedPath = procursusPath + "/.installed_fugu14_rootless"
		let prereleasePath = procursusPath + "/.used_fugu14_rootless_prerelease"

		if FileManager.default.fileExists(atPath: procursusPath) {
			if !FileManager.default.fileExists(atPath: installedPath) {
				Logger.print("Wiping existing bootstrap because installed file not found")
				try FileManager.default.removeItem(atPath: procursusPath)
			}
			if FileManager.default.fileExists(atPath: prereleasePath) {
				Logger.print("Wiping existing bootstrap because pre release")
				try FileManager.default.removeItem(atPath: procursusPath)
			}
		}
		if !FileManager.default.fileExists(atPath: procursusPath) {
			try FileManager.default.createDirectory(atPath: procursusPath, withIntermediateDirectories: true)
			bootstrapNeedsExtract = true
		}
		
		// Update basebin (should be done every rejailbreak)
		let basebinTarPath = self.bundlePath + "/basebin.tar"
		let basebinPath = procursusPath + "/basebin"
		if FileManager.default.fileExists(atPath: basebinPath) {
			try FileManager.default.removeItem(atPath: basebinPath)
		}
        try FileManager.default.createDirectory(atPath: basebinPath, withIntermediateDirectories: true)
		let untarRet = untar(tarPath: basebinTarPath, target: basebinPath)
		if untarRet != 0 {
			throw BootstrapError.custom(String(format:"Failed to untar Basebin: \(String(describing: untarRet))"))
		}
        // if FileManager.default.fileExists(atPath: "/usr/lib/systemhook.dylib") {
		// 	try FileManager.default.removeItem(atPath: "/usr/lib/systemhook.dylib")
		// }
		// try FileManager.default.copyItem(atPath: procursusPath + "/basebin/systemhook.dylib", toPath: "/usr/lib/systemhook.dylib")

		// Create /var/jb symlink
		try FileManager.default.createSymbolicLink(atPath: jbPath, withDestinationPath: procursusPath)

		// Extract Procursus if needed
		if bootstrapNeedsExtract {
			let bootstrapZstdPath = self.bundlePath + "/bootstrap-iphoneos-arm64.tar.zst"
            let bootstrapTmpTarPath = "/tmp/bootstrap-iphoneos-arm64.tar"
            if FileManager.default.fileExists(atPath: bootstrapTmpTarPath) {
                try FileManager.default.removeItem(atPath: bootstrapTmpTarPath);
            }
            let zstdRet = Self.zstdDecompress(zstdPath: bootstrapZstdPath, targetTarPath: bootstrapTmpTarPath)
            if zstdRet != 0 {
                throw BootstrapError.custom(String(format:"Failed to decompress bootstrap: \(String(describing: zstdRet))"))
            }
			let untarRet = untar(tarPath: bootstrapTmpTarPath, target: "/")
            try FileManager.default.removeItem(atPath: bootstrapTmpTarPath);
			if untarRet != 0 {
				throw BootstrapError.custom(String(format:"Failed to untar bootstrap: \(String(describing: untarRet))"))
			}
			try "".write(toFile: installedPath, atomically: true, encoding: String.Encoding.utf8)
		}

		// Update default sources
		let defaultSources = """
			Types: deb
			URIs: https://repo.chariz.com/
			Suites: ./
			Components:

			Types: deb
			URIs: https://havoc.app/
			Suites: ./
			Components:

			Types: deb
			URIs: http://apt.thebigboss.org/repofiles/cydia/
			Suites: stable
			Components: main

			Types: deb
			URIs: https://ellekit.space/
			Suites: ./
			Components:
			"""
		try defaultSources.write(toFile: "/var/jb/etc/apt/sources.list.d/default.sources", atomically: false, encoding: .utf8)
/*
		// Create basebin symlinks if they don't exist
		if !Self.fileOrSymlinkExists(atPath: "/var/jb/usr/bin/opainject") {
			try FileManager.default.createSymbolicLink(atPath: "/var/jb/usr/bin/opainject", withDestinationPath: procursusPath + "/basebin/opainject")
		}
		if !Self.fileOrSymlinkExists(atPath: "/var/jb/usr/bin/jbctl") {
			try FileManager.default.createSymbolicLink(atPath: "/var/jb/usr/bin/jbctl", withDestinationPath: procursusPath + "/basebin/jbctl")
		}
		if !Self.fileOrSymlinkExists(atPath: "/var/jb/usr/lib/libjailbreak.dylib") {
			try FileManager.default.createSymbolicLink(atPath: "/var/jb/usr/lib/libjailbreak.dylib", withDestinationPath: procursusPath + "/basebin/libjailbreak.dylib")
		}
		if !Self.fileOrSymlinkExists(atPath: "/var/jb/usr/lib/libfilecom.dylib") {
			try FileManager.default.createSymbolicLink(atPath: "/var/jb/usr/lib/libfilecom.dylib", withDestinationPath: procursusPath + "/basebin/libfilecom.dylib")
		}
*/
		// Create preferences directory if it does not exist
		if !FileManager.default.fileExists(atPath: "/var/jb/var/mobile/Library/Preferences") {
			let attributes: [FileAttributeKey: Any] = [
				.posixPermissions: 0o755, 
				.ownerAccountID: 501, 
				.groupOwnerAccountID: 501
			]
			try FileManager.default.createDirectory(atPath: "/var/jb/var/mobile/Library/Preferences", withIntermediateDirectories: true, attributes: attributes)
		}
	}
}