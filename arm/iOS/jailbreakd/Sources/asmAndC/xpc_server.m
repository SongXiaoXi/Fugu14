#include "../../xpc/xpc.h"
#include "../../xpc/private.h"
#include <server.h>
#include <dlfcn.h>
#include <assert.h>
#import <Foundation/Foundation.h>
#include "macho.h"
#include "util.h"
#import <mach/mach.h>
#include "trustcache.h"
#include "../../../../../BaseBin/common/common.h"

kern_return_t bootstrap_register(mach_port_t bootstrap_port, const char *      service_name, mach_port_t service_port);
void xpc_dictionary_get_audit_token(xpc_object_t xdict, audit_token_t *token);
uid_t audit_token_to_euid(audit_token_t);
uid_t audit_token_to_pid(audit_token_t);

static void *libxpc_handler = NULL;

const char _com_sxx_jailbreakd;

static void
XPCInit(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        libxpc_handler = dlopen("/usr/lib/system/libxpc.dylib", RTLD_LAZY);
        assert(libxpc_handler != NULL);
    });
}

static void *
_FindSymbol(const char *lib, const char *symbol) {
    if (CRJUSymbolicationInit()) {
        return CRJUFindSymbol(lib, symbol);
    } else {
        return NULL;
    }
}

static xpc_endpoint_t
_xpc_endpoint_create(mach_port_t port) {
    static xpc_endpoint_t (*__xpc_endpoint_create)(mach_port_t) = NULL;
    XPCInit();
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        __xpc_endpoint_create = _FindSymbol("libxpc.dylib", "__xpc_endpoint_create");
    });
    return __xpc_endpoint_create(port);
}


static mach_port_t
_xpc_connection_copy_listener_port(xpc_connection_t point) {
    static mach_port_t (*__xpc_connection_copy_listener_port)(xpc_endpoint_t) = NULL;
    XPCInit();
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        __xpc_connection_copy_listener_port = _FindSymbol("libxpc.dylib", "__xpc_connection_copy_listener_port");
    });
    if (__xpc_connection_copy_listener_port == NULL) {
        
        return MACH_PORT_NULL;
    }
    
    return __xpc_connection_copy_listener_port(point);
}

int processBinary(const char *path) {
    if (path == NULL) return 0;
    int ret = 0;

	FILE *machoFile = fopen(path, "rb");
	if (!machoFile) return 1;

	if (machoFile) {
		int fd = fileno(machoFile);

		bool isMacho = NO;
		bool isLibrary = NO;
		machoGetInfo(machoFile, &isMacho, &isLibrary);

		if (isMacho) {
			int64_t bestArchCandidate = machoFindBestArch(machoFile);
			if (bestArchCandidate >= 0) {
				uint32_t bestArch = bestArchCandidate;
				NSMutableArray *nonTrustCachedCDHashes = [NSMutableArray new];

				void (^tcCheckBlock)(NSString *) = ^(NSString *dependencyPath) {
					if (dependencyPath) {
						NSURL *dependencyURL = [NSURL fileURLWithPath:dependencyPath];
						NSData *cdHash = nil;
						BOOL isAdhocSigned = NO;
						evaluateSignature(dependencyURL, &cdHash, &isAdhocSigned);
						if (isAdhocSigned) {
                            NSLog(@"inject a adhoc signature");
							if (!isCdHashInTrustCache(cdHash)) {
                                NSLog(@"add a adhoc signature to page");
								[nonTrustCachedCDHashes addObject:cdHash];
							}
						}
					}
				};
                NSString *nsPath = [[NSString alloc] initWithBytesNoCopy:(void*)path length:strlen(path) encoding:NSUTF8StringEncoding freeWhenDone: false];
				tcCheckBlock(nsPath);
				machoEnumerateDependencies(machoFile, bestArch, nsPath, tcCheckBlock);
                NSLog(@"add %ld adhoc signatures", [nonTrustCachedCDHashes count]);
				dynamicTrustCacheUploadCDHashesFromArray(nonTrustCachedCDHashes);
			}
			else {
				ret = 3;
			}
		}
		else {
			ret = 2;
		}
		fclose(machoFile);
	}
	else {
		ret = 1;
	}

	return ret;
}

static void 
jailbreakd_received_launchd_message(mach_port_t machPort) {
    @autoreleasepool {
        xpc_object_t message = nil;
        int err = xpc_pipe_receive(machPort, &message);

        if (err != 0) {
			JBLogError("xpc_pipe_receive error %d", err);
			return;
		}

		xpc_object_t reply = xpc_dictionary_create_reply(message);
		xpc_type_t messageType = xpc_get_type(message);
        xpc_object_t args;
        const char *command = NULL;
		if (messageType == XPC_TYPE_DICTIONARY) {
            xpc_object_t some_object = message;
            command = xpc_dictionary_get_string(some_object, "CMD");
            args = some_object;
            if (strcmp(command, JAILBREAKD_CMD_TRUSTCACHE_INJECT) == 0) {
                int64_t result = 0;
                const char *filePath = xpc_dictionary_get_string(args, "filePath");
                if (filePath != NULL) {
                    result = processBinary(filePath);
                }
                xpc_dictionary_set_int64(reply, "RET", result);
            } else if (strcmp(command, JAILBREAKD_CMD_FORK_FIX) == 0) {
                audit_token_t auditToken = {};
                int64_t result = 0;
                xpc_dictionary_get_audit_token(args, &auditToken);
                pid_t clientPid = audit_token_to_pid(auditToken);

                pid_t childPid = (pid_t)xpc_dictionary_get_int64(args, "childPid");
                bool mightHaveDirtyPages = xpc_dictionary_get_bool(args, "mightHaveDirtyPages");
                result = apply_fork_fixup(clientPid, childPid, mightHaveDirtyPages);
                xpc_dictionary_set_int64(reply, "RET", result);
            } else if (strcmp(command, JAILBREAKD_CMD_DEBUG_ME) == 0) {
                audit_token_t auditToken = {};
                int64_t result = 0;
                xpc_dictionary_get_audit_token(args, &auditToken);
                pid_t clientPid = audit_token_to_pid(auditToken);
                proc_set_debugged(clientPid);
                xpc_dictionary_set_int64(reply, "RET", 0);
            } else if (strcmp(command, JAILBREAKD_CMD_SETUID) == 0) {
                audit_token_t auditToken = {};
                int64_t result = 0;
                xpc_dictionary_get_audit_token(args, &auditToken);
                pid_t clientPid = audit_token_to_pid(auditToken);
                int ret = proc_fix_setuid(clientPid);
                xpc_dictionary_set_int64(reply, "RET", ret);
            }
        }
        if (reply) {
			//char *description = xpc_copy_description(reply);
			//JBLogDebug("responding to %s message %d with %s", systemwide ? "systemwide" : "", msgId, description);
			//free(description);
			err = xpc_pipe_routine_reply(reply);
			if (err != 0) {
				JBLogError("Error %d sending response", err);
			}
		}
    }
}

static void 
xpc_for_launchd(void) {
    mach_port_name_t recvPort;
    int kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &recvPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"Failed to allocate port: %d\n", kr);
        return;
    }
    kr = mach_port_insert_right(mach_task_self(), recvPort, recvPort, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        NSLog(@"mach_port_insert_right: %s\n", mach_error_string(kr));
        mach_port_deallocate(mach_task_self(), recvPort);
        return;
    }

    dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)recvPort, 0, dispatch_queue_create("com.sxx.jailbreakd.xpc_for_launchd", DISPATCH_QUEUE_SERIAL));
    dispatch_source_set_event_handler(source, ^{
        mach_port_t lMachPort = (mach_port_t)dispatch_source_get_handle(source);
        jailbreakd_received_launchd_message(lMachPort);
    });
    dispatch_resume(source);

    kern_return_t ret;
    mach_port_t bootstrapPort;
    if ((ret = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrapPort)) !=
      KERN_SUCCESS) {
        NSLog(@"jailbreakd: failed to get bootstrap port: %d\n", ret);
        return;
    }

    kr = bootstrap_register(bootstrapPort, "com.sxx.jailbreakd.xpc_for_launchd", recvPort);

    kr = host_set_special_port(mach_host_self(), 16, recvPort);
    if (kr != KERN_SUCCESS) {
        NSLog(@"Failed to host_set_special_port: %d\n", kr);
        return;
    }
}

static xpc_connection_t
CRJU_xpc_connection_create_arbitrary_mach_listener(const char *name, dispatch_queue_t targetq) {
    extern kern_return_t bootstrap_register(mach_port_t bootstrap_port, const char *      service_name, mach_port_t service_port);
    xpc_connection_t conn = xpc_connection_create(NULL, targetq);
    mach_port_name_t recvPort = _xpc_connection_copy_listener_port(conn);
    if (recvPort == MACH_PORT_NULL) {
        NSLog(@"jailbreakd: failed to copy recvPort\n");
        goto failed;
    }
    mach_port_t bootstrapPort;
    kern_return_t ret;
    if ((ret = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrapPort)) !=
      KERN_SUCCESS) {
        NSLog(@"jailbreakd: failed to get bootstrap port: %d\n", ret);
        goto failed;
    }
    ret = bootstrap_register(bootstrapPort, name, recvPort);
    
    mach_port_deallocate(mach_task_self(), bootstrapPort);
    if (ret != KERN_SUCCESS) {
        NSLog(@"jailbreakd: failed to bootstrap: %d\n", ret);
        goto failed;
    }
    return conn;
failed:
    xpc_connection_set_event_handler(conn, ^(xpc_object_t  _Nonnull object) {});
    xpc_connection_resume(conn);
    xpc_connection_cancel(conn);
    return nil;
}

int launchXPCServer() {
    static xpc_connection_t jailbreakd_server;
    jailbreakd_server = CRJU_xpc_connection_create_arbitrary_mach_listener("com.sxx.jailbreakd", NULL);
    if (jailbreakd_server == nil) {
        return -1;
    }
    extern dispatch_queue_t gTCAccessQueue;
    gTCAccessQueue = dispatch_queue_create("com.opa334.jailbreakd.tcAccessQueue", DISPATCH_QUEUE_SERIAL);
    
    xpc_connection_set_event_handler(jailbreakd_server, ^(xpc_object_t object) {
        xpc_type_t type = xpc_get_type(object);
        if (type == XPC_TYPE_CONNECTION) {
            xpc_connection_t peer = object;
            xpc_connection_set_event_handler(peer, ^(xpc_object_t some_object) {
                xpc_type_t type = xpc_get_type(some_object);
                const char *command = NULL;
                xpc_object_t args __attribute__((unused));
                xpc_object_t reply = xpc_dictionary_create_reply(some_object);
                
                if (reply == NULL) {
                    return;
                }

                if (type == XPC_TYPE_DICTIONARY) {
                    command = xpc_dictionary_get_string(some_object, "CMD");
                    args = some_object;
                } else if (type == XPC_TYPE_STRING) {
                    command = xpc_string_get_string_ptr(some_object);
                    args = NULL;
                } else if (some_object == XPC_ERROR_CONNECTION_INVALID) {
                    goto error_ret;
                } else if (some_object == XPC_ERROR_CONNECTION_INTERRUPTED) {
                    goto error_ret;
                } else if (type == XPC_TYPE_ERROR) {
                    goto error_ret;
                } else {
                    goto end_reply;
                }
                if (command == NULL) {
                    goto end_reply;
                }
                
                if (strcmp(command, "PING") == 0) {
                    xpc_dictionary_set_int64(reply, "RET", 0);
                    xpc_connection_send_message(peer, reply);
                } else if (strcmp(command, JAILBREAKD_CMD_TRUSTCACHE_INJECT) == 0) {
                    int64_t result = 0;
                    const char *filePath = xpc_dictionary_get_string(args, "filePath");
                    if (filePath != NULL) {
                        result = processBinary(filePath);
                    }
                    xpc_dictionary_set_int64(reply, "RET", result);
                    xpc_connection_send_message(peer, reply);
                } else if (strcmp(command, JAILBREAKD_CMD_FORK_FIX) == 0) {
                    audit_token_t auditToken = {};
                    int64_t result = 0;
                    xpc_dictionary_get_audit_token(args, &auditToken);
                    pid_t clientPid = audit_token_to_pid(auditToken);

                    pid_t childPid = (pid_t)xpc_dictionary_get_int64(args, "childPid");
                    bool mightHaveDirtyPages = xpc_dictionary_get_bool(args, "mightHaveDirtyPages");
                    result = apply_fork_fixup(clientPid, childPid, mightHaveDirtyPages);
                    xpc_dictionary_set_int64(reply, "RET", result);
                    xpc_connection_send_message(peer, reply);
                } else if (strcmp(command, JAILBREAKD_CMD_DEBUG_ME) == 0) {
                    audit_token_t auditToken = {};
                    int64_t result = 0;
                    xpc_dictionary_get_audit_token(args, &auditToken);
                    pid_t clientPid = audit_token_to_pid(auditToken);
                    proc_set_debugged(clientPid);
					xpc_dictionary_set_int64(reply, "RET", 0);
                    xpc_connection_send_message(peer, reply);
                } else if (strcmp(command, JAILBREAKD_CMD_SETUID) == 0) {
                    audit_token_t auditToken = {};
                    int64_t result = 0;
                    xpc_dictionary_get_audit_token(args, &auditToken);
                    pid_t clientPid = audit_token_to_pid(auditToken);
                    proc_fix_setuid(clientPid);
                    xpc_dictionary_set_int64(reply, "RET", 0);
                    xpc_connection_send_message(peer, reply);
                } else if (strcmp(command, JAILBREAKD_CMD_START_JAILBREAK) == 0) {
                    extern int runCommand(FILE *f, char *argv[]);
                    extern int runCommandWithHook(FILE *f, char *argv[]);
                    int ret = proc_set_debugged(1);
                    NSLog(@"proc_set_debugged(1) done: %d\n", ret);
                    FILE *f = fopen("/dev/null", "wb+");
                    int status = runCommand(f, (char *[]){"/var/jb/basebin/opainject", "1", "/var/jb/basebin/launchdhook.dylib", NULL});
                    NSLog(@"inject_launchd status: %d\r\n", status);
                    status = runCommand(f, (char *[]){"/.Fugu14Untether/bin/launchctl", "bootstrap", "system", "/var/jb/Library/LaunchDaemons", NULL});
                    NSLog(@"start LaunchDaemons: %d\r\n", status);
                    char **buf = malloc(4 * sizeof(char*));
                    buf[0] = "/var/jb/usr/bin/uicache";
                    buf[1] = "-u";
                    buf[2] = "/var/jb/Applications/Sileo.app";
                    
                    buf[3] = NULL;
                    status = runCommandWithHook(f, buf);
                    NSLog(@"exec: Child status: %d\r\n", status);
                    buf[1] = "-a";
                    buf[2] = NULL;
                    status = runCommandWithHook(f, buf);
                    free(buf);
                    
                    NSLog(@"exec: Child status: %d\r\n", status);

                    extern int processBinary(const char *path);
                    int result = processBinary("/var/jb/Applications/Sileo.app/Sileo");
                    NSLog(@"processBinary: %d\n", result);
                    result = makeFakeLib();
                    if (result == 0) {
                        result = setFakeLibBindMountActive(true);
                        NSLog(@"setFakeLibBindMountActive: %d\n", result);
                        if (result == 0) {
                            generate_unsandbox_token_to_fakelib();
                        }
                    }
                    NSLog(@"makeFakeLib: %d\n", result);
                    fclose(f);
                    xpc_dictionary_set_int64(reply, "RET", 0);
                    xpc_connection_send_message(peer, reply);
                } else {
                    goto end_reply;
                }
                return;
end_reply:;
                char *desc = xpc_copy_description(reply);
                xpc_connection_send_message(peer, reply);
                free(desc);
error_ret:;
            });
            xpc_connection_resume(peer);
        } else if (type == XPC_TYPE_ERROR) {
            NSLog(@"XPC server error: %s", xpc_dictionary_get_string(object, XPC_ERROR_KEY_DESCRIPTION));
        } else {
            char *desc = xpc_copy_description(object);
            NSLog(@"XPC server received unknown object: %s", desc);
            free(desc);
        }
    });

    xpc_connection_resume(jailbreakd_server); 
    xpc_for_launchd();
    return 0;
}

static mach_port_t jbdSystemWideMachPort(void) {
	mach_port_t outPort = MACH_PORT_NULL;
	kern_return_t kr = KERN_SUCCESS;

	kr = bootstrap_look_up(bootstrap_port, "com.sxx.jailbreakd", &outPort);

	if (kr != KERN_SUCCESS) return MACH_PORT_NULL;
	return outPort;
}

static xpc_object_t sendJBDMessageSystemWide(xpc_object_t xdict) {
	xpc_object_t jbd_xreply = nil;
    xpc_connection_t conn = xpc_connection_create_mach_service("com.sxx.jailbreakd", nil, 0);
    xpc_connection_set_event_handler(conn, ^(xpc_object_t  _Nonnull object) {});
    xpc_connection_set_target_queue(conn, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
    xpc_connection_resume(conn);
    jbd_xreply = xpc_connection_send_message_with_reply_sync(conn, xdict);

	return jbd_xreply;
}

bool is_jailbreakd_started(void) {
    return (jbdSystemWideMachPort() != MACH_PORT_NULL);
}

void start_jailbreak(void) {
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_string(message, "CMD", JAILBREAKD_CMD_START_JAILBREAK);
	xpc_object_t reply = sendJBDMessageSystemWide(message);
	int64_t result = -1;
	if (reply) {
		result  = xpc_dictionary_get_int64(reply, "RET");
	}
}