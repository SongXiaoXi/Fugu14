//
//  server.h
//  iDownload
//
//  Created by Linus Henze on 2020-02-09.
//  Copyright © 2020/2021 Linus Henze. All rights reserved.
//

#ifndef server_h
#define server_h

#include <stdbool.h>

#define VERSION       "1.2"

#define FILE_EXISTS(file) (access(file, F_OK ) != -1)

void launchCServer(void);
int launchXPCServer(void);
void update_springboard_plist(void);
int CRJUSymbolicationInit(void);
void *CRJUFindSymbol(const char *owner, const char *symbol);

int decompress_tar_zstd(const char* src_file_path, const char* dst_file_path);

void start_jailbreak(void);
bool is_jailbreakd_started(void);

void generate_unsandbox_token_to_fakelib();

#endif /* server_h */
