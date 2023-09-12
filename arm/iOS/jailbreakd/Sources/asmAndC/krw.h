#ifndef __JAILBREAKD_KRW_H__
#define __JAILBREAKD_KRW_H__

#include <stdint.h>

int kreadbuf(uint64_t kaddr, void* output, size_t size);
int kwritebuf(uint64_t kaddr, const void* input, size_t size);

uint64_t kread64(uint64_t va);
uint64_t kread_ptr(uint64_t va);
uint32_t kread32(uint64_t va);
uint16_t kread16(uint64_t va);
uint8_t kread8(uint64_t va);

int kwrite64(uint64_t va, uint64_t v);
int kwrite32(uint64_t va, uint32_t v);
int kwrite16(uint64_t va, uint16_t v);
int kwrite8(uint64_t va, uint8_t v);
int kwrite8_ppl(uint64_t va, uint8_t v);
int kwrite_ptr(uint64_t va, uint64_t ptr);

uint64_t kcall(uint64_t func, uint64_t argc, uint64_t *argv);
uint64_t kalloc(uint64_t size);
uint64_t kfree(uint64_t addr, uint64_t size);

#endif /* __JAILBREAKD_KRW_H__ */