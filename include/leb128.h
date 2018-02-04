#ifndef LEB128_H
#define LEB128_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

size_t leb128_write_u64(uint64_t value, FILE *f, size_t pad_to);
size_t leb128_write_s64(int64_t value, FILE *f, size_t pad_to);

#endif
