#ifndef WRITE_H
#define WRITE_H

#include <stdint.h>
#include <stdio.h>

size_t write_u8(uint8_t b, FILE *f);
size_t write_u16(uint16_t b, FILE *f);
size_t write_u32(uint32_t b, FILE *f);

#endif
