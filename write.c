#include "write.h"

size_t write_u8(uint8_t b, FILE *f) {
	return fwrite(&b, 1, sizeof(b), f);
}

size_t write_u16(uint16_t b, FILE *f) {
	return fwrite(&b, 1, sizeof(b), f);
}

size_t write_u32(uint32_t b, FILE *f) {
	return fwrite(&b, 1, sizeof(b), f);
}
