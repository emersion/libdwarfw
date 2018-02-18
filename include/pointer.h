#include <stdint.h>
#include <stdio.h>

size_t pointer_write(long long int pointer, uint8_t enc, size_t offset,
	FILE *f);
uint8_t pointer_rela_type(uint8_t enc);
