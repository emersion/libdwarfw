#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <stdio.h>
#include <dwarf.h>
#include <dwarfw.h>

#define ADDRESS_SIZE 4

char *encode_instructions(size_t *len) {
	char *buf;
	FILE *f = open_memstream(&buf, len);
	if (f == NULL) {
		return NULL;
	}

	dwarfw_cfa_write_def_cfa(7, 8, f);
	dwarfw_cfa_write_offset(16, 1, f);

	fclose(f);

	return buf;
}

int main(int argc, char **argv) {
	FILE *f = stdout;

	size_t instr_len;
	char *instr = encode_instructions(&instr_len);
	if (instr == NULL) {
		return 1;
	}

	struct dwarfw_cie cie = {
		.version = 1,
		.augmentation = "zR",
		.code_alignment = 1,
		.data_alignment = -8,
		.return_address_register = 16,
		.augmentation_data = { .pointer_encoding = 0x1B },
		.instructions_length = instr_len,
		.instructions = instr,
	};

	dwarfw_cie_write(&cie, ADDRESS_SIZE, f);

	free(instr);

	return 0;
}
