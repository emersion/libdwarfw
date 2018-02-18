#define _POSIX_C_SOURCE 200809L
#include <dwarf.h>
#include <dwarfw.h>
#include <stdio.h>
#include <stdlib.h>

static char *encode_cie_instructions(size_t *len) {
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

static char *encode_fde_instructions(size_t *len) {
	char *buf;
	FILE *f = open_memstream(&buf, len);
	if (f == NULL) {
		return NULL;
	}

	dwarfw_cfa_write_advance_loc(1, f);
	dwarfw_cfa_write_def_cfa_offset(16, f);
	dwarfw_cfa_write_offset(6, 2, f);
	dwarfw_cfa_write_advance_loc(3, f);
	dwarfw_cfa_write_def_cfa_register(6, f);
	dwarfw_cfa_write_advance_loc(13, f);
	dwarfw_cfa_write_offset(15, 3, f);
	dwarfw_cfa_write_offset(14, 4, f);
	dwarfw_cfa_write_offset(13, 5, f);
	dwarfw_cfa_write_offset(12, 6, f);
	dwarfw_cfa_write_offset(3, 7, f);
	dwarfw_cfa_write_advance_loc(288, f);
	dwarfw_cfa_write_def_cfa(7, 8, f);

	fclose(f);

	return buf;
}

int main(int argc, char **argv) {
	FILE *f = stdout;
	size_t n, written = 0;

	size_t instr_len;
	char *instr = encode_cie_instructions(&instr_len);
	if (instr == NULL) {
		return 1;
	}

	struct dwarfw_cie cie = {
		.version = 1,
		.augmentation = "zR",
		.code_alignment = 1,
		.data_alignment = -8,
		.return_address_register = 16,
		.augmentation_data = {
			.pointer_encoding = DW_EH_PE_sdata4 | DW_EH_PE_pcrel,
		},
		.instructions_length = instr_len,
		.instructions = instr,
	};
	if (!(n = dwarfw_cie_write(&cie, f))) {
		return 1;
	}
	written += n;
	free(instr);

	instr = encode_fde_instructions(&instr_len);
	if (instr == NULL) {
		return 1;
	}

	struct dwarfw_fde fde = {
		.cie = &cie,
		.cie_pointer = written,
		.initial_location = 0,
		.address_range = 0x132,
		.instructions_length = instr_len,
		.instructions = instr,
	};
	if (!(n = dwarfw_fde_write(&fde, NULL, f))) {
		return 1;
	}
	written += n;
	free(instr);

	return 0;
}
