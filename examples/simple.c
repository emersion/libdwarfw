#define _POSIX_C_SOURCE 200809L
#include <dwarf.h>
#include <dwarfw.h>
#include <gelf.h>
#include <stdio.h>
#include <stdlib.h>

static char *encode_cie_instructions(struct dwarfw_cie *cie, size_t *len) {
	char *buf;
	FILE *f = open_memstream(&buf, len);
	if (f == NULL) {
		return NULL;
	}

	dwarfw_cie_write_def_cfa(cie, 7, 8, f);
	dwarfw_cie_write_offset(cie, 16, -8, f);

	fclose(f);

	return buf;
}

static char *encode_fde_instructions(struct dwarfw_fde *fde, size_t *len) {
	char *buf;
	FILE *f = open_memstream(&buf, len);
	if (f == NULL) {
		return NULL;
	}

	dwarfw_cie_write_advance_loc(fde->cie, 1, f);
	dwarfw_cie_write_def_cfa_offset(fde->cie, 16, f);
	dwarfw_cie_write_offset(fde->cie, 6, -16, f);
	dwarfw_cie_write_advance_loc(fde->cie, 3, f);
	dwarfw_cie_write_def_cfa_register(fde->cie, 6, f);
	dwarfw_cie_write_advance_loc(fde->cie, 13, f);
	dwarfw_cie_write_offset(fde->cie, 15, -24, f);
	dwarfw_cie_write_offset(fde->cie, 14, -32, f);
	dwarfw_cie_write_offset(fde->cie, 13, -40, f);
	dwarfw_cie_write_offset(fde->cie, 12, -48, f);
	dwarfw_cie_write_offset(fde->cie, 3, -56, f);
	dwarfw_cie_write_advance_loc(fde->cie, 288, f);
	dwarfw_cie_write_def_cfa(fde->cie, 7, 8, f);

	fclose(f);

	return buf;
}

int main(int argc, char **argv) {
	FILE *f = stdout;
	size_t n, written = 0;

	struct dwarfw_cie cie = {
		.version = 1,
		.augmentation = "zR",
		.code_alignment = 1,
		.data_alignment = -8,
		.return_address_register = 16,
		.augmentation_data = {
			.pointer_encoding = DW_EH_PE_sdata4 | DW_EH_PE_pcrel,
		},
	};

	size_t instr_len;
	char *instr = encode_cie_instructions(&cie, &instr_len);
	if (instr == NULL) {
		return 1;
	}
	cie.instructions_length = instr_len;
	cie.instructions = instr;

	if (!(n = dwarfw_cie_write(&cie, f))) {
		return 1;
	}
	written += n;
	free(instr);

	struct dwarfw_fde fde = {
		.cie = &cie,
		.cie_pointer = written,
		.initial_location = 0,
		.address_range = 0x132,
		.instructions_length = instr_len,
		.instructions = instr,
	};

	instr = encode_fde_instructions(&fde, &instr_len);
	if (instr == NULL) {
		return 1;
	}
	fde.instructions_length = instr_len;
	fde.instructions = instr;

	GElf_Rela rela;
	if (!(n = dwarfw_fde_write(&fde, &rela, f))) {
		return 1;
	}
	written += n;
	free(instr);

	return 0;
}
