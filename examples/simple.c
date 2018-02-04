#include <stdio.h>
#include <dwarf.h>
#include <dwarfw.h>

int main(int argc, char **argv) {
	FILE *f = stdout;

	struct dwarfw_cie cie = {
		.version = 1,
		.augmentation = "zR",
		.code_alignment = 1,
		.data_alignment = -8,
		.return_address_register = 16,
		.augmentation_data = { .pointer_encoding = 0x1B },
	};

	dwarfw_cie_write(&cie, f);
	dwarfw_cfa_write_def_cfa(7, 8, f);
	dwarfw_cfa_write_offset(16, 1, f);
	dwarfw_cfa_pad(2, f);
}
