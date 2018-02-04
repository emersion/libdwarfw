#include <elf.h>
#include <dwarfw.h>

int main(int argc, char **argv) {
	struct dwarfw_cie cie = {
		.version = 1,
		.augmentation = "zR",
		.code_alignment = 1,
		.data_alignment = -8,
	};

	return dwarfw_cie_write(&cie, stdout);
}
