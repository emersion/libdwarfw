#include <string.h>
#include <leb128.h>
#include <dwarfw.h>

static int dwarfw_cfi_header_write(size_t length, uint32_t cie, FILE* f) {
	// TODO: extended length
	uint32_t len = length;
	if (!fwrite(&len, sizeof(len), 1, f)) {
		return 1;
	}
	if (!fwrite(&cie, sizeof(cie), 1, f)) {
		return 1;
	}
	return 0;
}

int dwarfw_cie_write(struct dwarfw_cie *cie, FILE* f) {
	// TODO: precompute length
	// CIE pointer is always zero for CIEs
	if (dwarfw_cfi_header_write(0x14, 0, f)) {
		return 1;
	}
	if (!fwrite(&cie->version, sizeof(cie->version), 1, f)) {
		return 1;
	}
	if (!fwrite(cie->augmentation, strlen(cie->augmentation) + 1, 1, f)) {
		return 1;
	}
	if (!leb128_write_u64(cie->code_alignment, f, 0)) {
		return 1;
	}
	if (!leb128_write_s64(cie->data_alignment, f, 0)) {
		return 1;
	}
	return 0;
}
