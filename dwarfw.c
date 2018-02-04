#include <string.h>
#include <leb128.h>
#include <dwarfw.h>

static int dwarfw_cfi_header_write(size_t length, uint32_t cie, FILE *f) {
	// TODO: extended length
	uint32_t length_u32 = length;
	if (!fwrite(&length_u32, sizeof(length_u32), 1, f)) {
		return 1;
	}
	if (!fwrite(&cie, sizeof(cie), 1, f)) {
		return 1;
	}
	return 0;
}

int dwarfw_cie_write(struct dwarfw_cie *cie, FILE *f) {
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
	if (!leb128_write_u64(cie->return_address_register, f, 0)) {
		return 1;
	}

	if (cie->augmentation[0] == 'z') {
		uint8_t augmentation_data[1];
		size_t len = 0;

		if (strchr(cie->augmentation, 'R') != NULL) {
			augmentation_data[len] = cie->augmentation_data.pointer_encoding;
			++len;
		}

		if (!leb128_write_u64(len, f, 0)) {
			return 1;
		}
		if (!fwrite(augmentation_data, len, 1, f)) {
			return 1;
		}
	}

	return 0;
}
