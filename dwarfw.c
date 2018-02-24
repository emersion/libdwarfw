#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <dwarfw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "leb128.h"
#include "pointer.h"

#define ADDRESS_SIZE sizeof(uint32_t)

static size_t cfi_section_length_length(size_t body_length) {
	size_t length = sizeof(uint32_t);
	if (body_length >= 0xFFFFFFFF) {
		length += sizeof(uint64_t);
	}
	return length;
}

static size_t cfi_section_length(size_t body_length, size_t *padding_length) {
	// The length field is not included in the total length
	size_t header_length = sizeof(uint32_t); // CIE pointer

	size_t length = header_length + body_length;
	*padding_length = ADDRESS_SIZE - (length % ADDRESS_SIZE);

	return length + *padding_length;
}

static size_t cfi_header_write(size_t length, uint32_t cie_pointer, FILE *f) {
	size_t n, written = 0;

	if (length < 0xFFFFFFFF) {
		uint32_t length_u32 = length;
		if (!(n = fwrite(&length_u32, 1, sizeof(length_u32), f))) {
			return 0;
		}
		written += n;
	} else {
		// Extended length
		uint32_t length_u32 = 0xFFFFFFFF;
		if (!(n = fwrite(&length_u32, 1, sizeof(length_u32), f))) {
			return 0;
		}
		written += n;

		uint32_t length_u64 = length;
		if (!(n = fwrite(&length_u64, 1, sizeof(length_u64), f))) {
			return 0;
		}
		written += n;
	}

	if (!(n = fwrite(&cie_pointer, 1, sizeof(cie_pointer), f))) {
		return 0;
	}
	written += n;

	return written;
}


static size_t cie_header_write(struct dwarfw_cie *cie, FILE *f) {
	size_t n, written = 0;

	if (!(n = fwrite(&cie->version, 1, sizeof(cie->version), f))) {
		return 0;
	}
	written += n;
	if (!(n = fwrite(cie->augmentation, 1, strlen(cie->augmentation) + 1, f))) {
		return 0;
	}
	written += n;
	if (!(n = leb128_write_u64(cie->code_alignment, f, 0))) {
		return 0;
	}
	written += n;
	if (!(n = leb128_write_s64(cie->data_alignment, f, 0))) {
		return 0;
	}
	written += n;
	if (!(n = leb128_write_u64(cie->return_address_register, f, 0))) {
		return 0;
	}
	written += n;

	if (cie->augmentation[0] == 'z') {
		uint8_t augmentation_data[1];
		size_t len = 0;

		if (strchr(cie->augmentation, 'R') != NULL) {
			augmentation_data[len] = cie->augmentation_data.pointer_encoding;
			++len;
		}

		if (!(n = leb128_write_u64(len, f, 0))) {
			return 0;
		}
		written += n;
		if (!(n = fwrite(augmentation_data, 1, len, f))) {
			return 0;
		}
		written += n;
	}

	return written;
}

size_t dwarfw_cie_write(struct dwarfw_cie *cie, FILE *f) {
	size_t n, written = 0;

	// Encode header
	size_t header_len;
	char *header_buf;
	FILE *header_f = open_memstream(&header_buf, &header_len);
	if (header_f == NULL) {
		return 0;
	}
	if (!cie_header_write(cie, header_f)) {
		return 0;
	}
	fclose(header_f);

	size_t padding_length;
	size_t length = cfi_section_length(header_len + cie->instructions_length,
		&padding_length);

	// CIE pointer is always zero for CIEs
	if (!(n = cfi_header_write(length, 0, f))) {
		return 0;
	}
	written += n;

	if (!(n = fwrite(header_buf, 1, header_len, f))) {
		return 0;
	}
	free(header_buf);
	written += n;

	if (cie->instructions_length > 0) {
		if (!(n = fwrite(cie->instructions, 1, cie->instructions_length, f))) {
			return 0;
		}
		written += n;
	}

	if (!(n = dwarfw_cie_pad(cie, padding_length, f))) {
		return 0;
	}
	written += n;

	return written;
}


static size_t fde_header_write(struct dwarfw_fde *fde, size_t offset,
		GElf_Rela *rela, FILE *f) {
	size_t n, written = 0;

	uint8_t ptr_enc = fde->cie->augmentation_data.pointer_encoding;
	if (rela == NULL) {
		if (!(n = pointer_write(fde->initial_location, ptr_enc, offset, f))) {
			return 0;
		}
		written += n;
	} else {
		if (!(n = pointer_write(0, ptr_enc, 0, f))) {
			return 0;
		}
		written += n;

		rela->r_offset = offset;
		rela->r_info = GELF_R_INFO(0, pointer_rela_type(ptr_enc));
		rela->r_addend = fde->initial_location;
	}

	// Address range seems to always be a uint32_t for .eh_frame
	if (!(n = fwrite(&fde->address_range, 1, sizeof(fde->address_range), f))) {
		return 0;
	}
	written += n;

	if (fde->cie->augmentation[0] == 'z') {
		if (!(n = leb128_write_u64(0, f, 0))) {
			return 0;
		}
		written += n;
	}

	return written;
}

size_t dwarfw_fde_write(struct dwarfw_fde *fde, GElf_Rela *rela, FILE *f) {
	size_t n, written = 0;

	assert(fde->cie != NULL);
	assert(fde->cie_pointer != 0);

	// We need to know the size of the header
	// Encode header and discard it
	size_t header_len;
	char *header_buf;
	FILE *header_f = open_memstream(&header_buf, &header_len);
	if (header_f == NULL) {
		return 0;
	}
	if (!fde_header_write(fde, 0, NULL, header_f)) {
		return 0;
	}
	fclose(header_f);
	free(header_buf);

	size_t padding_length;
	size_t length = cfi_section_length(header_len + fde->instructions_length,
		&padding_length);

	// The pointer is a relative position from the start of the section
	// It needs to be encoded relative to the place it's written
	size_t cie_pointer = fde->cie_pointer + cfi_section_length_length(length);
	if (!(n = cfi_header_write(length, cie_pointer, f))) {
		return 0;
	}
	written += n;

	if (!(n = fde_header_write(fde, written, rela, f))) {
		return 0;
	}
	written += n;

	if (fde->instructions_length > 0) {
		if (!(n = fwrite(fde->instructions, 1, fde->instructions_length, f))) {
			return 0;
		}
		written += n;
	}

	if (!(n = dwarfw_cie_pad(fde->cie, padding_length, f))) {
		return 0;
	}
	written += n;

	return written;
}
