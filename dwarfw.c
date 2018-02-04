#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <leb128.h>
#include <dwarfw.h>

static size_t dwarfw_cfi_section_length(size_t body_length, size_t address_size,
		size_t *padding_length) {
	// The length field is not included in the total length
	size_t header_length = sizeof(uint32_t); // CIE pointer

	size_t length = header_length + body_length;
	*padding_length = address_size - (length % address_size);

	return length + *padding_length;
}

static size_t dwarfw_cfi_header_write(size_t length, uint32_t cie, FILE *f) {
	size_t written = 0;
	size_t n;

	// TODO: extended length
	uint32_t length_u32 = length;
	if (!(n = fwrite(&length_u32, sizeof(length_u32), 1, f))) {
		return 0;
	}
	written += n;

	if (!(n = fwrite(&cie, sizeof(cie), 1, f))) {
		return 0;
	}
	written += n;

	return written;
}


static size_t dwarfw_cie_header_write(struct dwarfw_cie *cie, FILE *f) {
	size_t written = 0;
	size_t n;

	if (!(n = fwrite(&cie->version, sizeof(cie->version), 1, f))) {
		return 0;
	}
	written += n;
	if (!(n = fwrite(cie->augmentation, strlen(cie->augmentation) + 1, 1, f))) {
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
		if (!(n = fwrite(augmentation_data, len, 1, f))) {
			return 0;
		}
		written += n;
	}

	return written;
}

size_t dwarfw_cie_write(struct dwarfw_cie *cie, size_t address_size, FILE *f) {
	size_t written = 0;
	size_t n;

	// Encode header
	size_t header_len;
	char *header_buf;
	FILE *header_f = open_memstream(&header_buf, &header_len);
	if (header_f == NULL) {
		return 0;
	}
	if (!dwarfw_cie_header_write(cie, header_f)) {
		return 0;
	}
	fclose(header_f);

	size_t padding_length;
	size_t length = dwarfw_cfi_section_length(
		header_len + cie->instructions_length, address_size,
		&padding_length);

	// CIE pointer is always zero for CIEs
	if (!(n = dwarfw_cfi_header_write(length, 0, f))) {
		return 0;
	}
	written += n;

	if (!(n = fwrite(header_buf, header_len, 1, f))) {
		return 0;
	}
	free(header_buf);
	written += n;

	if (!(n = fwrite(cie->instructions, cie->instructions_length, 1, f))) {
		return 0;
	}
	written += n;

	if (!(n = dwarfw_cfa_pad(padding_length, f))) {
		return 0;
	}
	written += n;

	return written;
}
