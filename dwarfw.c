#define _POSIX_C_SOURCE 200809L
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <leb128.h>
#include <dwarf.h>
#include <dwarfw.h>

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
	size_t written = 0;
	size_t n;

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

// See https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html#DWARFEHENCODING
static size_t pointer_write(long long int pointer, uint8_t enc, size_t offset,
		FILE *f) {
	switch (enc & 0xF0) {
	case 0:
		break; // No encoding
	case DW_EH_PE_pcrel:
	case DW_EH_PE_textrel:
	case DW_EH_PE_datarel:
	case DW_EH_PE_funcrel:
		pointer -= offset;
		break;
	case DW_EH_PE_aligned:
		return 0; // TODO
	default:
		return 0; // Unknown encoding
	}

	switch (enc & 0x0F) {
	case DW_EH_PE_absptr:;
		size_t pointer_arch = pointer;
		return fwrite(&pointer_arch, 1, sizeof(pointer_arch), f);
	case DW_EH_PE_uleb128:
		return leb128_write_u64(pointer, f, 0);
	case DW_EH_PE_udata2:;
		uint16_t pointer_u16 = pointer;
		return fwrite(&pointer_u16, 1, sizeof(pointer_u16), f);
	case DW_EH_PE_udata4:;
		uint32_t pointer_u32 = pointer;
		return fwrite(&pointer_u32, 1, sizeof(pointer_u32), f);
	case DW_EH_PE_udata8:;
		uint64_t pointer_u64 = pointer;
		return fwrite(&pointer_u64, 1, sizeof(pointer_u64), f);
	case DW_EH_PE_sleb128:
		return leb128_write_s64(pointer, f, 0);
	case DW_EH_PE_sdata2:;
		int16_t pointer_s16 = pointer;
		return fwrite(&pointer_s16, 1, sizeof(pointer_s16), f);
	case DW_EH_PE_sdata4:;
		int32_t pointer_s32 = pointer;
		return fwrite(&pointer_s32, 1, sizeof(pointer_s32), f);
	case DW_EH_PE_sdata8:;
		int64_t pointer_s64 = pointer;
		return fwrite(&pointer_s64, 1, sizeof(pointer_s64), f);
	default:
		return 0; // Unknown encoding
	}
}


static size_t cie_header_write(struct dwarfw_cie *cie, FILE *f) {
	size_t written = 0;
	size_t n;

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
	size_t written = 0;
	size_t n;

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

	if (!(n = fwrite(cie->instructions, 1, cie->instructions_length, f))) {
		return 0;
	}
	written += n;

	if (!(n = dwarfw_cfa_pad(padding_length, f))) {
		return 0;
	}
	written += n;

	return written;
}


static size_t fde_header_write(struct dwarfw_fde *fde, size_t offset, FILE* f) {
	size_t written = 0;
	size_t n;

	uint8_t ptr_enc = fde->cie->augmentation_data.pointer_encoding;
	if (!(n = pointer_write(fde->initial_location, ptr_enc, offset, f))) {
		return 0;
	}
	written += n;
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

size_t dwarfw_fde_write(struct dwarfw_fde *fde, FILE* f) {
	size_t written = 0;
	size_t n;

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
	if (!fde_header_write(fde, 0, header_f)) {
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

	if (!(n = fde_header_write(fde, written, f))) {
		return 0;
	}
	written += n;

	if (!(n = fwrite(fde->instructions, 1, fde->instructions_length, f))) {
		return 0;
	}
	written += n;

	if (!(n = dwarfw_cfa_pad(padding_length, f))) {
		return 0;
	}
	written += n;

	return written;
}
