#include <dwarf.h>
#include <leb128.h>
#include <dwarfw.h>

static size_t write_u8(uint8_t b, FILE *f) {
	return fwrite(&b, 1, sizeof(b), f);
}

static size_t write_u16(uint16_t b, FILE *f) {
	return fwrite(&b, 1, sizeof(b), f);
}

static size_t write_u32(uint32_t b, FILE *f) {
	return fwrite(&b, 1, sizeof(b), f);
}


#define OPCODE_LOW_MASK 0x3F

size_t dwarfw_cfa_write_advance_loc(uint32_t offset, FILE *f) {
	size_t written = 0;
	size_t n;

	if (offset <= OPCODE_LOW_MASK) {
		if (!(n = write_u8(DW_CFA_advance_loc | offset, f))) {
			return 0;
		}
		written += n;
	} else if (offset <= 0xFF) {
		if (!(n = write_u8(DW_CFA_advance_loc1, f))) {
			return 0;
		}
		written += n;

		if (!(n = write_u8(offset, f))) {
			return 0;
		}
		written += n;
	} else if (offset <= 0xFFFF) {
		if (!(n = write_u8(DW_CFA_advance_loc2, f))) {
			return 0;
		}
		written += n;

		if (!(n = write_u16(offset, f))) {
			return 0;
		}
		written += n;
	} else {
		if (!(n = write_u8(DW_CFA_advance_loc4, f))) {
			return 0;
		}
		written += n;

		if (!(n = write_u32(offset, f))) {
			return 0;
		}
		written += n;
	}

	return written;
}

size_t dwarfw_cfa_write_offset(uint64_t reg, uint64_t offset, FILE *f) {
	size_t written = 0;
	size_t n;

	if (reg <= OPCODE_LOW_MASK) {
		if (!(n = write_u8(DW_CFA_offset | reg, f))) {
			return 0;
		}
		written += n;
	} else {
		n = write_u8(DW_CFA_offset_extended, f);
		if (n == 0) {
			return 0;
		}
		written += n;

		if (!(n = leb128_write_u64(reg, f, 0))) {
			return 0;
		}
		written += n;
	}

	if (!(n = leb128_write_u64(offset, f, 0))) {
		return 0;
	}
	written += n;

	return written;
}

size_t dwarfw_cfa_write_nop(FILE *f) {
	return write_u8(DW_CFA_nop, f);
}

size_t dwarfw_cfa_write_set_loc(uint32_t addr, FILE *f) {
	size_t written = 0;
	size_t n;

	if (!(n = write_u8(DW_CFA_set_loc, f))) {
		return 0;
	}
	written += n;

	if (!(n = fwrite(&addr, 1, sizeof(addr), f))) {
		return 0;
	}
	written += n;

	return written;
}

size_t dwarfw_cfa_write_undefined(uint64_t reg, FILE *f) {
	size_t written = 0;
	size_t n;

	if (!(n = write_u8(DW_CFA_undefined, f))) {
		return 0;
	}
	written += n;

	if (!(n = leb128_write_u64(reg, f, 0))) {
		return 0;
	}
	written += n;

	return written;
}

size_t dwarfw_cfa_write_def_cfa(uint64_t reg, uint64_t offset, FILE *f) {
	size_t written = 0;
	size_t n;

	if (!(n = write_u8(DW_CFA_def_cfa, f))) {
		return 0;
	}
	written += n;

	if (!(n = leb128_write_u64(reg, f, 0))) {
		return 0;
	}
	written += n;

	if (!(n = leb128_write_u64(offset, f, 0))) {
		return 0;
	}
	written += n;

	return written;
}

size_t dwarfw_cfa_write_def_cfa_register(uint64_t reg, FILE *f) {
	size_t written = 0;
	size_t n;

	if (!(n = write_u8(DW_CFA_def_cfa_register, f))) {
		return 0;
	}
	written += n;

	if (!(n = leb128_write_u64(reg, f, 0))) {
		return 0;
	}
	written += n;

	return written;
}

size_t dwarfw_cfa_write_def_cfa_offset(uint64_t offset, FILE *f) {
	size_t written = 0;
	size_t n;

	if (!(n = write_u8(DW_CFA_def_cfa_offset, f))) {
		return 0;
	}
	written += n;

	if (!(n = leb128_write_u64(offset, f, 0))) {
		return 0;
	}
	written += n;

	return written;
}


size_t dwarfw_cfa_pad(size_t length, FILE *f) {
	size_t written = 0;
	while (written < length) {
		size_t n = dwarfw_cfa_write_nop(f);
		if (n == 0) {
			return 0;
		}
		written += n;
	}
	return written;
}
