#include <assert.h>
#include <dwarf.h>
#include <dwarfw.h>
#include <stdbool.h>
#include "leb128.h"
#include "pointer.h"
#include "write.h"

#define OPCODE_LOW_MASK 0x3F

size_t dwarfw_cie_write_advance_loc(struct dwarfw_cie *cie, uint32_t delta,
		FILE *f) {
	size_t n, written = 0;

	assert(delta % cie->code_alignment == 0);
	delta /= cie->code_alignment;

	if (delta <= OPCODE_LOW_MASK) {
		if (!(n = write_u8(DW_CFA_advance_loc | delta, f))) {
			return 0;
		}
		written += n;
	} else if (delta <= 0xFF) {
		if (!(n = write_u8(DW_CFA_advance_loc1, f))) {
			return 0;
		}
		written += n;

		if (!(n = write_u8(delta, f))) {
			return 0;
		}
		written += n;
	} else if (delta <= 0xFFFF) {
		if (!(n = write_u8(DW_CFA_advance_loc2, f))) {
			return 0;
		}
		written += n;

		if (!(n = write_u16(delta, f))) {
			return 0;
		}
		written += n;
	} else {
		if (!(n = write_u8(DW_CFA_advance_loc4, f))) {
			return 0;
		}
		written += n;

		if (!(n = write_u32(delta, f))) {
			return 0;
		}
		written += n;
	}

	return written;
}

size_t dwarfw_cie_write_offset(struct dwarfw_cie *cie, uint64_t reg,
		long long int offset, FILE *f) {
	size_t n, written = 0;

	assert(offset % cie->data_alignment == 0);
	offset /= cie->data_alignment;

	bool sf = offset < 0;

	if (reg <= OPCODE_LOW_MASK && !sf) {
		if (!(n = write_u8(DW_CFA_offset | reg, f))) {
			return 0;
		}
		written += n;
	} else {
		uint8_t op = sf ? DW_CFA_offset_extended_sf : DW_CFA_offset_extended;
		n = write_u8(op, f);
		if (n == 0) {
			return 0;
		}
		written += n;

		if (!(n = leb128_write_u64(reg, f, 0))) {
			return 0;
		}
		written += n;
	}

	if (sf) {
		if (!(n = leb128_write_s64(offset, f, 0))) {
			return 0;
		}
		written += n;
	} else {
		if (!(n = leb128_write_u64(offset, f, 0))) {
			return 0;
		}
		written += n;
	}

	return written;
}

size_t dwarfw_cie_write_restore(struct dwarfw_cie *cie, uint64_t reg, FILE *f) {
	size_t n, written = 0;

	if (reg <= OPCODE_LOW_MASK) {
		if (!(n = write_u8(DW_CFA_restore | reg, f))) {
			return 0;
		}
		written += n;
	} else {
		if (!(n = write_u8(DW_CFA_restore_extended, f))) {
			return 0;
		}
		written += n;

		if (!(n = leb128_write_u64(reg, f, 0))) {
			return 0;
		}
		written += n;
	}

	return written;
}

size_t dwarfw_cie_write_nop(struct dwarfw_cie *cie, FILE *f) {
	return write_u8(DW_CFA_nop, f);
}

size_t dwarfw_cie_write_set_loc(struct dwarfw_cie *cie, long long int addr,
		size_t offset, FILE *f) {
	size_t n, written = 0;

	if (!(n = write_u8(DW_CFA_set_loc, f))) {
		return 0;
	}
	written += n;

	if (!(n = pointer_write(addr, cie->augmentation_data.pointer_encoding,
			offset, f))) {
		return 0;
	}
	written += n;

	return written;
}

size_t dwarfw_cie_write_undefined(struct dwarfw_cie *cie, uint64_t reg,
		FILE *f) {
	size_t n, written = 0;

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

size_t dwarfw_cie_write_same_value(struct dwarfw_cie *cie, uint64_t reg,
		FILE *f) {
	size_t n, written = 0;

	if (!(n = write_u8(DW_CFA_same_value, f))) {
		return 0;
	}
	written += n;

	if (!(n = leb128_write_u64(reg, f, 0))) {
		return 0;
	}
	written += n;

	return written;
}

size_t dwarfw_cie_write_register(struct dwarfw_cie *cie, uint64_t reg,
		uint64_t ref, FILE *f) {
	size_t n, written = 0;

	if (!(n = write_u8(DW_CFA_register, f))) {
		return 0;
	}
	written += n;

	if (!(n = leb128_write_u64(reg, f, 0))) {
		return 0;
	}
	written += n;

	if (!(n = leb128_write_u64(ref, f, 0))) {
		return 0;
	}
	written += n;

	return written;
}

size_t dwarfw_cie_write_remember_state(struct dwarfw_cie *cie, FILE *f) {
	return write_u8(DW_CFA_remember_state, f);
}

size_t dwarfw_cie_write_restore_state(struct dwarfw_cie *cie, FILE *f) {
	return write_u8(DW_CFA_restore_state, f);
}

size_t dwarfw_cie_write_def_cfa(struct dwarfw_cie *cie, uint64_t reg,
		long long int offset, FILE *f) {
	size_t n, written = 0;

	bool sf = offset < 0;

	uint8_t op = sf ? DW_CFA_def_cfa_sf : DW_CFA_def_cfa;
	if (!(n = write_u8(op, f))) {
		return 0;
	}
	written += n;

	if (!(n = leb128_write_u64(reg, f, 0))) {
		return 0;
	}
	written += n;

	if (sf) {
		assert(offset % cie->data_alignment == 0);
		offset /= cie->data_alignment;

		if (!(n = leb128_write_s64(offset, f, 0))) {
			return 0;
		}
		written += n;
	} else {
		if (!(n = leb128_write_u64(offset, f, 0))) {
			return 0;
		}
		written += n;
	}

	return written;
}

size_t dwarfw_cie_write_def_cfa_register(struct dwarfw_cie *cie, uint64_t reg,
		FILE *f) {
	size_t n, written = 0;

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

size_t dwarfw_cie_write_def_cfa_offset(struct dwarfw_cie *cie,
		long long int offset, FILE *f) {
	size_t n, written = 0;

	bool sf = offset < 0;

	uint8_t op = sf ? DW_CFA_def_cfa_offset_sf : DW_CFA_def_cfa_offset;
	if (!(n = write_u8(op, f))) {
		return 0;
	}
	written += n;

	if (sf) {
		assert(offset % cie->data_alignment == 0);
		offset /= cie->data_alignment;

		if (!(n = leb128_write_s64(offset, f, 0))) {
			return 0;
		}
		written += n;
	} else {
		if (!(n = leb128_write_u64(offset, f, 0))) {
			return 0;
		}
		written += n;
	}

	return written;
}

static size_t write_block(const char *buf, size_t buf_len, FILE *f) {
	size_t n, written = 0;

	if (!(n = leb128_write_u64(buf_len, f, 0))) {
		return 0;
	}
	written += n;

	if (!(n = fwrite(buf, 1, buf_len, f))) {
		return 0;
	}
	written += n;

	return written;
}

size_t dwarfw_cie_write_def_cfa_expression(struct dwarfw_cie *cie,
		const char *expr, size_t expr_len, FILE *f) {
	size_t n, written = 0;

	if (!(n = write_u8(DW_CFA_def_cfa_expression, f))) {
		return 0;
	}
	written += n;

	if (!(n = write_block(expr, expr_len, f))) {
		return 0;
	}
	written += n;

	return written;
}

size_t dwarfw_cie_write_expression(struct dwarfw_cie *cie,
		uint64_t reg, const char *expr, size_t expr_len, FILE *f) {
	size_t n, written = 0;

	if (!(n = write_u8(DW_CFA_expression, f))) {
		return 0;
	}
	written += n;

	if (!(n = leb128_write_u64(reg, f, 0))) {
		return 0;
	}
	written += n;

	if (!(n = write_block(expr, expr_len, f))) {
		return 0;
	}
	written += n;

	return written;
}

size_t dwarfw_cie_write_val_offset(struct dwarfw_cie *cie, uint64_t reg,
		long long int offset, FILE *f) {
	size_t n, written = 0;

	assert(offset % cie->data_alignment == 0);
	offset /= cie->data_alignment;

	bool sf = offset < 0;

	uint8_t op = sf ? DW_CFA_val_offset_sf : DW_CFA_val_offset;
	if (!(n = write_u8(op, f))) {
		return 0;
	}
	written += n;

	if (!(n = leb128_write_u64(reg, f, 0))) {
		return 0;
	}
	written += n;

	if (sf) {
		if (!(n = leb128_write_s64(offset, f, 0))) {
			return 0;
		}
		written += n;
	} else {
		if (!(n = leb128_write_u64(offset, f, 0))) {
			return 0;
		}
		written += n;
	}

	return written;
}


size_t dwarfw_cie_pad(struct dwarfw_cie *cie, size_t length, FILE *f) {
	size_t written = 0;
	while (written < length) {
		size_t n = dwarfw_cie_write_nop(cie, f);
		if (n == 0) {
			return 0;
		}
		written += n;
	}
	return written;
}
