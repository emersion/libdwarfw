#include <dwarf.h>
#include <dwarfw.h>
#include "leb128.h"
#include "write.h"

size_t dwarfw_op_write_deref(FILE *f) {
	return write_u8(DW_OP_deref, f);
}

size_t dwarfw_op_write_bregx(uint64_t reg, long long int offset, FILE *f) {
	size_t n, written = 0;

	if (reg < 32) {
		if (!(n = write_u8(DW_OP_breg0 + reg, f))) {
			return 0;
		}
		written += n;
	} else {
		if (!(n = leb128_write_u64(reg, f, 0))) {
			return 0;
		}
		written += n;
	}

	if (!(n = leb128_write_s64(offset, f, 0))) {
		return 0;
	}
	written += n;

	return written;
}
