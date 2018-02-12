#include <stdbool.h>
#include "leb128.h"

size_t leb128_write_u64(uint64_t value, FILE *f, size_t pad_to) {
	size_t count = 0;
	do {
		uint8_t b = value & 0x7f;
		value >>= 7;
		++count;
		if (value != 0 || count < pad_to) {
			b |= 0x80; // Mark this byte to show that more bytes will follow
		}
		if (!fwrite(&b, sizeof(b), 1, f)) {
			return 0;
		}
	} while (value != 0);

	// Pad with 0x80 and emit a null byte at the end
	if (count < pad_to) {
		for (; count < pad_to - 1; ++count) {
			uint8_t b = 0x80;
			if (!fwrite(&b, sizeof(b), 1, f)) {
				return 0;
			}
		}
		uint8_t b = 0x00;
		if (!fwrite(&b, sizeof(b), 1, f)) {
			return 0;
		}
		++count;
	}

	return count;
}

size_t leb128_write_s64(int64_t value, FILE *f, size_t pad_to) {
	bool more;
	size_t count = 0;
	do {
		uint8_t b = value & 0x7f;
		// NOTE: this assumes that this signed shift is an arithmetic right shift
		value >>= 7;
		more = !((((value == 0 ) && ((b & 0x40) == 0)) ||
			((value == -1) && ((b & 0x40) != 0))));
		++count;
		if (more || count < pad_to) {
			b |= 0x80; // Mark this byte to show that more bytes will follow
		}
		if (!fwrite(&b, sizeof(b), 1, f)) {
			return 0;
		}
	} while (more);

	// Pad with 0x80 and emit a terminating byte at the end
	if (count < pad_to) {
		uint8_t pad_value = value < 0 ? 0x7f : 0x00;
		for (; count < pad_to - 1; ++count) {
			uint8_t b = pad_value | 0x80;
			if (!fwrite(&b, sizeof(b), 1, f)) {
				return 0;
			}
		}
		if (!fwrite(&pad_value, sizeof(pad_value), 1, f)) {
			return 0;
		}
		++count;
	}

	return count;
}
