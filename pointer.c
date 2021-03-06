#include <dwarf.h>
#include <elf.h>
#include <stdbool.h>
#include "leb128.h"
#include "pointer.h"

// See https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html#DWARFEHENCODING
size_t pointer_write(long long int pointer, uint8_t enc, size_t offset,
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

uint8_t pointer_rela_type(uint8_t enc) {
	bool rel = false;
	switch (enc & 0xF0) {
	case 0:
		break; // No encoding
	case DW_EH_PE_pcrel:
	case DW_EH_PE_textrel:
	case DW_EH_PE_datarel:
	case DW_EH_PE_funcrel:
		rel = true;
		break;
	case DW_EH_PE_aligned:
		return R_X86_64_NONE; // TODO
	default:
		return R_X86_64_NONE; // Unknown encoding
	}

	// TODO: support more of these
	switch (enc & 0x0F) {
	case DW_EH_PE_udata2:
		return rel ? R_X86_64_NONE : R_X86_64_16;
	case DW_EH_PE_udata4:
		return rel ? R_X86_64_NONE : R_X86_64_32;
	case DW_EH_PE_udata8:
		return rel ? R_X86_64_NONE : R_X86_64_64;
	case DW_EH_PE_sdata2:
		return rel ? R_X86_64_PC16 : R_X86_64_NONE;
	case DW_EH_PE_sdata4:
		return rel ? R_X86_64_PC32 : R_X86_64_32S;
	case DW_EH_PE_sdata8:
		return rel ? R_X86_64_PC64 : R_X86_64_NONE;
	default:
		return R_X86_64_NONE; // Unsupported encoding
	}
}
