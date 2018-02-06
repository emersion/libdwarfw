#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>
#include <dwarfw.h>

// Fallback for systems without this "read and write, mmaping if possible" cmd.
#ifndef ELF_C_RDWR_MMAP
#define ELF_C_RDWR_MMAP ELF_C_RDWR
#endif

static char *encode_cie_instructions(size_t *len) {
	char *buf;
	FILE *f = open_memstream(&buf, len);
	if (f == NULL) {
		return NULL;
	}

	dwarfw_cfa_write_def_cfa(7, 8, f);
	dwarfw_cfa_write_offset(16, 1, f);

	fclose(f);

	return buf;
}

static char *encode_fde_instructions(size_t *len) {
	char *buf;
	FILE *f = open_memstream(&buf, len);
	if (f == NULL) {
		return NULL;
	}

	dwarfw_cfa_write_advance_loc(1, f);
	dwarfw_cfa_write_def_cfa_offset(16, f);
	dwarfw_cfa_write_offset(6, 2, f);
	dwarfw_cfa_write_advance_loc(3, f);
	dwarfw_cfa_write_def_cfa_register(6, f);
	dwarfw_cfa_write_advance_loc(13, f);
	dwarfw_cfa_write_offset(15, 3, f);
	dwarfw_cfa_write_offset(14, 4, f);
	dwarfw_cfa_write_offset(13, 5, f);
	dwarfw_cfa_write_offset(12, 6, f);
	dwarfw_cfa_write_offset(3, 7, f);
	dwarfw_cfa_write_advance_loc(288, f);
	dwarfw_cfa_write_def_cfa(7, 8, f);

	fclose(f);

	return buf;
}

static size_t write_eh_frame(long unsigned int text_offset, FILE *f) {
	size_t n, written = 0;

	size_t instr_len;
	char *instr = encode_cie_instructions(&instr_len);
	if (instr == NULL) {
		return 0;
	}

	struct dwarfw_cie cie = {
		.version = 1,
		.augmentation = "zR",
		.code_alignment = 1,
		.data_alignment = -8,
		.return_address_register = 16,
		.augmentation_data = { .pointer_encoding = 0x1B },
		.instructions_length = instr_len,
		.instructions = instr,
	};
	if (!(n = dwarfw_cie_write(&cie, f))) {
		return 0;
	}
	written += n;
	free(instr);

	instr = encode_fde_instructions(&instr_len);
	if (instr == NULL) {
		return 0;
	}

	struct dwarfw_fde fde = {
		.cie = &cie,
		.cie_pointer = written,
		.initial_location = text_offset - written,
		.address_range = 0x132,
		.instructions_length = instr_len,
		.instructions = instr,
	};
	if (!(n = dwarfw_fde_write(&fde, f))) {
		return 0;
	}
	written += n;
	free(instr);

	return written;
}

static Elf_Scn *find_section_by_name(Elf *e, const char *section_name) {
	size_t sections_num;
	if (elf_getshdrnum(e, &sections_num)) {
		return NULL;
	}

	size_t shstrndx;
	if (elf_getshdrstrndx(e, &shstrndx)) {
		return NULL;
	}

	for (size_t i = 0; i < sections_num; ++i) {
		Elf_Scn *s = elf_getscn(e, i);
		if (s == NULL) {
			return NULL;
		}

		GElf_Shdr sh;
		if (!gelf_getshdr(s, &sh)) {
			return NULL;
		}

		char *name = elf_strptr(e, shstrndx, sh.sh_name);
		if (name == NULL) {
			return NULL;
		}

		if (strcmp(name, section_name) == 0) {
			return s;
		}
	}

	return NULL;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "Missing ELF file argument\n");
		return 1;
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
		return 1;
	}

	// Open the ELF file
	int fd = open(argv[1], O_RDWR, 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot open file %s\n", argv[1]);
		return 1;
	}

	Elf *e = elf_begin(fd, ELF_C_RDWR_MMAP, NULL);
	if (e == NULL) {
		fprintf(stderr, "elf_begin() failed: %s\n", elf_errmsg(-1));
		return 1;
	}

	// Check the ELF object
	Elf_Kind ek = elf_kind(e);
	if (ek != ELF_K_ELF) {
		fprintf(stderr, "Not an ELF object\n");
		return 1;
	}

	Elf_Scn *text = find_section_by_name(e, ".text");
	if (text == NULL) {
		fprintf(stderr, "ELF object is missing a .text section\n");
		return 1;
	}

	GElf_Shdr text_shdr;
	if (!gelf_getshdr(text, &text_shdr)) {
		fprintf(stderr, "gelf_getshdr(text) failed\n");
		return 1;
	}

	char *name = ".eh_frame";

	// Write the .eh_frame section body in a buffer
	size_t len;
	char *buf;
	FILE *f = open_memstream(&buf, &len);
	if (f == NULL) {
		return 1;
	}
	if (!write_eh_frame(text_shdr.sh_offset, f)) {
		return 1;
	}
	fclose(f);

	// Create the section
	Elf_Scn *scn = elf_newscn(e);
	if (scn == NULL) {
		fprintf(stderr, "elf_newscn() failed: %s\n", elf_errmsg(-1));
		return 1;
	}

	Elf_Data *data = elf_newdata(scn);
	if (data == NULL) {
		fprintf(stderr, "elf_newdata() failed: %s\n", elf_errmsg(-1));
		return 1;
	}
	data->d_align = 4;
	data->d_buf = buf;
	data->d_size = len;

	GElf_Shdr shdr;
	if (!gelf_getshdr(scn, &shdr)) {
		fprintf(stderr, "gelf_getshdr() failed\n");
		return 1;
	}

	shdr.sh_size = len;
	shdr.sh_type = SHT_PROGBITS;
	shdr.sh_addralign = 1;
	shdr.sh_flags = SHF_ALLOC;

	// Add section name to .shstrtab
	Elf_Scn *shstrtab = find_section_by_name(e, ".shstrtab");
	if (shstrtab == NULL) {
		fprintf(stderr, "can't find .shstrtab section\n");
		return 1;
	}

	GElf_Shdr shstrtab_shdr;
	if (!gelf_getshdr(shstrtab, &shstrtab_shdr)) {
		fprintf(stderr, "gelf_getshdr(shstrtab) failed\n");
		return 1;
	}

	Elf_Data *shstrtab_data = elf_newdata(shstrtab);
	if (shstrtab_data == NULL) {
		fprintf(stderr, "elf_newdata(shstrtab) failed\n");
		return 1;
	}

	shstrtab_data->d_buf = name;
	shstrtab_data->d_size = strlen(name) + 1;
	shstrtab_data->d_align = 1;

	shdr.sh_name = shstrtab_shdr.sh_size;

	if (!gelf_update_shdr(scn, &shdr)) {
		fprintf(stderr, "gelf_update_shdr() failed\n");
		return 1;
	}

	// Write the modified ELF object
	elf_flagelf(e, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(e, ELF_C_WRITE) < 0) {
		fprintf(stderr, "elf_update() failed: %s\n", elf_errmsg(-1));
		return 1;
	}

	free(buf);
	elf_end(e);
	close(fd);
	return 0;
}
