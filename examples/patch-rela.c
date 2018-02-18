#define _POSIX_C_SOURCE 200809L
#include <dwarf.h>
#include <dwarfw.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Fallback for systems without this "read and write, mmaping if possible" cmd
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
		.augmentation_data = {
			.pointer_encoding = DW_EH_PE_sdata4 | DW_EH_PE_pcrel,
		},
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

static Elf_Scn *find_section_by_name(Elf *elf, const char *section_name) {
	size_t sections_num;
	if (elf_getshdrnum(elf, &sections_num)) {
		return NULL;
	}

	size_t shstrndx;
	if (elf_getshdrstrndx(elf, &shstrndx)) {
		return NULL;
	}

	for (size_t i = 0; i < sections_num; ++i) {
		Elf_Scn *s = elf_getscn(elf, i);
		if (s == NULL) {
			return NULL;
		}

		GElf_Shdr sh;
		if (!gelf_getshdr(s, &sh)) {
			return NULL;
		}

		char *name = elf_strptr(elf, shstrndx, sh.sh_name);
		if (name == NULL) {
			return NULL;
		}

		if (strcmp(name, section_name) == 0) {
			return s;
		}
	}

	return NULL;
}

static Elf_Scn *create_section(Elf *elf, const char *name) {
	Elf_Scn *scn = elf_newscn(elf);
	if (scn == NULL) {
		fprintf(stderr, "elf_newscn() failed: %s\n", elf_errmsg(-1));
		return NULL;
	}

	GElf_Shdr shdr;
	if (!gelf_getshdr(scn, &shdr)) {
		fprintf(stderr, "gelf_getshdr() failed\n");
		return NULL;
	}

	// Add section name to .shstrtab
	Elf_Scn *shstrtab = find_section_by_name(elf, ".shstrtab");
	if (shstrtab == NULL) {
		fprintf(stderr, "can't find .shstrtab section\n");
		return NULL;
	}

	GElf_Shdr shstrtab_shdr;
	if (!gelf_getshdr(shstrtab, &shstrtab_shdr)) {
		fprintf(stderr, "gelf_getshdr(shstrtab) failed\n");
		return NULL;
	}

	Elf_Data *shstrtab_data = elf_newdata(shstrtab);
	if (shstrtab_data == NULL) {
		fprintf(stderr, "elf_newdata(shstrtab) failed\n");
		return NULL;
	}
	shstrtab_data->d_buf = strdup(name);
	shstrtab_data->d_size = strlen(name) + 1;
	shstrtab_data->d_align = 1;

	shdr.sh_name = shstrtab_shdr.sh_size;
	shstrtab_shdr.sh_size += shstrtab_data->d_size;

	if (!gelf_update_shdr(scn, &shdr)) {
		fprintf(stderr, "gelf_update_shdr() failed\n");
		return NULL;
	}

	if (!gelf_update_shdr(shstrtab, &shstrtab_shdr)) {
		fprintf(stderr, "gelf_update_shdr(shstrtab) failed\n");
		return NULL;
	}

	return scn;
}

static int find_section_symbol(Elf *elf, size_t index, GElf_Sym *sym) {
	Elf_Scn *symtab = find_section_by_name(elf, ".symtab");
	if (symtab == NULL) {
		fprintf(stderr, "can't find .symtab section\n");
		return -1;
	}

	Elf_Data *symtab_data = elf_getdata(symtab, NULL);
	if (symtab_data == NULL) {
		fprintf(stderr, "elf_getdata(symtab) failed\n");
		return -1;
	}

	GElf_Shdr symtab_shdr;
	if (!gelf_getshdr(symtab, &symtab_shdr)) {
		fprintf(stderr, "gelf_getshdr(symtab) failed\n");
		return -1;
	}

	int symbols_nr = symtab_shdr.sh_size / symtab_shdr.sh_entsize;
	for (int i = 0; i < symbols_nr; ++i) {
		if (!gelf_getsym(symtab_data, i, sym)) {
			fprintf(stderr, "gelf_getsym() failed\n");
			continue;
		}

		if (GELF_ST_TYPE(sym->st_info) == STT_SECTION && index == sym->st_shndx) {
			return i;
		}
	}

	return -1;
}

static Elf_Scn *create_rela_section(Elf *elf, const char *name, Elf_Scn *base,
		GElf_Rela *rela) {
	Elf_Scn *scn = create_section(elf, name);
	if (scn == NULL) {
		fprintf(stderr, "can't create rela section\n");
		return NULL;
	}

	Elf_Data *data = elf_newdata(scn);
	if (!data) {
		fprintf(stderr, "elf_newdata() failed\n");
		return NULL;
	}

	data->d_buf = rela;
	data->d_size = sizeof(GElf_Rela);
	data->d_align = 1;

	Elf_Scn *symtab = find_section_by_name(elf, ".symtab");
	if (symtab == NULL) {
		fprintf(stderr, "can't find .symtab section\n");
		return NULL;
	}

	GElf_Shdr shdr;
	if (!gelf_getshdr(scn, &shdr)) {
		fprintf(stderr, "gelf_getshdr() failed\n");
		return NULL;
	}
	shdr.sh_size = data->d_size;
	shdr.sh_type = SHT_RELA;
	shdr.sh_addralign = 8;
	shdr.sh_link = elf_ndxscn(symtab);
	shdr.sh_info = elf_ndxscn(base);
	shdr.sh_flags = SHF_INFO_LINK;
	if (!gelf_update_shdr(scn, &shdr)) {
		fprintf(stderr, "gelf_update_shdr() failed\n");
		return NULL;
	}

	return scn;
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

	Elf *elf = elf_begin(fd, ELF_C_RDWR_MMAP, NULL);
	if (elf == NULL) {
		fprintf(stderr, "elf_begin() failed: %s\n", elf_errmsg(-1));
		return 1;
	}

	// Check the ELF object
	Elf_Kind ek = elf_kind(elf);
	if (ek != ELF_K_ELF) {
		fprintf(stderr, "Not an ELF object\n");
		return 1;
	}

	Elf_Scn *text = find_section_by_name(elf, ".text");
	if (text == NULL) {
		fprintf(stderr, "ELF object is missing a .text section\n");
		return 1;
	}

	GElf_Shdr text_shdr;
	if (!gelf_getshdr(text, &text_shdr)) {
		fprintf(stderr, "gelf_getshdr(text) failed\n");
		return 1;
	}

	// Write the .eh_frame section body in a buffer
	size_t len;
	char *buf;
	FILE *f = open_memstream(&buf, &len);
	if (f == NULL) {
		return 1;
	}
	if (!write_eh_frame(0x20, f)) { // text_shdr.sh_offset
		return 1;
	}
	fclose(f);

	// Create the .eh_frame section
	Elf_Scn *scn = create_section(elf, ".eh_frame");
	if (scn == NULL) {
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
	if (!gelf_update_shdr(scn, &shdr)) {
		fprintf(stderr, "gelf_update_shdr() failed\n");
		return 1;
	}

	// Create the .eh_frame.rela section
	GElf_Sym text_sym;
	int text_sym_idx = find_section_symbol(elf, elf_ndxscn(text), &text_sym);
	if (text_sym_idx < 0) {
		fprintf(stderr, "can't find .text section in symbol table\n");
		return 1;
	}
	GElf_Rela initial_position_rela = {
		.r_offset = 0x20,
		.r_info = GELF_R_INFO(text_sym_idx, R_X86_64_PC32),
		.r_addend = 0,
	};
	Elf_Scn *rela = create_rela_section(elf, ".rela.eh_frame", scn,
		&initial_position_rela);
	if (rela == NULL) {
		return 1;
	}

	// Write the modified ELF object
	elf_flagelf(elf, ELF_C_SET, ELF_F_DIRTY);
	if (elf_update(elf, ELF_C_WRITE) < 0) {
		fprintf(stderr, "elf_update() failed: %s\n", elf_errmsg(-1));
		return 1;
	}

	free(buf);
	elf_end(elf);
	close(fd);
	return 0;
}
