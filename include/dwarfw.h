#ifndef DWARFW_H
#define DWARFW_H

#include <stdint.h>
#include <stdio.h>

struct dwarfw_cie {
	uint8_t version;
	char *augmentation;
	uint64_t code_alignment;
	int64_t data_alignment;
	uint64_t return_address_register;

	// only if augmentation contains "z"
	struct {
		uint8_t pointer_encoding; // only if augmentation contains "R"
		// TODO: other augmentation data formats
	} augmentation_data;

	size_t instructions_length;
	char *instructions;
};

size_t dwarfw_cie_write(struct dwarfw_cie *cie, size_t address_size, FILE *f);

struct dwarfw_fde {
	struct dwarfw_cie *cie;

	uint32_t cie_pointer;
	uint32_t initial_location, address_range;
	// TODO: augmentation data

	size_t instructions_length;
	char *instructions;
};

size_t dwarfw_fde_write(struct dwarfw_fde *fde, size_t address_size, FILE *f);

size_t dwarfw_cfa_write_advance_loc(uint32_t delta, FILE *f);
size_t dwarfw_cfa_write_offset(uint64_t reg, uint64_t offset, FILE *f);
size_t dwarfw_cfa_write_nop(FILE *f);
size_t dwarfw_cfa_write_set_loc(uint32_t addr, FILE *f);
size_t dwarfw_cfa_write_undefined(uint64_t reg, FILE *f);
size_t dwarfw_cfa_write_def_cfa(uint64_t reg, uint64_t offset, FILE *f);
size_t dwarfw_cfa_write_def_cfa_register(uint64_t reg, FILE *f);
size_t dwarfw_cfa_write_def_cfa_offset(uint64_t offset, FILE *f);

size_t dwarfw_cfa_pad(size_t length, FILE *f);

#endif
