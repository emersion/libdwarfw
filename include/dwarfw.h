#ifndef DWARFW_H
#define DWARFW_H

#include <gelf.h>
#include <stdint.h>
#include <stdio.h>

struct dwarfw_cie {
	uint8_t version;
	const char *augmentation;
	uint64_t code_alignment;
	int64_t data_alignment;
	uint64_t return_address_register;

	// only if augmentation contains "z"
	struct {
		uint8_t pointer_encoding; // only if augmentation contains "R"
		// TODO: other augmentation data formats
	} augmentation_data;

	size_t instructions_length;
	const char *instructions;
};

size_t dwarfw_cie_write(struct dwarfw_cie *cie, FILE *f);

struct dwarfw_fde {
	struct dwarfw_cie *cie;

	uint32_t cie_pointer; // relative to the start of the FDE section
	long long int initial_location;
	uint32_t address_range;
	// TODO: augmentation data

	size_t instructions_length;
	const char *instructions;
};

size_t dwarfw_fde_write(struct dwarfw_fde *fde, GElf_Rela *rela, FILE* f);

// Call Frame Instructions
size_t dwarfw_cie_write_advance_loc(struct dwarfw_cie *cie, uint32_t delta,
	FILE *f);
size_t dwarfw_cie_write_offset(struct dwarfw_cie *cie, uint64_t reg,
	long long int offset, FILE *f);
size_t dwarfw_cie_write_restore(struct dwarfw_cie *cie, uint64_t reg, FILE *f);
size_t dwarfw_cie_write_nop(struct dwarfw_cie *cie, FILE *f);
size_t dwarfw_cie_write_set_loc(struct dwarfw_cie *cie, long long int addr,
	size_t offset, FILE *f);
size_t dwarfw_cie_write_undefined(struct dwarfw_cie *cie, uint64_t reg,
	FILE *f);
size_t dwarfw_cie_write_same_value(struct dwarfw_cie *cie, uint64_t reg,
	FILE *f);
size_t dwarfw_cie_write_register(struct dwarfw_cie *cie, uint64_t reg,
	uint64_t ref, FILE *f);
size_t dwarfw_cie_write_remember_state(struct dwarfw_cie *cie, FILE *f);
size_t dwarfw_cie_write_restore_state(struct dwarfw_cie *cie, FILE *f);
size_t dwarfw_cie_write_def_cfa(struct dwarfw_cie *cie, uint64_t reg,
	long long int offset, FILE *f);
size_t dwarfw_cie_write_def_cfa_register(struct dwarfw_cie *cie, uint64_t reg,
	FILE *f);
size_t dwarfw_cie_write_def_cfa_offset(struct dwarfw_cie *cie,
	long long int offset, FILE *f);
size_t dwarfw_cie_write_def_cfa_expression(struct dwarfw_cie *cie,
	const char *expr, size_t expr_len, FILE *f);
size_t dwarfw_cie_write_expression(struct dwarfw_cie *cie,
	uint64_t reg, const char *expr, size_t expr_len, FILE *f);
size_t dwarfw_cie_write_val_offset(struct dwarfw_cie *cie, uint64_t reg,
	long long int offset, FILE *f);

size_t dwarfw_cie_pad(struct dwarfw_cie *cie, size_t length, FILE *f);

// Call Frame Expressions
size_t dwarfw_op_write_deref(FILE *f);
size_t dwarfw_op_write_bregx(uint64_t reg, long long int offset, FILE *f);

#endif
