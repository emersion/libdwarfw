#ifndef DWARFW_H
#define DWARFW_H

#include <stdint.h>
#include <stdio.h>

struct dwarfw_instruction; // TODO

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

	size_t initial_instructions_length;
	struct dwarfw_instruction *initial_instructions;
};

int dwarfw_cie_write(struct dwarfw_cie *cie, FILE* f);

#endif
