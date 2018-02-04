#ifndef DWARFW_H
#define DWARFW_H

#include <stdint.h>
#include <stdio.h>

struct dwarfw_cie {
	uint8_t version;
	char *augmentation;
	uint64_t code_alignment;
	int64_t data_alignment;
};

int dwarfw_cie_write(struct dwarfw_cie *cie, FILE* f);

#endif
