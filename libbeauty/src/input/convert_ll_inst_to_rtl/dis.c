/*
 *  Copyright (C) 2004-2009 The libbeauty Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
/* Intel ia32 instruction format: -
 Instruction-Prefixes (Up to four prefixes of 1-byte each. [optional] )
 Opcode (1-, 2-, or 3-byte opcode)
 ModR/M (1 byte [if required] )
 SIB (Scale-Index-Base:1 byte [if required] )
 Displacement (Address displacement of 1, 2, or 4 bytes or none)
 Immediate (Immediate data of 1, 2, or 4 bytes or none)

 Naming convention taken from Intel Instruction set manual, Appendix A. 25366713.pdf
*/
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <rev.h>
#include <instruction_low_level.h>
#include <convert_ll_inst_to_rtl.h>


const char * dis_opcode_table[] = {
	"NOP",   // 0x00
	"MOV",   // 0x01
	"ADD",   // 0x02
	"ADC",   // 0x03
	"SUB",   // 0x04
	"SBB",   // 0x05
	"OR ",   // 0x06
	"XOR",   // 0x07
	"AND",   // 0x08
	"NOT",   // 0x09
	"TEST",  // 0x0A
	"NEG",   // 0x0B
	"CMP",   // 0x0C
	"MUL",   // 0x0D
	"IMUL",  // 0x0E
	"DIV",   // 0x0F
	"IDIV",  // 0x10
	"JMP",   // 0x11
	"CALL",  // 0x12
	"IF ",   // 0x13
	"ROL",   // 0x14  /* ROL,ROR etc. might be reduced to simpler equivalents. */
	"ROR",   // 0x15
	"RCL",   // 0x16
	"RCR",   // 0x17
	"SHL",   // 0x18
	"SHR",   // 0x19
	"SAL",   // 0x1A
	"SAR",   // 0x1B
	"IN ",   // 0x1C
	"OUT",   // 0x1D
	"RET",   // 0x1E
	"SEX",   // 0x1F   /* Signed extension */
	"JMPT",	 // 0x20
	"CALLT",  // 0x21
	"PHI",  // 0x22
	"ICMP",  // 0x23
	"BRANCH",  // 0x24 
	"LOAD",  // 0x25
	"STORE",  // 0x26
	"LEA",  // 0x27
	"CMOV",  // 0x28
	"DEC",  // 0x29
	"INC",  // 0x2a
	"POP",  // 0x2b
	"PUSH",  // 0x2c
	"LEAVE", // 0x2d
	"NOP", // 0x2e
	"GEP1", // 0x2f
	"CALLM", // 0x30
	"SETCC", // 0x31
	"JMPM", // 0x32
	"MOVS", // 0x33
	"IMULD", // 0x34
	"MULD", // 0x35
	"TRUNC", // 0x36
	"ZEXT", // 0x37
	"BITCAST", // 0x38 
	""
};

uint32_t print_reloc_table_entry(struct reloc_table_s *reloc_table_entry) {
	debug_print(DEBUG_INPUT_DIS, 1, "Reloc Type:0x%x\n", reloc_table_entry->type);
	debug_print(DEBUG_INPUT_DIS, 1, "Address:0x%"PRIx64"\n", reloc_table_entry->address);
	debug_print(DEBUG_INPUT_DIS, 1, "Size:0x%"PRIx64"\n", reloc_table_entry->size);
	debug_print(DEBUG_INPUT_DIS, 1, "Value:0x%"PRIx64"\n", reloc_table_entry->symbol_value);
	debug_print(DEBUG_INPUT_DIS, 1, "External Function Index:0x%"PRIx64"\n", reloc_table_entry->external_functions_index);
	debug_print(DEBUG_INPUT_DIS, 1, "Section index:0x%"PRIx64"\n", reloc_table_entry->section_index);
	debug_print(DEBUG_INPUT_DIS, 1, "Section name:%s\n", reloc_table_entry->section_name);
	debug_print(DEBUG_INPUT_DIS, 1, "Symbol name:%s\n", reloc_table_entry->symbol_name);
	return 0;
}

int lookup_external_entry_point_function(struct self_s *self, uint64_t section_id, uint64_t section_index, char *name, uint64_t value_uint, int *result)
{
	int found = 1; // 1 = not-found, 0 = found.
	int tmp;
	int len1, len2;
	int l;
	debug_print(DEBUG_INPUT_DIS, 1, "looking for external entry point %s\n", name);
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
        if (self->external_entry_points[l].valid && self->external_entry_points[l].type == 1) {
			if ((self->external_entry_points[l].section_id == section_id) &&
				(self->external_entry_points[l].section_index == section_index) &&
				(self->external_entry_points[l].value == value_uint)) {
				len1 = strlen(name);
				len2 = strlen(self->external_entry_points[l].name);
				if (len1 == len2) {
					tmp = strncmp(name, self->external_entry_points[l].name, len2);
					if (!tmp) {
						*result = l;
						debug_print(DEBUG_INPUT_DIS, 1, "found at %x\n", l);
						found = 0;
						break;
					}
				}
			}
		}
	}
	return found;
}

int search_relocation_table_ll_dis(struct self_s *self, uint64_t section_id, uint64_t section_index, uint8_t *base_address, uint64_t offset, uint64_t size, uint64_t *reloc_index)
{
	int n;
	struct reloc_s *reloc = self->sections[section_index].reloc_entry;
	debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: params: section_id=0x%lx, section_index=0x%lx, base_address = %p, offset = 0x%lx, size=0x%lx\n",
		section_id,
		section_index,
		base_address,
		offset,
		size);
	for (n = 0; n < self->sections[section_index].reloc_size; n++) {
		if (reloc[n].offset == offset) {
			*reloc_index = n;
			return 0;
		}
	}
	return 1;
}

int convert_operand(struct self_s *self, int section_id, int section_index, uint64_t base_address, struct operand_low_level_s *ll_operand, int operand_number, struct operand_s *inst_operand) {
	struct reloc_s *reloc_table_entry;
	uint64_t reloc_index;
	int tmp;

	debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: kind = 0x%x\n", ll_operand->kind);
	switch(ll_operand->kind) {
	case KIND_EMPTY:
		inst_operand->store = 0;
		inst_operand->indirect = 0;
		inst_operand->indirect_size = 0;
		inst_operand->index = 0;
		inst_operand->relocated = 0;
		inst_operand->relocated_section_id = 0;
		inst_operand->relocated_section_index = 0;
		inst_operand->relocated_index = 0;
		inst_operand->value_size = 0;
		break;
	case KIND_REG:
		inst_operand->store = STORE_REG;
		inst_operand->indirect = IND_DIRECT;
		inst_operand->indirect_size = ll_operand->size;
		inst_operand->index = ll_operand->operand[operand_number].value;
		inst_operand->relocated = 0;
		inst_operand->relocated_section_id = 0;
		inst_operand->relocated_section_index = 0;
		inst_operand->relocated_index = 0;
		inst_operand->value_size = ll_operand->operand[operand_number].size;
		break;
	case KIND_IMM:
		inst_operand->store = STORE_DIRECT;
		inst_operand->indirect = IND_DIRECT;
		inst_operand->indirect_size = ll_operand->size;
		inst_operand->index = ll_operand->operand[operand_number].value;
		inst_operand->relocated = 0;
		inst_operand->relocated_section_id = 0;
		inst_operand->relocated_section_index = 0;
		inst_operand->relocated_index = 0;
//		inst_operand->value_size = ll_operand->operand[operand_number].size;
		inst_operand->value_size = ll_operand->size;
		debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: relocate: base_address = 0x%lx, offset = 0x%lx, size = 0x%x\n",
			base_address,
			ll_operand->operand[operand_number].offset,
			ll_operand->operand[operand_number].size);
		reloc_index = 0;
		if (self->sections_size > section_index) {
			debug_print(DEBUG_INPUT_DIS, 1, "sections = 0x%lx reloc_size = 0x%lx\n",
				self->sections_size, self->sections[section_index].reloc_size);
		}
		if (self->sections_size && self->sections[section_index].reloc_size) {
			debug_print(DEBUG_INPUT_DIS, 1, "sections = 0x%lx reloc_size = 0x%lx\n",
				self->sections_size, self->sections[section_index].reloc_size);
			tmp = search_relocation_table_ll_dis(self, section_id, section_index, 0,
				base_address + ll_operand->operand[operand_number].offset,
				ll_operand->operand[operand_number].size >> 3,
				&reloc_index);
			debug_print(DEBUG_INPUT_DIS, 1, "tmp = %d, reloc_index = 0x%lx\n",
						tmp, reloc_index);
			reloc_table_entry = &(self->sections[section_index].reloc_entry[reloc_index]);
			if (!tmp) {
				debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: relocate found index=0x%lx, type=0x%x, offset=0x%lx, size=0x%lx, section_id=0x%lx, section_index=0x%lx,name=%s, value_int = 0x%lx, value_uint = 0x%lx, addend = 0x%lx\n",
					reloc_index,
					reloc_table_entry->type,
					reloc_table_entry->offset,
					reloc_table_entry->offset_size,
					reloc_table_entry->section_id,
					reloc_table_entry->section_index,
					reloc_table_entry->name,
					reloc_table_entry->value_int,
					reloc_table_entry->value_uint,
					reloc_table_entry->addend);
				if (self->sections[reloc_table_entry->section_index].section_id != reloc_table_entry->section_id) {
					int result = 0;
					inst_operand->relocated = 3; /* An external function / variable */
					inst_operand->relocated_section_id = reloc_table_entry->section_id;
					inst_operand->relocated_section_index = reloc_table_entry->section_index;
					inst_operand->relocated_index = reloc_index;
					tmp = lookup_external_function(self, reloc_table_entry->name, &result);
					if (!tmp) {
						inst_operand->relocated_external_function = result;
						debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: relocated 3 found function %s at entry %d\n",
									reloc_table_entry->name,
									result);
					} else {
						debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: relocated 3 failed to find function %s\n", reloc_table_entry->name);
						exit(1);
					}
				} else if ((reloc_table_entry->section_index == section_index) &&
						(reloc_table_entry->section_id == section_id)) {
					int result = 0;
					inst_operand->relocated = 2; /* Internal function / variable */
					//inst_operand->relocated_area = reloc_table_entry->relocated_area;
					inst_operand->relocated_section_id = reloc_table_entry->section_id;
					inst_operand->relocated_section_index = reloc_table_entry->section_index;
					inst_operand->relocated_index = reloc_index;
					tmp = lookup_external_entry_point_function(self,
															reloc_table_entry->section_id,
															reloc_table_entry->section_index,
															reloc_table_entry->name,
															reloc_table_entry->value_uint,
															&result);
					if (!tmp) {
						inst_operand->index = result;
						inst_operand->relocated_external_function = result;
						debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: relocated 2 found function %s at entry %d\n",
									reloc_table_entry->name,
									result);
					} else {
						debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: relocated 2 failed to find function %s\n", reloc_table_entry->name);
						//exit(1);
					}
				} else if (self->sections[reloc_table_entry->section_index].data) {
					debug_print(DEBUG_INPUT_DIS, 1, "FIXME: reloc_table_entry pointing to DATA section\n");
					// FIXME: TODO
					//        This means that this operand is a pointer.
					inst_operand->relocated = 1; /* Data pointer relocated */
					inst_operand->relocated_section_id = reloc_table_entry->section_id;
					inst_operand->relocated_section_index = reloc_table_entry->section_index;
					switch(reloc_table_entry->type) {
					case 0x1:
					case 0xa:
						inst_operand->relocated_index = reloc_table_entry->addend;
						debug_print(DEBUG_INPUT_DIS, 1, "section_name:%s + 0x%x\n",
								reloc_table_entry->name,
								reloc_table_entry->addend);
						break;

					case 0x2:
					case 0xb:
						inst_operand->relocated_index = reloc_table_entry->value_uint;
						debug_print(DEBUG_INPUT_DIS, 1, "section_name:%s + 0x%x\n",
								reloc_table_entry->name,
								reloc_table_entry->value_uint);
						break;

					default:
						debug_print(DEBUG_INPUT_DIS, 1, "type not handled\n");
						exit(1);
					}
					//exit(1);
				} else {
					debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: relocated 2 failed to find function %s\n", reloc_table_entry->name);
				}
				//exit(1);
			}
		}
		break;
#if 0
			tmp = bf_relocated_code(self->handle_void, 0,
				base_address + ll_operand->operand[operand_number].offset,
				ll_operand->operand[operand_number].size >> 3,
				&reloc_index,
				&reloc_table_entry);
			if (!tmp) {
				debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: relocate found index=0x%lx, type=0x%x, address=0x%lx, size=0x%lx, addend=0x%lx, external_function_index=0x%lx, section_id=0x%lx, section_index=0x%lx, relocation_area=0x%lx, value = 0x%lx, section_name=%s, symbol_name=%s\n",
					reloc_index,
					reloc_table_entry->type,
					reloc_table_entry->address,
					reloc_table_entry->size,
					reloc_table_entry->addend,
					reloc_table_entry->external_functions_index,
					reloc_table_entry->section_id,
					reloc_table_entry->section_index,
					reloc_table_entry->relocated_area,
					reloc_table_entry->symbol_value,
					reloc_table_entry->section_name,
					reloc_table_entry->symbol_name);
				if (reloc_table_entry->type == 2) {
					int result = 0;
					inst_operand->relocated = 3; /* An external function / variable */
					inst_operand->relocated_index = reloc_index;
					tmp = lookup_external_function(self, reloc_table_entry->symbol_name, &result);
					if (!tmp) {
						inst_operand->relocated_area = result;
						debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: relocated 3 found function %s at entry %d\n",
									reloc_table_entry->symbol_name,
									result);
					} else {
						debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: relocated 3 failed to find function %s\n", reloc_table_entry->symbol_name);
						exit(1);
					}
				} else {
					inst_operand->relocated = 2;
					inst_operand->relocated_area = reloc_table_entry->relocated_area;
					inst_operand->relocated_index = reloc_table_entry->symbol_value;
				}
			}
		}
		break;
#endif
	case KIND_SCALE:
	case KIND_IND_SCALE:
		switch (operand_number) {
		case 0:
		case 2:
		case 4:
			/* REG */
			inst_operand->store = STORE_REG;
			inst_operand->indirect = IND_DIRECT;
			inst_operand->indirect_size = ll_operand->size;
			inst_operand->index = ll_operand->operand[operand_number].value;
			inst_operand->relocated = 0;
			inst_operand->value_size = ll_operand->operand[operand_number].size;
			break;
		case 1:
		case 3:
			/* IMM */
			inst_operand->store = STORE_DIRECT;
			inst_operand->indirect = IND_DIRECT;
			inst_operand->indirect_size = ll_operand->size;
			inst_operand->index = ll_operand->operand[operand_number].value;
			inst_operand->relocated = 0;
			inst_operand->value_size = ll_operand->operand[operand_number].size;
			debug_print(DEBUG_INPUT_DIS, 1, "convert_operand: relocate scale: operand =  0x%x, base_address = 0x%lx, offset = 0x%lx, size = 0x%x\n",
				operand_number,
				base_address,
				ll_operand->operand[operand_number].offset,
				ll_operand->operand[operand_number].size);
			break;
		default:
			// FAILURE EXIT
			printf("FAILED: KIND_SCALE operand_number out of range\n");
			exit(1);
			break;
		}
		break;
	default:
		// FAILURE EXIT
		printf("FAILED: KIND not recognised\n");
		exit(1);
		break;
	}
	return 0;
}

struct operand_low_level_s operand_empty = {
	.kind = KIND_EMPTY,
};

struct operand_low_level_s operand_reg_tmp1 = {
	.kind = KIND_REG,
	.size = 64,
	.operand = {{.value = REG_TMP1, .size = 64, .offset = 0}},
//	.operand.operand[0].size = 64,
//	.operand.operand[0].offset = 0,
};

struct operand_low_level_s operand_reg_tmp2 = {
	.kind = KIND_REG,
	.size = 64,
	.operand = {{.value = REG_TMP2, .size = 64, .offset = 0}},
};

struct operand_low_level_s operand_reg_tmp3 = {
	.kind = KIND_REG,
	.size = 64,
	.operand = {{.value = REG_TMP3, .size = 64, .offset = 0}},
};

struct operand_low_level_s operand_reg_tmp4 = {
	.kind = KIND_REG,
	.size = 64,
	.operand = {{.value = REG_TMP4, .size = 64, .offset = 0}},
};


int convert_base(struct self_s *self, int section_id, int section_index, struct instruction_low_level_s *ll_inst, int flags, struct dis_instructions_s *dis_instructions) {
	int tmp;
	struct instruction_s *instruction;
	int n;
	int indirect = 0;
	int srcA_ind = 0;
	int srcB_ind = 0;
	int dstA_ind = 0;
	int result = 0;
	int final_opcode = 0;
	int imm_sign = 0;
	int ind_stack = 0;
	struct operand_low_level_s *previous_operand;
	struct operand_low_level_s *scale_ptr_operand;
	struct operand_low_level_s operand_imm;
	struct operand_low_level_s *srcA_operand;
	struct operand_low_level_s *srcB_operand;
	struct operand_low_level_s *dstA_operand;
	struct operand_low_level_s *scale_operand;
	struct operand_low_level_s operand_tmp;

	debug_print(DEBUG_INPUT_DIS, 1, "convert_base entered\n");
	debug_print(DEBUG_INPUT_DIS, 1, "disassemble_amd64:convert_base start inst_number = 0x%x\n", dis_instructions->instruction_number);
	dis_instructions->instruction[dis_instructions->instruction_number].opcode = NOP; /* Un-supported OPCODE */
	dis_instructions->instruction[dis_instructions->instruction_number].flags = 0; /* No flags effected */
	if ((ll_inst->srcA.kind == KIND_IND_REG) || 	
		(ll_inst->srcA.kind == KIND_IND_IMM) || 	
		(ll_inst->srcA.kind == KIND_IND_SCALE))
		srcA_ind = 1;
	if ((ll_inst->srcB.kind == KIND_IND_REG) || 	
		(ll_inst->srcB.kind == KIND_IND_IMM) || 	
		(ll_inst->srcB.kind == KIND_IND_SCALE))
		srcB_ind = 1;
	if ((ll_inst->dstA.kind == KIND_IND_REG) || 	
		(ll_inst->dstA.kind == KIND_IND_IMM) || 	
		(ll_inst->dstA.kind == KIND_IND_SCALE))
		dstA_ind = 1;
	if (srcA_ind || srcB_ind || dstA_ind) 
		indirect = 1;
	debug_print(DEBUG_INPUT_DIS, 1, "disassemble_amd64:convert_base srcA_ind:%d srcB_ind:%d dstA_ind:%d ind:%d\n",
                   srcA_ind, srcB_ind, dstA_ind, indirect);
	final_opcode = ll_inst->opcode;

	previous_operand = &operand_empty;
	scale_ptr_operand = &operand_empty;
	scale_operand = &operand_empty;
	srcA_operand = &(ll_inst->srcA);
	srcB_operand = &(ll_inst->srcB);
	dstA_operand = &(ll_inst->dstA);
	debug_print(DEBUG_INPUT_DIS, 1, "KIND operand: srcA=0x%x, srcB=0x%x, dstA=0x%x\n",
		srcA_operand->kind,
		srcB_operand->kind,
		dstA_operand->kind);
	debug_print(DEBUG_INPUT_DIS, 1, "KIND ll_inst: srcA=0x%x, srcB=0x%x, dstA=0x%x\n",
		ll_inst->srcA.kind,
		ll_inst->srcB.kind,
		ll_inst->dstA.kind);
	/* FIXME: Need to handle special instructions as well */
	if (!indirect) {
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		if ((srcA_operand->kind == KIND_SCALE) &&
			(srcB_operand->kind == KIND_SCALE)) {
			// FAILURE EXIT
			printf("FAILED: Too many KIND_IND_SCALE\n");
			exit(1);
		}
		if (dstA_operand->kind == KIND_SCALE) {
			// FAILURE EXIT
			printf("FAILED: dstA KIND_IND_SCALE\n");
			exit(1);
		}
		if (srcB_operand->kind == KIND_SCALE) {
			debug_print(DEBUG_INPUT_DIS, 1, "srcB KIND_SCALE\n");
			scale_operand = srcB_operand;
			// Most likely opcode LEA. Deal with scale, put result in REG_TMP1
			if (scale_operand->operand[2].value == 0) {
				previous_operand = &operand_empty;
			} else if ((scale_operand->operand[2].value != 0) && (scale_operand->operand[1].value == 1)) {
				operand_tmp.kind = KIND_REG;
				operand_tmp.size = 64;
				operand_tmp.operand[0].value = scale_operand->operand[2].value;
				operand_tmp.operand[0].size = scale_operand->operand[2].size;
				operand_tmp.operand[0].offset = scale_operand->operand[2].offset;
				previous_operand = &operand_tmp;
			} else if ((scale_operand->operand[2].value != 0) && (scale_operand->operand[1].value > 1)) {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
				instruction->opcode = IMUL;
				instruction->flags = 0;
				convert_operand(self, section_id, section_index, ll_inst->address, scale_operand, 2, &(instruction->srcA));
				convert_operand(self, section_id, section_index, ll_inst->address, scale_operand, 1, &(instruction->srcB));
				instruction->srcB.value_size = instruction->srcA.value_size;
				convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp1, 0, &(instruction->dstA));
				dis_instructions->instruction_number++;
				previous_operand = &operand_reg_tmp1;
			}
			if ((scale_operand->operand[3].value > 0) && (previous_operand == &operand_empty)) {
				int64_t value = scale_operand->operand[3].value;
				if (value < 0) {
					imm_sign = 1;
					value = 0 - value;
				}
				operand_imm.kind = KIND_IMM;
				operand_imm.size = 64;
				operand_imm.operand[0].value = value;
				operand_imm.operand[0].size = scale_operand->operand[3].size;
				operand_imm.operand[0].offset = scale_operand->operand[3].offset;
				previous_operand = &operand_imm;
			} else if ((scale_operand->operand[3].value > 0) && (previous_operand != &operand_empty)) {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
				int64_t value = scale_operand->operand[3].value;
				if (value < 0) {
					imm_sign = 1;
					value = 0 - value;
					instruction->opcode = SUB;
				} else {
					instruction->opcode = ADD;
				}
				operand_imm.kind = KIND_IMM;
				operand_imm.size = 64;
				operand_imm.operand[0].value = value;
				operand_imm.operand[0].size = scale_operand->operand[3].size;
				operand_imm.operand[0].offset = scale_operand->operand[3].offset;
				instruction->flags = 0;
				convert_operand(self, section_id, section_index, ll_inst->address, previous_operand, 0, &(instruction->srcA));
				convert_operand(self, section_id, section_index, ll_inst->address, &operand_imm, 0, &(instruction->srcB));
				convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp1, 0, &(instruction->dstA));
				dis_instructions->instruction_number++;
				previous_operand = &operand_reg_tmp1;
			}
			if (previous_operand == &operand_empty) {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
				instruction->opcode = MOV;
				instruction->flags = 0;
				convert_operand(self, section_id, section_index, ll_inst->address, scale_operand, 0, &(instruction->srcA));
				convert_operand(self, section_id, section_index, ll_inst->address, &operand_empty, 0, &(instruction->srcB));
				convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp1, 0, &(instruction->dstA));
				dis_instructions->instruction_number++;
				previous_operand = &operand_reg_tmp1;
				srcA_operand = &operand_reg_tmp1;
			} else if (scale_operand->operand[0].value > 0) {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
				if (imm_sign) {	
					instruction->opcode = SUB;
				} else {
					instruction->opcode = ADD;
				}
				instruction->flags = 0;
				convert_operand(self, section_id, section_index, ll_inst->address, scale_operand, 0, &(instruction->srcA));
				convert_operand(self, section_id, section_index, ll_inst->address, previous_operand, 0, &(instruction->srcB));
				convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp1, 0, &(instruction->dstA));
				dis_instructions->instruction_number++;
				previous_operand = &operand_reg_tmp1;
				srcA_operand = &operand_reg_tmp1;
			} else {
				srcA_operand = &operand_reg_tmp1;
			}
			final_opcode = MOV;
		}
		if (ll_inst->srcA.kind == KIND_SCALE) {
			// Deal with scale, put result in REG_TMP1
			printf("FAILED: srcA KIND_IND_SCALE\n");
			exit(1);
		}
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = final_opcode;
		instruction->flags = flags;
		convert_operand(self, section_id, section_index, ll_inst->address, srcA_operand, 0, &(instruction->srcA));
		convert_operand(self, section_id, section_index, ll_inst->address, srcB_operand, 0, &(instruction->srcB));
		convert_operand(self, section_id, section_index, ll_inst->address, dstA_operand, 0, &(instruction->dstA));
		dis_instructions->instruction_number++;
	} else {
		/* Handle the indirect case */
		debug_print(DEBUG_INPUT_DIS, 1, "srcA kind:%d, srcB kind:%d dstA kind:%d\n",
                            srcA_operand->kind, srcB_operand->kind, dstA_operand->kind);
		if (dstA_operand->kind == KIND_IND_SCALE) {
			scale_operand = dstA_operand;
			/* Let srcA and srcB override this */
		}
		if (srcA_operand->kind == KIND_IND_SCALE) {
			scale_operand = srcA_operand;
		}
		if (srcB_operand->kind == KIND_IND_SCALE) {
			scale_operand = srcB_operand;
		}
		if ((scale_operand->operand[0].value >= REG_SP) &&
			(scale_operand->operand[0].value <= REG_BP)) {
			ind_stack = 1;
		}

		/* IMUL the index reg[2] with the multiplier imm[1] */
		if (scale_operand->operand[2].value == 0) {
			previous_operand = &operand_empty;
		} else if ((scale_operand->operand[2].value != 0) && (scale_operand->operand[1].value == 1)) {
			operand_tmp.kind = KIND_REG;
			operand_tmp.size = 64;
			operand_tmp.operand[0].value = scale_operand->operand[2].value;
			operand_tmp.operand[0].size = scale_operand->operand[2].size;
			operand_tmp.operand[0].offset = scale_operand->operand[2].offset;
			previous_operand = &operand_tmp;
		} else if ((scale_operand->operand[2].value != 0) && (scale_operand->operand[1].value > 1)) {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = IMUL;
			instruction->flags = 0;
			convert_operand(self, section_id, section_index, ll_inst->address, scale_operand, 2, &(instruction->srcA));
			convert_operand(self, section_id, section_index, ll_inst->address, scale_operand, 1, &(instruction->srcB));
			/* Make the constant multiplier equal in width to the dstA */
			instruction->srcB.value_size = operand_reg_tmp1.size;
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp1, 0, &(instruction->dstA));
			dis_instructions->instruction_number++;
			previous_operand = &operand_reg_tmp1;
		} else {
			printf("Should not reach here\n");
			exit(1);
		}

		/* Add pointer offset */
		if ((scale_operand->operand[0].value > 0) && (previous_operand == &operand_empty)) {
			operand_tmp.kind = KIND_REG;
			operand_tmp.size = 64;
			operand_tmp.operand[0].value = scale_operand->operand[0].value;
			operand_tmp.operand[0].size = scale_operand->operand[0].size;
			operand_tmp.operand[0].offset = scale_operand->operand[0].offset;
			previous_operand = &operand_tmp;
		} else if ((scale_operand->operand[0].value > 0) && (previous_operand != &operand_empty)) {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = ADD;
			instruction->flags = 0;
			convert_operand(self, section_id, section_index, ll_inst->address, previous_operand, 0, &(instruction->srcA));
			convert_operand(self, section_id, section_index, ll_inst->address, scale_operand, 0, &(instruction->srcB));
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp1, 0, &(instruction->dstA));
			dis_instructions->instruction_number++;
			previous_operand = &operand_reg_tmp1;
		}

		/* Add the IMM[3] offset */
		if (previous_operand == &operand_empty) {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			int64_t value = scale_operand->operand[3].value;
			if (value < 0) {
				imm_sign = 1;
				value = 0 - value;
				instruction->opcode = SUB;
			} else {
				instruction->opcode = ADD;
			}
			operand_imm.kind = KIND_IMM;
			operand_imm.size = 64;
			operand_imm.operand[0].value = 0;
			operand_imm.operand[0].size = 0;
			operand_imm.operand[0].offset = 0;
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_imm, 0, &(instruction->srcA));
			operand_imm.kind = KIND_IMM;
			operand_imm.size = 64;
			operand_imm.operand[0].value = value;
			operand_imm.operand[0].size = scale_operand->operand[3].size;
			operand_imm.operand[0].offset = scale_operand->operand[3].offset;
			instruction->flags = 0;
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_imm, 0, &(instruction->srcB));
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp1, 0, &(instruction->dstA));
			dis_instructions->instruction_number++;
			previous_operand = &operand_reg_tmp1;
		} else if (previous_operand != &operand_empty) {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			int64_t value = scale_operand->operand[3].value;
			if (value < 0) {
				imm_sign = 1;
				value = 0 - value;
				instruction->opcode = SUB;
			} else {
				instruction->opcode = ADD;
			}
			operand_imm.kind = KIND_IMM;
			operand_imm.size = 64;
			operand_imm.operand[0].value = value;
			operand_imm.operand[0].size = scale_operand->operand[3].size;
			operand_imm.operand[0].offset = scale_operand->operand[3].offset;
			instruction->flags = 0;
			convert_operand(self, section_id, section_index, ll_inst->address, previous_operand, 0, &(instruction->srcA));
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_imm, 0, &(instruction->srcB));
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp1, 0, &(instruction->dstA));
			dis_instructions->instruction_number++;
			previous_operand = &operand_reg_tmp1;
		}
                scale_ptr_operand = previous_operand;

		if ((srcA_operand->kind == KIND_IND_SCALE) ||
			(srcB_operand->kind == KIND_IND_SCALE)) {

			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = BITCAST;
			instruction->flags = 0;
			convert_operand(self, section_id, section_index, ll_inst->address, scale_ptr_operand, 0, &(instruction->srcA));
			instruction->srcA.value_size = 0; /* Don't know the size at this point */
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp2, 0, &(instruction->dstA));
			//instruction->dstA.value_size = ll_inst->srcA.size;
			instruction->dstA.value_size = 0;
			dis_instructions->instruction_number++;

			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = LOAD;
			instruction->flags = 0;
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp2, 0, &(instruction->srcA));
			instruction->srcA.value_size = ll_inst->srcA.size;
			if (ind_stack) {
				instruction->srcA.indirect = IND_STACK;
			} else {
				instruction->srcA.indirect = IND_MEM;
			}
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp2, 0, &(instruction->srcB));
			instruction->srcB.value_size = 64;
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp3, 0, &(instruction->dstA));
			instruction->dstA.value_size = ll_inst->srcA.size;
			dis_instructions->instruction_number++;
			previous_operand = &operand_reg_tmp3;
		}
		
		if (ll_inst->srcA.kind == KIND_IND_SCALE) {
			srcA_operand = previous_operand;
		}
		if (ll_inst->srcB.kind == KIND_IND_SCALE) {
			srcB_operand = previous_operand;
		}
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = ll_inst->opcode;
		instruction->flags = flags;
		convert_operand(self, section_id, section_index, ll_inst->address, srcA_operand, 0, &(instruction->srcA));
		instruction->srcA.value_size = ll_inst->srcA.size;
		convert_operand(self, section_id, section_index, ll_inst->address, srcB_operand, 0, &(instruction->srcB));
		instruction->srcB.value_size = ll_inst->srcB.size;
		if (ll_inst->dstA.kind == KIND_IND_SCALE) {
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp4, 0, &(instruction->dstA));
			instruction->dstA.value_size = ll_inst->dstA.size;
		} else {
			convert_operand(self, section_id, section_index, ll_inst->address, dstA_operand, 0, &(instruction->dstA));
		}
		dis_instructions->instruction_number++;
		if (ll_inst->dstA.kind == KIND_IND_SCALE) {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = BITCAST;
			instruction->flags = 0;
			convert_operand(self, section_id, section_index, ll_inst->address, scale_ptr_operand, 0, &(instruction->srcA));
			instruction->srcA.value_size = 0; /* Don't know the size at this point */
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp2, 0, &(instruction->dstA));
			//instruction->dstA.value_size = ll_inst->srcA.size;
			instruction->dstA.value_size = 0;
			dis_instructions->instruction_number++;

			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = STORE;
			instruction->flags = 0;
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp4, 0, &(instruction->srcA));
			instruction->srcA.value_size = ll_inst->srcA.size;
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp2, 0, &(instruction->srcB));
			convert_operand(self, section_id, section_index, ll_inst->address, &operand_reg_tmp2, 0, &(instruction->dstA));
			instruction->dstA.value_size = ll_inst->dstA.size;
			if (ind_stack) {
				instruction->dstA.indirect = IND_STACK;
			} else {
				instruction->dstA.indirect = IND_MEM;
			}
			dis_instructions->instruction_number++;
		}
	}
	result = 0;
	debug_print(DEBUG_INPUT_DIS, 1, "convert_base exit\n");
	return result;
}

int copy_operand(struct operand_low_level_s *src, struct operand_low_level_s *dst) {
	int n;
	dst->kind = src->kind;
	dst->size = src->size;
	for (n = 0; n < 16; n++) {
		dst->operand[n].value = src->operand[n].value;
		dst->operand[n].size = src->operand[n].size;
		dst->operand[n].offset = src->operand[n].offset;
	}
	return 0;
}

int convert_ll_inst_to_rtl(struct self_s *self, int section_id, int section_index, struct instruction_low_level_s *ll_inst, struct dis_instructions_s *dis_instructions) {
	int tmp;
	int n;
	int result = 1;
	int8_t rel8;
	int16_t rel16;
	int32_t rel32;
	int64_t rel64;
	uint64_t value;
	struct instruction_s *instruction;
	struct reloc_table_s *reloc_table_entry;

	debug_print(DEBUG_INPUT_DIS, 1, "start\n");
	dis_instructions->instruction_number = 0;
	dis_instructions->bytes_used = ll_inst->octets;

	debug_print(DEBUG_INPUT_DIS, 1, "ll_inst->opcode = 0x%x\n", ll_inst->opcode);
	switch (ll_inst->opcode) {
	case NOP:
		/* Do nothing */
		result = 0;
		break;
	case MOV:
	case ZEXT:
		copy_operand(&ll_inst->srcB, &ll_inst->srcA);
		ll_inst->srcB.kind = KIND_EMPTY;
		tmp  = convert_base(self, section_id, section_index, ll_inst, 0, dis_instructions);
		result = tmp;
		break;
	case CMOV:
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = IF;
		instruction->flags = 0;
		instruction->dstA.store = STORE_DIRECT;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		/* Means get from rest of instruction */
		//relative = getbyte(base_address, offset + dis_instructions->bytes_used);
		/* extends byte to int64_t */
		rel64 = 0; /* Skip to next instruction */
		instruction->dstA.index = rel64;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 32;
		instruction->srcA.store = STORE_DIRECT;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = ll_inst->predicate; /* CONDITION to skip mov instruction */
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 32;
		dis_instructions->instruction_number++;
		
		ll_inst->opcode = MOV;
		//copy_operand(&ll_inst->srcB, &ll_inst->srcA);
		ll_inst->srcB.kind = KIND_EMPTY;
		tmp  = convert_base(self, section_id, section_index, ll_inst, 0, dis_instructions);
		result = tmp;
		break;
	case SETCC:
		copy_operand(&ll_inst->srcA, &ll_inst->dstA);
		ll_inst->opcode = MOV;
		ll_inst->srcA.kind = KIND_IMM;
		ll_inst->srcA.size = 8;
		ll_inst->srcA.operand[0].value = 1;
		ll_inst->srcA.operand[0].size = 8;
		ll_inst->srcA.operand[0].offset = 0;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = IF;
		instruction->flags = 0;
		instruction->dstA.store = STORE_DIRECT;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		/* Means get from rest of instruction */
		//relative = getbyte(base_address, offset + dis_instructions->bytes_used);
		/* extends byte to int64_t */
		rel64 = 0; /* Skip to next instruction */
		instruction->dstA.index = rel64;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 32;
		instruction->srcA.store = STORE_DIRECT;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = ll_inst->predicate; /* CONDITION to skip mov instruction */
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 32;
		dis_instructions->instruction_number++;
		
		tmp  = convert_base(self, section_id, section_index, ll_inst, 0, dis_instructions);
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = IF;
		instruction->flags = 0;
		instruction->dstA.store = STORE_DIRECT;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		/* Means get from rest of instruction */
		//relative = getbyte(base_address, offset + dis_instructions->bytes_used);
		/* extends byte to int64_t */
		rel64 = 0; /* Skip to next instruction */
		instruction->dstA.index = rel64;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 32;
		instruction->srcA.store = STORE_DIRECT;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = ((ll_inst->predicate - 1) ^ 0x1) + 1; /* CONDITION to skip mov instruction */
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 32;
		dis_instructions->instruction_number++;
		
		ll_inst->srcA.operand[0].value = 0;
		tmp  = convert_base(self, section_id, section_index, ll_inst, 0, dis_instructions);
		result = tmp;
		break;

	case DEC:
		copy_operand(&ll_inst->dstA, &ll_inst->srcA);
		ll_inst->srcB.kind = KIND_IMM;
		ll_inst->srcB.size = ll_inst->dstA.size;
		if (ll_inst->dstA.size == 0) {
			debug_print(DEBUG_INPUT_DIS, 1, "ERROR DEC value size == 0\n");
			exit(1);
		}
		ll_inst->srcB.operand[0].value = 1;
		ll_inst->srcB.operand[0].size = ll_inst->dstA.size;
		ll_inst->srcB.operand[0].offset = 0;
		ll_inst->opcode = SUB;
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case INC:
		copy_operand(&ll_inst->dstA, &ll_inst->srcA);
		ll_inst->srcB.kind = KIND_IMM;
		ll_inst->srcB.size = ll_inst->dstA.size;
		if (ll_inst->dstA.size == 0) {
			debug_print(DEBUG_INPUT_DIS, 1, "ERROR INC value size == 0\n");
			exit(1);
		}
		ll_inst->srcB.operand[0].value = 1;
		ll_inst->srcB.operand[0].size = ll_inst->dstA.size;
		ll_inst->srcB.operand[0].offset = 0;
		ll_inst->opcode = ADD;
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case LEA: /* Used at the MC Inst low level */
		tmp  = convert_base(self, section_id, section_index, ll_inst, 0, dis_instructions);
		result = tmp;
		break;
	case JMPT: /* Jump Table */
		tmp  = convert_base(self, section_id, section_index, ll_inst, 0, dis_instructions);
		result = tmp;
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number -  1];
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_IP;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		break;
	case JMPM: /* Jump Indirect */
		ll_inst->opcode = JMPT;
		tmp  = convert_base(self, section_id, section_index, ll_inst, 0, dis_instructions);
		result = tmp;
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number -  1];
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_IP;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		break;
	case CALLT: /* Call jump table */
		break;
	case JMP: /* Relative */
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = JMP;
		instruction->flags = 0;
		instruction->srcA.store = STORE_DIRECT;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		value = ll_inst->srcB.operand[0].value;
		switch (ll_inst->srcB.operand[0].size) {
		case 8:
			rel8 = value;
			rel64 = rel8;
			value = rel64;
			break;
		case 16:
			rel16 = value;
			rel64 = rel16;
			value = rel64;
			break;
		case 32:
			rel32 = value;
			rel64 = rel32;
			value = rel64;
			break;
		case 64:
			break;
		}
		instruction->srcA.index = value;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_IP;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		dis_instructions->instruction_number++;
		result = 0;
		break;
	case CALL: /* non-relative */
		/* srcA = call target.
		 * srcB = ESP.
		 */
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = CALL;
		instruction->flags = 0;
		/* Note: ll_inst->srcB due to the way opcode_form == 1 is processed. */
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcB), 0, &(instruction->srcA));
		debug_print(DEBUG_INPUT_DIS, 1, "CALL instruction->srcA.index = 0x%lx\n", instruction->srcA.index);
		instruction->srcB.store = STORE_REG;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = REG_SP;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_AX;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		dis_instructions->instruction_number++;
		result = 0;
		break;
	case CALLM: /* indirect */
		/* srcA = target
		 * srcB = ESP
		 * dstA = EAX
		 */
		ll_inst->opcode = CALLM;
		tmp  = convert_base(self, section_id, section_index, ll_inst, 0, dis_instructions);
		result = tmp;
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number -  1];
		instruction->srcB.store = STORE_REG;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = REG_SP;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_AX;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		//dis_instructions->instruction_number++;
		break;
	case IF:
		debug_print(DEBUG_INPUT_DIS, 1, "IF opcode  = 0x%x\n", ll_inst->opcode);
		debug_print(DEBUG_INPUT_DIS, 1, "address  = 0x%lx\n", ll_inst->address);
		debug_print(DEBUG_INPUT_DIS, 1, "octets  = 0x%x\n", ll_inst->octets);
		debug_print(DEBUG_INPUT_DIS, 1, "predicate  = 0x%x\n", ll_inst->predicate);
		debug_print(DEBUG_INPUT_DIS, 1, "value  = 0x%lx\n", ll_inst->srcA.operand[0].value);
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = IF;
		instruction->flags = 0;
		instruction->dstA.store = STORE_DIRECT;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		value = ll_inst->srcB.operand[0].value;
		switch (ll_inst->srcB.operand[0].size) {
		case 8:
			rel8 = value;
			rel64 = rel8;
			value = rel64;
			break;
		case 16:
			rel16 = value;
			rel64 = rel16;
			value = rel64;
			break;
		case 32:
			rel32 = value;
			rel64 = rel32;
			value = rel64;
			break;
		case 64:
			break;
		}
		instruction->dstA.index = value;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 32;
		instruction->srcA.store = STORE_DIRECT;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = ll_inst->predicate; /* CONDITION */
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 32;
		dis_instructions->instruction_number++;
		result = 0;
		break;
	case IN:
		break;
	case OUT:
		break;
	case ICMP: /* ICMP. Similar to LLVM ICMP */
		break;
	case BRANCH: /* Branch Conditional. Similar to LLVM ICMP */
		break;
	case LOAD: /* Load from memory/stack */
		tmp  = convert_base(self, section_id, section_index, ll_inst, 0, dis_instructions);
		result = tmp;
		break;
	case STORE: /* Store to memory/stack */
		tmp  = convert_base(self, section_id, section_index, ll_inst, 0, dis_instructions);
		result = tmp;
		break;
	case SEX: /* Signed Extention */
		if ((ll_inst->srcA.kind == KIND_EMPTY) &&
			(ll_inst->srcB.kind == KIND_EMPTY) &&
			(ll_inst->dstA.kind == KIND_EMPTY)) {
			/* Special case for CDQE */
			ll_inst->srcB.kind = KIND_REG;
			//ll_operand->size; // Already set
		        ll_inst->srcB.operand[0].value = REG_AX;
		        ll_inst->srcB.operand[0].size = ll_inst->srcB.size;
			ll_inst->dstA.kind = KIND_REG;
			//ll_operand->size; // Already set
		        ll_inst->dstA.operand[0].value = REG_AX;
		        ll_inst->dstA.operand[0].size = ll_inst->dstA.size;
		}
		copy_operand(&ll_inst->srcB, &ll_inst->srcA);
		ll_inst->srcB.kind = KIND_EMPTY;
		tmp  = convert_base(self, section_id, section_index, ll_inst, 0, dis_instructions);
		result = tmp;
		break;
	case LIB_PHI: /* A PHI point */
		break;
	case RET: /* Special instruction for helping to print the "result local_regNNNN;" */
                /* POP -> IP=[SP]; SP=SP+4; */
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = LOAD;
		instruction->flags = 0;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_TMP1;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;

		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_STACK;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_SP;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;

		instruction->srcB.store = STORE_REG;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = REG_SP;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = ADD;
		instruction->flags = 0;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_SP;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_SP;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->srcB.store = STORE_DIRECT;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = 8;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = NOP;
		instruction->flags = 0;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_AX;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_AX;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->srcB.store = STORE_REG;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = REG_AX;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = MOV;
		instruction->flags = 0;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_IP;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_TMP1;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->srcB.store = STORE_REG;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = REG_TMP1;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		dis_instructions->instruction_number++;

		result = 0;
		break;
	case ADD:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case ADC:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SUB:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SBB:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case OR:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case XOR:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		for (n = 0; n < dis_instructions->instruction_number; n++) {
			instruction = &dis_instructions->instruction[n];
			if ((instruction->opcode == XOR) &&
				(instruction->srcA.store == STORE_REG) &&
				(instruction->srcB.store == STORE_REG) &&
				(instruction->srcA.indirect == IND_DIRECT) &&
				(instruction->srcB.indirect == IND_DIRECT) &&
				(instruction->srcA.indirect_size == instruction->srcB.indirect_size) &&
				(instruction->srcA.index == instruction->srcB.index) &&  // REG index
				(instruction->srcA.relocated == 0) &&
				(instruction->srcB.relocated == 0) &&
				(instruction->srcA.value_size == instruction->srcB.value_size) ) {
				debug_print(DEBUG_INPUT_DIS, 1, "convert: XOR self found\n");
				/* Change REG to IMM value of 0 */
				instruction->srcA.store = STORE_DIRECT;
				instruction->srcA.index = 0;
				instruction->srcB.store = STORE_DIRECT;
				instruction->srcB.index = 0;
			}
		}
		break;
	case rAND:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case NOT:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case TEST:
		if ((ll_inst->srcA.kind == KIND_EMPTY) &&
			(ll_inst->srcB.kind != KIND_EMPTY) &&
			(ll_inst->dstA.kind != KIND_EMPTY)) {
			copy_operand(&ll_inst->dstA, &ll_inst->srcA);
			ll_inst->dstA.kind = KIND_EMPTY;
		}
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case NEG:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case CMP:
		ll_inst->dstA.kind = KIND_EMPTY;
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case MUL:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case IMUL:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case DIV:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case IDIV:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case ROL:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case ROR:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case RCL:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case RCR:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SHL:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SHR:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SAL:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SAR:
		tmp  = convert_base(self, section_id, section_index, ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case LEAVE:
		/* ESP = EBP; */
		/* POP EBP -> EBP=[SP]; SP=SP+4 (+2 for word); */
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = MOV;
		instruction->flags = 0;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_SP;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_BP;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = LOAD;
		instruction->flags = 0;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_BP;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_STACK;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_SP;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->srcB.store = STORE_REG;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = REG_SP;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = ADD;
		instruction->flags = 0;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_SP;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_SP;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->srcB.store = STORE_DIRECT;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = 8;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		dis_instructions->instruction_number++;
		result = 0;
		break;
	case PUSH:
                /* PUSH -> SP=SP-4 (-2 for word); [SP]=reg; */
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = SUB;
		instruction->flags = 0; /* Do not effect flags */
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_SP;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_SP;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->srcB.store = STORE_DIRECT;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = ll_inst->srcA.size >> 3;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = STORE;
		instruction->flags = 0;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->srcA));
		instruction->srcB.store = STORE_REG;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = REG_SP;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_STACK;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_SP;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = ll_inst->srcA.size;
		dis_instructions->instruction_number++;
		result = 0;
		break;
	case POP:
                /* POP -> ES=[SP]; SP=SP+4 (+2 for word); */
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = LOAD;
		instruction->flags = 0;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_STACK;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_SP;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = ll_inst->srcA.size;
		instruction->srcB.store = STORE_REG;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = REG_SP;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = ll_inst->srcA.size;
		/* Form 2 puts the dest in the src. So correct it here */
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->dstA));
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = ADD;
		instruction->flags = 0;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_SP;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_SP;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->srcB.store = STORE_DIRECT;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = ll_inst->srcA.size >> 3;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		dis_instructions->instruction_number++;
		result = 0;
		break;
	case MOVS:
		if (ll_inst->rep == 1) {
			/* FIXME not finished */
			/* CMP ECX, 0 */
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = CMP;
			instruction->flags = 1;
			instruction->srcA.store = STORE_REG;
			instruction->srcA.indirect = IND_DIRECT;
			instruction->srcA.indirect_size = 64;
			instruction->srcA.index = REG_CX;
			instruction->srcA.relocated = 0;
			instruction->srcA.value_size = ll_inst->srcA.size;
			instruction->dstA.store = STORE_DIRECT;
			instruction->dstA.indirect = IND_DIRECT;
			instruction->dstA.indirect_size = 64;
			instruction->dstA.index = 0;
			instruction->dstA.relocated = 0;
			instruction->dstA.value_size = 32;
			instruction->srcB.store = STORE_DIRECT;
			instruction->srcB.indirect = IND_DIRECT;
			instruction->srcB.indirect_size = 64;
			instruction->srcB.index = 0;
			instruction->srcB.relocated = 0;
			instruction->srcB.value_size = ll_inst->srcA.size;
			dis_instructions->instruction_number++;

			/* IF: JZ next instruction */
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = IF;
			instruction->flags = 0;
			instruction->dstA.store = STORE_DIRECT;
			instruction->dstA.indirect = IND_DIRECT;
			instruction->dstA.indirect_size = 64;
			/* Should be to next amd64 instruction. */
			instruction->dstA.index = 0;  /* 0 is next instruction */
			instruction->dstA.relocated = 0;
			instruction->dstA.value_size = 32;
			instruction->srcA.store = STORE_DIRECT;
			instruction->srcA.indirect = IND_DIRECT;
			instruction->srcA.indirect_size = 64;
			instruction->srcA.index = 4; /* CONDITION JZ */
			instruction->srcA.relocated = 0;
			instruction->srcA.value_size = 32;
			dis_instructions->instruction_number++;

			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
			/* CX-- */
			instruction->opcode = SUB;
			instruction->flags = 0;
			instruction->srcA.store = STORE_DIRECT;
			instruction->srcA.indirect = IND_DIRECT;
			instruction->srcA.indirect_size = 64;
			instruction->srcA.index = 1;
			instruction->srcA.relocated = 0;
			instruction->srcA.value_size = ll_inst->srcA.size;
			instruction->dstA.store = STORE_REG;
			instruction->dstA.indirect = IND_DIRECT;
			instruction->dstA.indirect_size = 64;
			instruction->dstA.index = REG_CX;
			instruction->dstA.relocated = 0;
			instruction->dstA.value_size = ll_inst->srcA.size;
			instruction->srcB.store = STORE_REG;
			instruction->srcB.indirect = IND_DIRECT;
			instruction->srcB.indirect_size = 64;
			instruction->srcB.index = REG_CX;
			instruction->srcB.relocated = 0;
			instruction->srcB.value_size = ll_inst->srcA.size;
			dis_instructions->instruction_number++;
		}
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = LOAD;
		instruction->flags = 0;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->srcA));
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->srcB));
		convert_operand(self, section_id, section_index, ll_inst->address, &(operand_reg_tmp2), 0, &(instruction->dstA));
		/* Force indirect */
		instruction->srcA.indirect = IND_MEM;
		instruction->srcA.indirect_size = ll_inst->srcA.size;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = STORE;
		instruction->flags = 0;
		convert_operand(self, section_id, section_index, ll_inst->address, &(operand_reg_tmp2), 0, &(instruction->srcA));
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->dstA), 0, &(instruction->srcB));
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->dstA), 0, &(instruction->dstA));
		/* Force indirect */
		instruction->dstA.indirect = IND_MEM;
		instruction->dstA.indirect_size = ll_inst->dstA.size;
		dis_instructions->instruction_number++;
		/* FIXME: Need to use direction flag */

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = ADD;
		instruction->flags = 0;
		instruction->srcA.store = STORE_DIRECT;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = ll_inst->srcA.size >> 3;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = ll_inst->srcA.size;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->dstA));
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->srcB));
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = ADD;
		instruction->flags = 0;
		instruction->srcA.store = STORE_DIRECT;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = ll_inst->dstA.size >> 3;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = ll_inst->dstA.size;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->dstA), 0, &(instruction->dstA));
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->dstA), 0, &(instruction->srcB));
		dis_instructions->instruction_number++;

		if (ll_inst->rep == 1) {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = JMP;
			instruction->flags = 0;
			instruction->srcA.store = STORE_DIRECT;
			instruction->srcA.indirect = IND_DIRECT;
			instruction->srcA.indirect_size = 64;
			/* JMP back to beginning of this amd64 instruction and also the rep byte */
			instruction->srcA.index = -(dis_instructions->bytes_used); 
			instruction->srcA.relocated = 0;
			instruction->srcA.value_size = 64;
			instruction->dstA.store = STORE_REG;
			instruction->dstA.indirect = IND_DIRECT;
			instruction->dstA.indirect_size = 64;
			instruction->dstA.index = REG_IP;
			instruction->dstA.relocated = 0;
			instruction->dstA.value_size = 64;
			dis_instructions->instruction_number++;
		}
		result = 0;
		break;
	case IMULD:
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = SEX;
		instruction->flags = 0;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->srcA));
		instruction->srcA.value_size = 32;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->dstA));
		instruction->dstA.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = SEX;
		instruction->flags = 0;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 32;
		instruction->srcA.index = REG_AX;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 32;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_AX;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = MUL;
		instruction->flags = 1;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_AX;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->srcB));
		instruction->srcB.value_size = 64;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_AX;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = SAR;
		instruction->flags = 0;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_AX;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->srcB.store = STORE_DIRECT;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = 32;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->dstA));
		instruction->dstA.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = TRUNC;
		instruction->flags = 0;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_AX;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 32;
		instruction->dstA.index = REG_AX;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 32;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = TRUNC;
		instruction->flags = 0;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->srcA));
		instruction->srcA.value_size = 64;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->dstA));
		instruction->dstA.value_size = 32;
		dis_instructions->instruction_number++;
		result = 0;
		break;

	case MULD:
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = MOV;
		instruction->flags = 0;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->srcA));
		instruction->srcA.value_size = 32;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->dstA));
		instruction->dstA.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = MOV;
		instruction->flags = 0;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 32;
		instruction->srcA.index = REG_AX;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 32;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_AX;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = MUL;
		instruction->flags = 1;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_AX;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->srcB));
		instruction->srcB.value_size = 64;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 64;
		instruction->dstA.index = REG_AX;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = SAR;
		instruction->flags = 0;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_AX;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->srcB.store = STORE_DIRECT;
		instruction->srcB.indirect = IND_DIRECT;
		instruction->srcB.indirect_size = 64;
		instruction->srcB.index = 32;
		instruction->srcB.relocated = 0;
		instruction->srcB.value_size = 64;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->dstA));
		instruction->dstA.value_size = 64;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = TRUNC;
		instruction->flags = 0;
		instruction->srcA.store = STORE_REG;
		instruction->srcA.indirect = IND_DIRECT;
		instruction->srcA.indirect_size = 64;
		instruction->srcA.index = REG_AX;
		instruction->srcA.relocated = 0;
		instruction->srcA.value_size = 64;
		instruction->dstA.store = STORE_REG;
		instruction->dstA.indirect = IND_DIRECT;
		instruction->dstA.indirect_size = 32;
		instruction->dstA.index = REG_AX;
		instruction->dstA.relocated = 0;
		instruction->dstA.value_size = 32;
		dis_instructions->instruction_number++;

		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];
		instruction->opcode = TRUNC;
		instruction->flags = 0;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->srcA));
		instruction->srcA.value_size = 64;
		convert_operand(self, section_id, section_index, ll_inst->address, &(ll_inst->srcA), 0, &(instruction->dstA));
		instruction->dstA.value_size = 32;
		dis_instructions->instruction_number++;
		result = 0;
		break;

	default:
		debug_print(DEBUG_INPUT_DIS, 1, "convert: Unrecognised opcode %x\n", ll_inst->opcode);
		result = 1;
		break;
	}
	debug_print(DEBUG_INPUT_DIS, 1, "disassemble_amd64:end inst_number = 0x%x\n", dis_instructions->instruction_number);
#if 0
	for (n = 0; n < dis_instructions->instruction_number; n++) {
		instruction = &dis_instructions->instruction[n];
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: opcode = 0x%x:%s\n",
			n, instruction->opcode, dis_opcode_table[instruction->opcode]);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: flags = 0x%x\n", n, instruction->flags);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.store = 0x%x\n", n, instruction->srcA.store);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.indirect = 0x%x\n", n, instruction->srcA.indirect);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.indirect_size = 0x%x\n", n, instruction->srcA.indirect_size);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.index = 0x%"PRIx64"\n", n, instruction->srcA.index);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.relocated = 0x%x\n", n, instruction->srcA.relocated);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.value_size = 0x%x\n", n, instruction->srcA.value_size);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.store = 0x%x\n", n, instruction->srcB.store);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.indirect = 0x%x\n", n, instruction->srcB.indirect);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.indirect_size = 0x%x\n", n, instruction->srcB.indirect_size);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.index = 0x%"PRIx64"\n", n, instruction->srcB.index);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.relocated = 0x%x\n", n, instruction->srcB.relocated);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.value_size = 0x%x\n", n, instruction->srcB.value_size);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.store = 0x%x\n", n, instruction->dstA.store);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.indirect = 0x%x\n", n, instruction->dstA.indirect);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.indirect_size = 0x%x\n", n, instruction->dstA.indirect_size);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.store = 0x%x\n", n, instruction->dstA.store);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.index = 0x%"PRIx64"\n", n, instruction->dstA.index);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.value_size = 0x%x\n", n, instruction->dstA.value_size);
	}
#endif
	return result;
}
