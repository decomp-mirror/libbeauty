/*
 *  Copyright (C) 2004  The revenge Team
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
 *
 *
 * 11-9-2004 Initial work.
 *   Copyright (C) 2004 James Courtier-Dutton James@superbug.co.uk
 * 10-11-2007 Updates.
 *   Copyright (C) 2007 James Courtier-Dutton James@superbug.co.uk
 * 29-03-2009 Updates.
 *   Copyright (C) 2009 James Courtier-Dutton James@superbug.co.uk
 * 05-05-2013 Updates.
 *   Copyright (C) 2004-2013 James Courtier-Dutton James@superbug.co.uk
 */

/* Intel ia32 instruction format: -
 Instruction-Prefixes (Up to four prefixes of 1-byte each. [optional] )
 Opcode (1-, 2-, or 3-byte opcode)
 ModR/M (1 byte [if required] )
 SIB (Scale-Index-Base:1 byte [if required] )
 Displacement (Address displacement of 1, 2, or 4 bytes or none)
 Immediate (Immediate data of 1, 2, or 4 bytes or none)

 Naming convention taked from Intel Instruction set manual,
 Appendix A. 25366713.pdf
*/

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include <rev.h>
#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>
#include "instruction_low_level.h"
#include "decode_inst.h"
#include <dis.h>
#include <convert_ll_inst_to_rtl.h>
#include <execinfo.h>

#define EIP_START 0x40000000

struct dis_instructions_s dis_instructions;
uint8_t *data;
size_t data_size = 0;
uint8_t *rodata;
size_t rodata_size = 0;
char *dis_flags_table[] = { " ", "f" };
uint64_t inst_log = 1;	/* Pointer to the current free instruction log entry. */

/* debug: 0 = no debug output. >= 1 is more debug output */
int debug_dis64 = 0;
int debug_input_bfd = 0;
int debug_input_dis = 0;
int debug_exe = 0;
int debug_analyse = 0;
int debug_analyse_paths = 0;
int debug_analyse_phi = 0;
int debug_analyse_tip = 0;
int debug_output = 0;
int debug_output_llvm = 0;
int debug_input_header = 0;

void setLogLevel()
{
	if (getenv("ENABLE_DEBUG_DIS64"))
		debug_dis64 = 1;
	if (getenv("ENABLE_DEBUG_INPUT_BFD"))
		debug_input_bfd = 1;
	if (getenv("ENABLE_DEBUG_INPUT_DIS"))
		debug_input_dis = 1;
	if (getenv("ENABLE_DEBUG_EXE"))
		debug_exe = 1;
	if (getenv("ENABLE_DEBUG_ANALYSE"))
		debug_analyse = 1;
	if (getenv("ENABLE_DEBUG_ANALYSE_PATHS"))
		debug_analyse_paths = 1;
	if (getenv("ENABLE_DEBUG_ANALYSE_PHI"))
		debug_analyse_phi = 1;
	if (getenv("ENABLE_DEBUG_ANALYSE_TIP"))
		debug_analyse_tip = 1;
	if (getenv("ENABLE_DEBUG_OUTPUT"))
		debug_output = 1;
	if (getenv("ENABLE_DEBUG_OUTPUT_LLVM"))
		debug_output_llvm = 1;
	if (getenv("ENABLE_DEBUG_INPUT_HEADER"))
		debug_input_header = 1;
}

void dbg_print(const char* file, int line, const char* func, int module, int level, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	char *file2 = file;
	if (strlen(file) > 30) {
		file2 = &file[strlen(file)-30];
	}
	switch (module) {
	case DEBUG_MAIN:
		if (level <= debug_dis64) {
			dprintf(STDERR_FILENO, "DEBUG_MAIN,0x%x ...%s:%d %s(): ", level, file2, line, func);
			vdprintf(STDERR_FILENO, format, ap);
		}
		break;
	case DEBUG_INPUT_BFD:
		if (level <= debug_input_bfd) {
			dprintf(STDERR_FILENO, "DEBUG_INPUT_BFD,0x%x ...%s:%d %s(): ", level, file2, line, func);
			vdprintf(STDERR_FILENO, format, ap);
		}
		break;
	case DEBUG_INPUT_DIS:
		if (level <= debug_input_dis) {
			dprintf(STDERR_FILENO, "DEBUG_INPUT_DIS,0x%x ...%s:%d %s(): ", level, file2, line, func);
			vdprintf(STDERR_FILENO, format, ap);
		}
		break;
	case DEBUG_EXE:
		if (level <= debug_exe) {
			dprintf(STDERR_FILENO, "DEBUG_EXE,0x%x ...%s:%d %s(): ", level, file2, line, func);
			vdprintf(STDERR_FILENO, format, ap);
		}
		break;
	case DEBUG_ANALYSE:
		if (level <= debug_analyse) {
			dprintf(STDERR_FILENO, "DEBUG_ANALYSE,0x%x ...%s:%d %s(): ", level, file2, line, func);
			vdprintf(STDERR_FILENO, format, ap);
		}
		break;
	case DEBUG_ANALYSE_PATHS:
		if (level <= debug_analyse_paths) {
			dprintf(STDERR_FILENO, "DEBUG_ANALYSE_PATHS,0x%x ...%s:%d %s(): ", level, file2, line, func);
			vdprintf(STDERR_FILENO, format, ap);
		}
		break;
	case DEBUG_ANALYSE_PHI:
		if (level <= debug_analyse_phi) {
			dprintf(STDERR_FILENO, "DEBUG_ANALYSE_PHI,0x%x ...%s:%d %s(): ", level, file2, line, func);
			vdprintf(STDERR_FILENO, format, ap);
		}
		break;
	case DEBUG_ANALYSE_TIP:
		if (level <= debug_analyse_tip) {
			dprintf(STDERR_FILENO, "DEBUG_ANALYSE_TIP,0x%x ...%s:%d %s(): ", level, file2, line, func);
			vdprintf(STDERR_FILENO, format, ap);
		}
		break;
	case DEBUG_OUTPUT:
		if (level <= debug_output) {
			dprintf(STDERR_FILENO, "DEBUG_OUTPUT,0x%x ...%s:%d %s(): ", level, file2, line, func);
			vdprintf(STDERR_FILENO, format, ap);
		}
		break;
	case DEBUG_OUTPUT_LLVM:
		if (level <= debug_output_llvm) {
			dprintf(STDERR_FILENO, "DEBUG_OUTPUT_LLVM,0x%x ...%s:%d %s(): ", level, file2, line, func);
			vdprintf(STDERR_FILENO, format, ap);
		}
		break;
	case DEBUG_INPUT_HEADER:
		if (level <= debug_input_header) {
			dprintf(STDERR_FILENO, "DEBUG_INPUT_HEADER,0x%x ...%s:%d %s(): ", level, file2, line, func);
			vdprintf(STDERR_FILENO, format, ap);
		}
		break;
	default:
		printf("DEBUG Failed: Module 0x%x\n", module);
		exit(1);
		break;
	}
	va_end(ap);
}

/* Params order:
 * int test30(int64_t param_reg0040, int64_t param_reg0038, int64_t param_reg0018, int64_t param_reg0010, int64_t param_reg0050, int64_t param_reg0058, int64_t param_stack0008, int64_t param_stack0010)
 */

/* Used to store details of each instruction.
 * Linked by prev/next pointers
 * so that a single list can store all program flow.
 */
// struct inst_log_entry_s inst_log_entry[INST_LOG_ENTRY_SIZE];
// int search_back_seen[INST_LOG_ENTRY_SIZE];

/* Used to keep record of where we have been before.
 * Used to identify program flow, branches, and joins.
 */
int memory_used[MEMORY_USED_SIZE];
/* Used to keep a non bfd version of the relocation entries */
int memory_relocation[MEMORY_USED_SIZE];

#if 0
int disassemble(struct self_s *self, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t offset) {
	int tmp;
	tmp = disassemble_amd64(self->handle_void, dis_instructions, base_address, offset);
	return tmp;
}
#endif

int disassemble(struct self_s *self, int section_id, int section_index, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t buffer_size, uint64_t offset) {
	struct instruction_low_level_s *ll_inst = (struct instruction_low_level_s *)self->ll_inst;
	int tmp = 0;
	int m;
	LLVMDecodeAsmX86_64Ref da = self->decode_asm;

	ll_inst->opcode = 0;
	ll_inst->srcA.kind = KIND_EMPTY;
	ll_inst->srcB.kind = KIND_EMPTY;
	ll_inst->dstA.kind = KIND_EMPTY;
	tmp = LLVMInstructionDecodeAsmX86_64(da, base_address,
		buffer_size, offset,
		ll_inst);
	if (tmp) {
		printf("LLVMInstructionDecodeAsmX86_64 failed. offset = 0x%"PRIx64"\n", offset);
		exit(1);
	}
	tmp = LLVMPrintInstructionDecodeAsmX86_64(da, ll_inst);
	if (tmp) {
		printf("LLVMPrintInstructionDecodeAsmX86_64() failed. offset = 0x%"PRIx64"\n", offset);
		exit(1);
	}
	tmp = convert_ll_inst_to_rtl(self, section_id, section_index, ll_inst, dis_instructions);
	if (tmp) {
		printf("convert_ll_inst_to_rtl() failed. offset = 0x%"PRIx64"\n", offset);
		exit(1);
	}
	if (ll_inst->octets != dis_instructions->bytes_used) {
		printf("octets mismatch 0x%x:0x%x\n", ll_inst->octets, dis_instructions->bytes_used);
		exit(1);
	}
	for (m = 0; m < dis_instructions->instruction_number; m++) {
		tmp = print_inst(self, &(dis_instructions->instruction[m]), m + 0x10000000, NULL);
	}
	return tmp;
}

int print_dis_instructions(struct self_s *self)
{
	int n;
	struct instruction_s *instruction;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;

	debug_print(DEBUG_MAIN, 1, "print_dis_instructions:\n");
	for (n = 1; n < inst_log; n++) {
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		if (print_inst(self, instruction, n, NULL))
			return 1;
		debug_print(DEBUG_MAIN, 1, "start_address:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.start_address,
			inst_log1->value2.start_address,
			inst_log1->value3.start_address);
		debug_print(DEBUG_MAIN, 1, "init:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.init_value,
			inst_log1->value2.init_value,
			inst_log1->value3.init_value);
		debug_print(DEBUG_MAIN, 1, "offset:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.offset_value,
			inst_log1->value2.offset_value,
			inst_log1->value3.offset_value);
		debug_print(DEBUG_MAIN, 1, "indirect init:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.indirect_init_value,
			inst_log1->value2.indirect_init_value,
			inst_log1->value3.indirect_init_value);
		debug_print(DEBUG_MAIN, 1, "indirect offset:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.indirect_offset_value,
			inst_log1->value2.indirect_offset_value,
			inst_log1->value3.indirect_offset_value);
		debug_print(DEBUG_MAIN, 1, "value_type:0x%x, 0x%x -> 0x%x\n",
			inst_log1->value1.value_type,
			inst_log1->value2.value_type,
			inst_log1->value3.value_type);
		debug_print(DEBUG_MAIN, 1, "value_scope:0x%x, 0x%x -> 0x%x\n",
			inst_log1->value1.value_scope,
			inst_log1->value2.value_scope,
			inst_log1->value3.value_scope);
		debug_print(DEBUG_MAIN, 1, "value_id:0x%"PRIx64", 0x%"PRIx64" -> 0x%"PRIx64"\n",
			inst_log1->value1.value_id,
			inst_log1->value2.value_id,
			inst_log1->value3.value_id);
		if (inst_log1->prev_size > 0) {
			int n;
			for (n = 0; n < inst_log1->prev_size; n++) {
				debug_print(DEBUG_MAIN, 1, "inst_prev:%d:0x%04x\n",
					n,
					inst_log1->prev[n]);
			}
		}
		if (inst_log1->next_size > 0) {
			int n;
			for (n = 0; n < inst_log1->next_size; n++) {
				debug_print(DEBUG_MAIN, 1, "inst_next:%d:0x%04x\n",
					n,
					inst_log1->next[n]);
			}
		}
	}
	return 0;
}


/* Eventually this will be built from standard C .h or C++ .hpp files */
	int external_functions_init(struct self_s *self)
{
	/* RDI, RSI, RDX, RCX, R8, R9, ... */
	self->external_function_reg_order_size = 6;
	self->external_function_reg_order =
		calloc(6, sizeof(int));
	self->external_function_reg_order[0] = REG_DI;
	self->external_function_reg_order[1] = REG_SI;
	self->external_function_reg_order[2] = REG_DX;
	self->external_function_reg_order[3] = REG_CX;
	self->external_function_reg_order[4] = REG_08;
	self->external_function_reg_order[5] = REG_09;
	self->external_functions_size = 0;
#if 0
	self->external_functions_size = 12;
	self->external_functions =
		calloc(12, sizeof(struct external_function_s));
	self->external_functions[1].function_name = "printf";
	self->external_functions[1].return_type = 1;
	self->external_functions[1].fields_size = 2;
	self->external_functions[1].field_type =
		calloc(2, sizeof(int));
	self->external_functions[1].field_type[0] = 3; // char *
	self->external_functions[1].field_type[1] = 4; // ... 

	self->external_functions[2].function_name = "putchar";
	self->external_functions[2].return_type = 1;
	self->external_functions[2].fields_size = 1;
	self->external_functions[2].field_type =
		calloc(1, sizeof(int));
	self->external_functions[2].field_type[0] = 1; // int

	self->external_functions[3].function_name = "i2c_transfer";
	self->external_functions[3].return_type = 1;
	self->external_functions[3].fields_size = 3;
	self->external_functions[3].field_type =
		calloc(3, sizeof(int));
	self->external_functions[3].field_type[0] = 7; // int8_t *
	self->external_functions[3].field_type[1] = 7; // int8_t *
	self->external_functions[3].field_type[2] = 1; // int

	self->external_functions[4].function_name = "msleep";
	self->external_functions[4].return_type = 1;
	self->external_functions[4].fields_size = 1;
	self->external_functions[4].field_type =
		calloc(1, sizeof(int));
	self->external_functions[4].field_type[0] = 1; // int

	self->external_functions[5].function_name = "printk";
	self->external_functions[5].return_type = 1;
	self->external_functions[5].fields_size = 2;
	self->external_functions[5].field_type =
		calloc(2, sizeof(int));
	self->external_functions[5].field_type[0] = 3; // char *
	self->external_functions[5].field_type[1] = 4; // ... 

	self->external_functions[6].function_name = "kfree_wrap";
	self->external_functions[6].return_type = 1;
	self->external_functions[6].fields_size = 1;
	self->external_functions[6].field_type =
		calloc(1, sizeof(int));
	self->external_functions[6].field_type[0] = 7; // int8_t *

	self->external_functions[7].function_name = "__const_udelay";
	self->external_functions[7].return_type = 1;
	self->external_functions[7].fields_size = 1;
	self->external_functions[7].field_type =
		calloc(1, sizeof(int));
	self->external_functions[7].field_type[0] = 8; // uint64_t

	self->external_functions[8].function_name = "kzalloc_wrap";
	self->external_functions[8].return_type = 7;
	self->external_functions[8].fields_size = 1;
	self->external_functions[8].field_type =
		calloc(1, sizeof(int));
	self->external_functions[8].field_type[0] = 1; // int

	self->external_functions[9].function_name = "kmalloc_wrap";
	self->external_functions[9].return_type = 7;
	self->external_functions[9].fields_size = 1;
	self->external_functions[9].field_type =
		calloc(1, sizeof(int));
	self->external_functions[9].field_type[0] = 1; // int

	self->external_functions[10].function_name = "get_random_bytes";
	self->external_functions[10].return_type = 1;
	self->external_functions[10].fields_size = 2;
	self->external_functions[10].field_type =
		calloc(2, sizeof(int));
	self->external_functions[10].field_type[0] = 3; // char *
	self->external_functions[10].field_type[1] = 1; // int

	self->external_functions[11].function_name = "memcpy";
	self->external_functions[11].return_type = 1;
	self->external_functions[11].fields_size = 3;
	self->external_functions[11].field_type =
		calloc(3, sizeof(int));
	self->external_functions[11].field_type[0] = 7; // int8_t *
	self->external_functions[11].field_type[1] = 7; // int8_t *
	self->external_functions[11].field_type[2] = 1; // int
#endif
	self->simple_field_types_size = 9;
	self->simple_field_types =
		calloc(9, sizeof(struct simple_field_type_s));
	self->simple_field_types[1].integer1 = 1;
	self->simple_field_types[1].bits = 32;
	self->simple_field_types[2].char1 = 1;
	self->simple_field_types[2].bits = 8;
	self->simple_field_types[3].pointer1 = 2;
	self->simple_field_types[3].variable_def = 1;
	self->simple_field_types[4].variable = 1;
	self->simple_field_types[5].pointer1 = 2;
	self->simple_field_types[6].integer1 = 1;
	self->simple_field_types[6].bits = 8;
	self->simple_field_types[7].pointer1 = 6;
	self->simple_field_types[8].integer1 = 1;
	self->simple_field_types[8].bits = 64;

	self->struct_types_size = 0;
	self->struct_type_size = 0;

	return 0;
}


int ram_init(struct memory_s *memory_data)
{
	return 0;
}

int reg_init(struct memory_s *memory_reg)
{
	/* esp */
	memory_reg[0].section_id = 0;
	memory_reg[0].section_index = 0;
	memory_reg[0].start_address = REG_SP;
	/* 4 bytes */
	memory_reg[0].length = 8;
	/* 1 - Known */
	memory_reg[0].init_value_type = 1;
	/* Initial value when first accessed */
	memory_reg[0].init_value = 0x10000;
	/* No offset yet */
	memory_reg[0].offset_value = 0;
	/* 0 - unknown,
	 * 1 - unsigned,
	 * 2 - signed,
	 * 3 - pointer,
	 * 4 - Instruction,
	 * 5 - Instruction pointer(EIP),
	 * 6 - Stack pointer.
	 */
	memory_reg[0].value_type = 6;
	memory_reg[0].value_unsigned = 0;
	memory_reg[0].value_signed = 0;
	memory_reg[0].value_instruction = 0;
	memory_reg[0].value_pointer = 1;
	memory_reg[0].value_normal = 0;
	/* Index into the various structure tables */
	memory_reg[0].value_struct = 0;
	/* last_accessed_from_instruction_at_memory_location */
	memory_reg[0].ref_memory = 0;
	memory_reg[0].ref_log = 0;
	/* value_scope: 0 - unknown, 1 - Param, 2 - Local, 3 - Mem */
	memory_reg[0].value_scope = 2;
	/* Each time a new value is assigned, this value_id increases */
	memory_reg[0].value_id = 1;
	/* valid: 0 - Entry Not used yet, 1 - Entry Used */
	memory_reg[0].valid = 1;

	/* ebp */
	memory_reg[1].section_id = 0;
	memory_reg[1].section_index = 0;
	memory_reg[1].start_address = REG_BP;
	/* 4 bytes */
	memory_reg[1].length = 8;
	/* 1 - Known */
	memory_reg[1].init_value_type = 1;
	/* Initial value when first accessed */
	memory_reg[1].init_value = 0x20000;
	/* No offset yet */
	memory_reg[1].offset_value = 0;
	/* 0 - unknown,
	 * 1 - unsigned,
	 * 2 - signed,
	 * 3 - pointer,
	 * 4 - Instruction,
	 * 5 - Instruction pointer(EIP),
	 * 6 - Stack pointer.
	 */
	memory_reg[1].value_type = 6;
	memory_reg[1].value_unsigned = 0;
	memory_reg[1].value_signed = 0;
	memory_reg[1].value_instruction = 0;
	memory_reg[1].value_pointer = 1;
	memory_reg[1].value_normal = 0;
	/* Index into the various structure tables */
	memory_reg[1].value_struct = 0;
	memory_reg[1].ref_memory = 0;
	memory_reg[1].ref_log = 0;
	/* value_scope: 0 - unknown, 1 - Param, 2 - Local, 3 - Mem */
	memory_reg[1].value_scope = 2;
	/* Each time a new value is assigned, this value_id increases */
	memory_reg[1].value_id = 2;
	/* valid: 0 - entry Not used yet, 1 - entry Used */
	memory_reg[1].valid = 1;

	/* eip */
	memory_reg[2].section_id = 0;
	memory_reg[2].section_index = 0;
	memory_reg[2].start_address = REG_IP;
	/* 4 bytes */
	memory_reg[2].length = 8;
	/* 1 - Known */
	memory_reg[2].init_value_type = 1;
	/* Initial value when first accessed */
	memory_reg[2].init_value = EIP_START;
	/* No offset yet */
	memory_reg[2].offset_value = 0;
	/* 0 - unknown,
	 * 1 - unsigned,
	 * 2 - signed,
	 * 3 - pointer,
	 * 4 - Instruction,
	 * 5 - Instruction pointer(EIP),
	 * 6 - Stack pointer.
	 */
	memory_reg[2].value_type = 5;
	memory_reg[2].value_type = 6;
	memory_reg[2].value_unsigned = 0;
	memory_reg[2].value_signed = 0;
	memory_reg[2].value_instruction = 0;
	memory_reg[2].value_pointer = 1;
	memory_reg[2].value_normal = 0;
	/* Index into the various structure tables */
	memory_reg[2].value_struct = 0;
	memory_reg[2].ref_memory = 0;
	memory_reg[2].ref_log = 0;
	/* value_scope: 0 - unknown, 1 - Param, 2 - Local, 3 - Mem */
	memory_reg[2].value_scope = 3;
	/* Each time a new value is assigned, this value_id increases */
	memory_reg[2].value_id = 0;
	/* valid: 0 - entry Not used yet, 1 - entry Used */
	memory_reg[2].valid = 1;
	return 0;
}

int stack_init(struct memory_s *memory_stack)
{
	int n = 0;
	/* eip on the stack */
	memory_stack[n].start_address = 0x10000;
	/* 4 bytes */
	memory_stack[n].length = 8;
	/* 1 - Known */
	memory_stack[n].init_value_type = 1;
	/* Initial value when first accessed */
	memory_stack[n].init_value = 0x0;
	/* No offset yet */
	memory_stack[n].offset_value = 0;
	/* 0 - unknown,
	 * 1 - unsigned,
	 * 2 - signed,
	 * 3 - pointer,
	 * 4 - Instruction,
	 * 5 - Instruction pointer(EIP),
	 * 6 - Stack pointer.
	 */
	memory_stack[n].value_type = 5;
	memory_stack[n].value_unsigned = 0;
	memory_stack[n].value_signed = 0;
	memory_stack[n].value_instruction = 0;
	memory_stack[n].value_pointer = 1;
	memory_stack[n].value_normal = 0;
	/* Index into the various structure tables */
	memory_stack[n].value_struct = 0;
	memory_stack[n].ref_memory = 0;
	memory_stack[n].ref_log = 0;
	/* value_scope: 0 - unknown, 1 - Param, 2 - Local, 3 - Mem */
	memory_stack[n].value_scope = 2;
	/* Each time a new value is assigned, this value_id increases */
	memory_stack[n].value_id = 3;
	/* valid: 0 - Not used yet, 1 - Used */
	memory_stack[n].valid = 1;
	n++;

#if 0
	/* Param1 */
	memory_stack[n].start_address = 0x10004;
	/* 4 bytes */
	memory_stack[n].length = 4;
	/* 1 - Known */
	memory_stack[n].init_value_type = 1;
	/* Initial value when first accessed */
	memory_stack[n].init_value = 0x321;
	/* No offset yet */
	memory_stack[n].offset_value = 0;
	/* 0 - unknown,
	 * 1 - unsigned,
	 * 2 - signed,
	 * 3 - pointer,
	 * 4 - Instruction,
	 * 5 - Instruction pointer(EIP),
	 * 6 - Stack pointer.
	 */
	memory_stack[n].value_type = 2;
	memory_stack[n].ref_memory = 0;
	memory_stack[n].ref_log = 0;
	/* value_scope: 0 - unknown, 1 - Param, 2 - Local, 3 - Mem */
	memory_stack[n].value_scope = 0;
	/* Each time a new value is assigned, this value_id increases */
	memory_stack[n].value_id = 0;
	/* valid: 0 - Not used yet, 1 - Used */
	memory_stack[n].valid = 1;
	n++;
#endif
	for (;n < MEMORY_STACK_SIZE; n++) {
		memory_stack[n].valid = 0;
	}
	return 0;
}

int print_mem(struct memory_s *memory, int location) {
	debug_print(DEBUG_MAIN, 1, "start_address:0x%"PRIx64"\n",
		memory[location].start_address);
	debug_print(DEBUG_MAIN, 1, "length:0x%x\n",
		memory[location].length);
	debug_print(DEBUG_MAIN, 1, "init_value_type:0x%x\n",
		memory[location].init_value_type);
	debug_print(DEBUG_MAIN, 1, "init:0x%"PRIx64"\n",
		memory[location].init_value);
	debug_print(DEBUG_MAIN, 1, "offset:0x%"PRIx64"\n",
		memory[location].offset_value);
	debug_print(DEBUG_MAIN, 1, "indirect_init:0x%"PRIx64"\n",
		memory[location].indirect_init_value);
	debug_print(DEBUG_MAIN, 1, "indirect_offset:0x%"PRIx64"\n",
		memory[location].indirect_offset_value);
	debug_print(DEBUG_MAIN, 1, "value_type:0x%x\n",
		memory[location].value_type);
	debug_print(DEBUG_MAIN, 1, "ref_memory:0x%"PRIx32"\n",
		memory[location].ref_memory);
	debug_print(DEBUG_MAIN, 1, "ref_log:0x%"PRIx32"\n",
		memory[location].ref_log);
	debug_print(DEBUG_MAIN, 1, "value_scope:0x%x\n",
		memory[location].value_scope);
	debug_print(DEBUG_MAIN, 1, "value_id:0x%"PRIx64"\n",
		memory[location].value_id);
	debug_print(DEBUG_MAIN, 1, "valid:0x%"PRIx64"\n",
		memory[location].valid);
	return 0;
}

int external_entry_points_init(struct external_entry_point_s *external_entry_points, int offset, void *handle_void)
{
	int tmp;
	int n;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;

	tmp = external_entry_points_init_bfl(external_entry_points, offset, handle_void);
	for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
		if (external_entry_points[n].valid != 0) {
			debug_print(DEBUG_MAIN, 1, "init external entry point 0x%x\n",
				n);
			external_entry_points[n].process_state.memory_text =
				calloc(MEMORY_TEXT_SIZE, sizeof(struct memory_s));
			external_entry_points[n].process_state.memory_text_size = MEMORY_TEXT_SIZE;
			external_entry_points[n].process_state.memory_stack =
				calloc(MEMORY_STACK_SIZE, sizeof(struct memory_s));
			external_entry_points[n].process_state.memory_stack_size = MEMORY_STACK_SIZE;
			external_entry_points[n].process_state.memory_reg =
				calloc(MEMORY_REG_SIZE, sizeof(struct memory_s));
			external_entry_points[n].process_state.memory_reg_size = MEMORY_REG_SIZE;
			external_entry_points[n].process_state.memory_data =
				calloc(MEMORY_DATA_SIZE, sizeof(struct memory_s));
			external_entry_points[n].process_state.memory_data_size = MEMORY_DATA_SIZE;
			external_entry_points[n].process_state.memory_used =
				calloc(MEMORY_USED_SIZE, sizeof(int));
			external_entry_points[n].process_state.memory_used_size = MEMORY_USED_SIZE;
			//memory_text = external_entry_points[n].process_state.memory_text;
			memory_stack = external_entry_points[n].process_state.memory_stack;
			memory_reg = external_entry_points[n].process_state.memory_reg;
			memory_data = external_entry_points[n].process_state.memory_data;
			//memory_used = external_entry_points[n].process_state.memory_used;

			ram_init(memory_data);
			reg_init(memory_reg);
			stack_init(memory_stack);
			/* Set EIP entry point equal to symbol table entry point */
			//memory_reg[2].init_value = EIP_START;
			memory_reg[2].section_id = external_entry_points[n].section_id;
			memory_reg[2].section_index = external_entry_points[n].section_index;
			memory_reg[2].offset_value = external_entry_points[n].value;

			print_mem(memory_reg, 1);
			external_entry_points[n].params_reg_ordered =
				calloc(REG_PARAMS_ORDER_MAX, sizeof(int));
		}
	}
	return tmp;
}

int analyse_memory_log(struct self_s *self)
{
	uint64_t l, m, n;
	for (l = 0; l < self->sections_size; l++) {
		debug_print(DEBUG_MAIN, 1, "Scanning section 0x%lx\n", l);
		if (self->sections[l].memory_log_size > 0) {
			debug_print(DEBUG_MAIN, 1, "Processing section 0x%lx, content_size 0x%lx\n",
					l,
					self->sections[l].content_size);

			self->sections[l].memory_struct = calloc(self->sections[l].content_size, sizeof(struct memory_struct_s));
			self->sections[l].memory_struct_size = self->sections[l].content_size;

			for (m = 0; m < self->sections[l].memory_log_size; m++) {
				debug_print(DEBUG_MAIN, 1, "memory_log_size = 0x%lx of 0x%lx\n", m, self->sections[l].memory_log_size);
				if ((self->sections[l].memory_log[m].type == 1) ||
						(self->sections[l].memory_log[m].type == 2) ||
						(self->sections[l].memory_log[m].type == 3)) {
					debug_print(DEBUG_MAIN, 1, "Processing GLOBAL: Section:0x%lx Addr:0x%lx size:0x%lx\n",
							l,
							self->sections[l].memory_log[m].address,
							self->sections[l].memory_log[m].length);
					uint64_t offset = self->sections[l].memory_log[m].address;
					debug_print(DEBUG_MAIN, 1, "offset = 0x%lx\n", offset);
					if (self->sections[l].memory_struct[offset].sizes_size == 0) {
						self->sections[l].memory_struct[offset].sizes = calloc(1, sizeof(uint64_t));
						self->sections[l].memory_struct[offset].sizes_type = calloc(1, sizeof(uint64_t));
						self->sections[l].memory_struct[offset].log_index = calloc(1, sizeof(uint64_t));
						self->sections[l].memory_struct[offset].sizes[0] = self->sections[l].memory_log[m].length;
						self->sections[l].memory_struct[offset].sizes_type[0] = self->sections[l].memory_log[m].type;
						self->sections[l].memory_struct[offset].log_index[0] = m;
						self->sections[l].memory_struct[offset].sizes_size = 1;
						self->sections[l].memory_struct[offset].limit_low = offset;
						self->sections[l].memory_struct[offset].limit_high =
								offset + self->sections[l].memory_log[m].length;
						self->sections[l].memory_struct[offset].value_index = 0;
						self->sections[l].memory_struct[offset].valid = 1;
					} else {
						int found = 0;
						for (n = 0; n < self->sections[l].memory_struct[offset].sizes_size; n++) {
							if (self->sections[l].memory_struct[offset].sizes[n] == self->sections[l].memory_log[m].length) {
								found = 1;
								debug_print(DEBUG_MAIN, 1, "Found size\n");
								break;
							}
						}
						if (found == 0) {
							self->sections[l].memory_struct[offset].sizes = realloc(
									self->sections[l].memory_struct[offset].sizes,
									(self->sections[l].memory_struct[offset].sizes_size + 1) * sizeof(uint64_t));
							self->sections[l].memory_struct[offset].sizes_type = realloc(
									self->sections[l].memory_struct[offset].sizes,
									(self->sections[l].memory_struct[offset].sizes_size + 1) * sizeof(uint64_t));
							self->sections[l].memory_struct[offset].sizes[self->sections[l].memory_struct[offset].sizes_size] =
									self->sections[l].memory_log[m].length;
							self->sections[l].memory_struct[offset].sizes_type[self->sections[l].memory_struct[offset].sizes_size] =
									self->sections[l].memory_log[m].type;
							self->sections[l].memory_struct[offset].log_index[self->sections[l].memory_struct[offset].sizes_size] =
									m;
							self->sections[l].memory_struct[offset].limit_low = offset;
							self->sections[l].memory_struct[offset].limit_high =
									offset + self->sections[l].memory_log[m].length;
							self->sections[l].memory_struct[offset].value_index = 0;
							self->sections[l].memory_struct[offset].valid = 1;
							self->sections[l].memory_struct[offset].sizes_size++;
						}
					}
				} else {
					debug_print(DEBUG_MAIN, 1, "Unknown type:0x%lx\n",
							self->sections[l].memory_log[m].type);
				}
			}
		}
	}
	return 0;
}

int print_memory_log(struct self_s *self)
{
	uint64_t l, m, n;
	for (l = 0; l < self->sections_size; l++) {
		debug_print(DEBUG_MAIN, 1, "Scanning section 0x%lx\n", l);
		if (self->sections[l].memory_struct_size > 0) {
			for (m = 0; m < self->sections[l].memory_struct_size; m++) {
				if (1 == self->sections[l].memory_struct[m].valid) {
					debug_print(DEBUG_MAIN, 1, "memory_struct:0x%lx: sizes_size=0x%lx, limit_low=0x%lx, limit_high=0x%lx, value_index=0x%lx\n",
							m,
							self->sections[l].memory_struct[m].sizes_size,
							self->sections[l].memory_struct[m].limit_low,
							self->sections[l].memory_struct[m].limit_high,
							self->sections[l].memory_struct[m].value_index);
					for (n = 0; n < self->sections[l].memory_struct[m].sizes_size; n++) {
						debug_print(DEBUG_MAIN, 1, "   0x%lx: memory_struct: sizes=0x%lx, sizes_type=0x%lx\n",
								n,
								self->sections[l].memory_struct[m].sizes[n],
								self->sections[l].memory_struct[m].sizes_type[n]);
					}
				}
			}
		}
	}
	return 0;
}


int main(int argc, char *argv[])
{
	int n = 0;
//	uint64_t offset = 0;
//	int instruction_offset = 0;
//	int octets = 0;
//	int result;
	char *filename;
	struct self_s *self = NULL;
	void *handle_void = NULL;
	uint32_t arch;
	uint64_t mach;
	int fd;
	int tmp;
	int err;
	int found;
	const char *file = "test.obj";
//	size_t inst_size = 0;
//	uint64_t reloc_size = 0;
	int l, m;
	struct instruction_s *instruction;
//	struct instruction_s *instruction_prev;
	struct inst_log_entry_s *inst_log1;
//	struct inst_log_entry_s *inst_log1_prev;
	struct inst_log_entry_s *inst_exe;
	struct inst_log_entry_s *inst_log_entry;
//	struct memory_s *value;
	uint64_t inst_log_prev = 0;
	int param_present[100];
	int param_size[100];
	char *expression;
	int not_finished;
	struct memory_s *memory_text;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;
	int *memory_used;
	struct relocation_s *relocations;
	struct external_entry_point_s *external_entry_points;
	struct control_flow_node_s *nodes;
	int nodes_size;
	struct path_s *paths;
	int paths_size = 300000;
	struct loop_s *loops;
	int loops_size = 2000;
	//struct ast_s *ast;
	int *section_number_mapping;
	struct reloc_table_s *reloc_table;
	int reloc_table_size;
	LLVMDecodeAsmX86_64Ref decode_asm;
	char *buffer = NULL;
	int section_code_index;
	struct input_find_types_s find_types;

	buffer = calloc(1,1024);
	setLogLevel();

	debug_print(DEBUG_MAIN, 1, "Hello loops 0x%x\n", 2000);
	getcwd(buffer, 1024);
    printf("CWD = %s\n", buffer);
	if (argc != 2) {
		printf("Syntax error\n");
		printf("Usage: dis64 filename\n");
		printf("Where \"filename\" is the input .o file\n");
		exit(1);
	}
	file = argv[1];

	self = malloc(sizeof(struct self_s));
	expression = malloc(1000); /* Buffer for if expressions */

	handle_void = bf_test_open_file(file);
	if (!handle_void) {
		debug_print(DEBUG_MAIN, 1, "Failed to find or recognise file\n");
		return 1;
	}
	self->handle_void = handle_void;
	tmp = bf_get_arch_mach(handle_void, &arch, &mach);
	if ((arch != 9) ||
		(mach != 8)) {
		debug_print(DEBUG_MAIN, 1, "File not the correct arch(0x%x) and mach(0x%"PRIx64")\n", arch, mach);
		return 1;
	}

	bf_print_symtab(handle_void);

	bf_init_section_number_mapping(handle_void, &section_number_mapping);

	bf_print_sectiontab(handle_void);
	tmp = bf_get_sections_size(handle_void, &(self->load_sections_length));
	debug_print(DEBUG_MAIN, 1, "self->load_sections_length = 0x%lx\n", self->load_sections_length);
	if (tmp) {
		debug_print(DEBUG_MAIN, 1, "Error getting sections_size\n");
		exit(1);
	}
	/* 0: For NULL pointers
	 * 1: REGS
	 * 2: STACK
	 * 3: Segments from .o file
	 * 4: MALLOC
	 */
	self->load_sections_offset = 3;
	self->sections_size = self->load_sections_offset + self->load_sections_length;
	self->sections = calloc(self->sections_size, sizeof(struct section_s));
	for (n = 0; n < self->load_sections_length; n++) {
		int offset = self->load_sections_offset;
		bf_get_section_id(handle_void, n, &(self->sections[n + offset].section_id));
		bf_get_section_name(handle_void, n, &(self->sections[n + offset].section_name));
		bf_get_content_size(handle_void, n, &(self->sections[n + offset].content_size));
		if ((self->sections[n + offset].content_size) > 0) {
			self->sections[n + offset].content = malloc(self->sections[n + offset].content_size);
			tmp = bf_copy_section_contents(handle_void, n, self->sections[n + offset].content, self->sections[n + offset].content_size);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Error section content load failed\n");
				exit(1);
			}
			self->sections[n + offset].memory =
					calloc(self->sections[n + offset].content_size, sizeof(struct memory_s));
			self->sections[n + offset].memory_size = self->sections[n + offset].content_size;
		}
		bf_get_section_alignment(handle_void, n, &(self->sections[n + offset].alignment));
		self->sections[n + offset].alloc = bf_section_is_alloc(handle_void, n);
		self->sections[n + offset].load = bf_section_is_load(handle_void, n);
		self->sections[n + offset].reloc = bf_section_is_reloc(handle_void, n);
		self->sections[n + offset].read_only = bf_section_is_readonly(handle_void, n);
		self->sections[n + offset].code = bf_section_is_code(handle_void, n);
		self->sections[n + offset].data = bf_section_is_data(handle_void, n);
		bf_get_reloc_table_section_size(handle_void, n, &(self->sections[n + offset].reloc_size));
		debug_print(DEBUG_MAIN, 1, "section[%d].reloc_size = 0x%lx\n", n, self->sections[n + offset].reloc_size);
		if ((self->sections[n + offset].reloc_size) > 0) {
			self->sections[n + offset].reloc_entry = calloc(self->sections[n + offset].reloc_size, sizeof(struct reloc_s));
		    tmp = bf_get_reloc_table_section(handle_void, n, offset, self->sections[n + offset].reloc_entry);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Error section reloc load failed\n");
				exit(1);
			}
		}
	}
	for (n = 0; n < self->sections_size; n++) {
		int m;
		debug_print(DEBUG_MAIN, 1, "id           = 0x%x\n", self->sections[n].section_id);
		debug_print(DEBUG_MAIN, 1, "index        = 0x%x\n", n);
		debug_print(DEBUG_MAIN, 1, "name         = %s\n", self->sections[n].section_name);
		debug_print(DEBUG_MAIN, 1, "content_size = 0x%lx\n", self->sections[n].content_size);
		debug_print(DEBUG_MAIN, 1, "alignment    = %d\n", self->sections[n].alignment);
		debug_print(DEBUG_MAIN, 1, "alloc        = %d\n", self->sections[n].alloc);
		debug_print(DEBUG_MAIN, 1, "load         = %d\n", self->sections[n].load);
		debug_print(DEBUG_MAIN, 1, "reloc        = %d\n", self->sections[n].reloc);
		debug_print(DEBUG_MAIN, 1, "read_only    = %d\n", self->sections[n].read_only);
		debug_print(DEBUG_MAIN, 1, "code         = %d\n", self->sections[n].code);
		debug_print(DEBUG_MAIN, 1, "data         = %d\n", self->sections[n].data);
		for (m = 0; m < self->sections[n].reloc_size; m++) {
			struct reloc_s *reloc = &(self->sections[n].reloc_entry[m]);
			debug_print(DEBUG_MAIN, 1, "rel[%d].type         = 0x%x\n", m, reloc->type);
			debug_print(DEBUG_MAIN, 1, "rel[%d].offset       = 0x%lx\n", m, reloc->offset);
			debug_print(DEBUG_MAIN, 1, "rel[%d].offset_size  = 0x%lx\n", m, reloc->offset_size);
			debug_print(DEBUG_MAIN, 1, "rel[%d].id           = 0x%lx\n", m, reloc->section_id);
			debug_print(DEBUG_MAIN, 1, "rel[%d].index        = 0x%lx\n", m, reloc->section_index);
			debug_print(DEBUG_MAIN, 1, "rel[%d].name         = %s\n", m, reloc->name);
			debug_print(DEBUG_MAIN, 1, "rel[%d].value_int    = 0x%lx\n", m, reloc->value_int);
			debug_print(DEBUG_MAIN, 1, "rel[%d].value_uint   = 0x%lx\n", m, reloc->value_uint);
			debug_print(DEBUG_MAIN, 1, "rel[%d].addend       = 0x%lx\n", m, reloc->addend);
		}

	}

	debug_print(DEBUG_MAIN, 1, "Setup ok\n");
	section_code_index = 0;
	found = 0;
	for (n = 0; n < self->sections_size; n++) {
		if (self->sections[n].code) {
			section_code_index = n;
			found++;
		}
	}
	if (found != 1) {
		debug_print(DEBUG_MAIN, 1, "Error: Found %d CODE sections, not sure which to use.\n", found);
		exit(1);
	}

	//inst = malloc(inst_size);
	/* valgrind does not know about bf_copy_data_section */
	//memset(inst, 0, inst_size);
	//bf_copy_code_section(handle_void, inst, inst_size);
	debug_print(DEBUG_MAIN, 1, "dis:.text Data at %p, size=0x%"PRIx64"\n",
				self->sections[section_code_index].content,
				self->sections[section_code_index].content_size);
	for (n = 0; n < self->sections[section_code_index].content_size; n++) {
		printf("0x%02x", self->sections[section_code_index].content[n]);
	}
	printf("\n");
	data_size = bf_get_data_size(handle_void);
	data = malloc(data_size);
	/* valgrind does not know about bf_copy_data_section */
	memset(data, 0, data_size);
	bf_copy_data_section(handle_void, data, data_size);
	debug_print(DEBUG_MAIN, 1, "dis:.data Data at %p, size=0x%"PRIx64"\n", data, data_size);
	for (n = 0; n < data_size; n++) {
		debug_print(DEBUG_MAIN, 1,  "0x%02x", data[n]);
	}
	debug_print(DEBUG_MAIN, 1, "\n");

	rodata_size = bf_get_rodata_size(handle_void);
	rodata = malloc(rodata_size);
	/* valgrind does not know about bf_copy_data_section */
	memset(rodata, 0, rodata_size);
	bf_copy_rodata_section(handle_void, rodata, rodata_size);
	debug_print(DEBUG_MAIN, 1, "dis:.rodata Data at %p, size=0x%"PRIx64"\n", rodata, rodata_size);
	for (n = 0; n < rodata_size; n++) {
		debug_print(DEBUG_MAIN, 1,  "0x%02x", rodata[n]);
	}
	debug_print(DEBUG_MAIN, 1, "\n");

	inst_log_entry = calloc(INST_LOG_ENTRY_SIZE, sizeof(struct inst_log_entry_s));
	relocations =  calloc(RELOCATION_SIZE, sizeof(struct relocation_s));
	external_entry_points = calloc(EXTERNAL_ENTRY_POINTS_MAX, sizeof(struct external_entry_point_s));
	debug_print(DEBUG_MAIN, 1, "sizeof struct self_s = 0x%"PRIx64"\n", sizeof *self);
	self->section_number_mapping = section_number_mapping;
	self->data_size = data_size;
	self->data = data;
	self->rodata_size = rodata_size;
	self->rodata = rodata;
	self->handle_void = handle_void;
	printf("rodata_size=0x%lx\n", rodata_size);
	printf("handle_void = %p\n", handle_void);
	self->inst_log_entry = inst_log_entry;
	self->relocations = relocations;
	self->external_entry_points = external_entry_points;
	self->entry_point = calloc(ENTRY_POINTS_SIZE, sizeof(struct entry_point_s));
	self->entry_point_list_length = ENTRY_POINTS_SIZE;
//	self->search_back_seen = calloc(INST_LOG_ENTRY_SIZE, sizeof(int));
	self->ll_inst = (void *)calloc(1, sizeof(struct instruction_low_level_s));
	LLVMInitializeX86TargetInfo();
	LLVMInitializeX86TargetMC();
	LLVMInitializeX86AsmParser();
	LLVMInitializeX86Disassembler();
	decode_asm = LLVMNewDecodeAsmX86_64();
	tmp = LLVMSetupDecodeAsmX86_64(decode_asm);
	self->decode_asm = decode_asm;

	nodes = calloc(1000, sizeof(struct control_flow_node_s));
	nodes_size = 0;
	self->nodes = nodes;
	self->nodes_size = nodes_size;
	
	/* valgrind does not know about bf_copy_data_section */
	memset(data, 0, data_size);
	bf_copy_data_section(handle_void, data, data_size);
	debug_print(DEBUG_MAIN, 1, "dis:.data Data at %p, size=0x%"PRIx64"\n", data, data_size);
	for (n = 0; n < data_size; n++) {
		debug_print(DEBUG_MAIN, 1, " 0x%02x", data[n]);
	}
	debug_print(DEBUG_MAIN, 1, "\n");

	tmp = input_find_types(self, "test110.bc", &find_types);
	tmp = input_load_data_hints(self, "test110.hints");
	input_dump_mod(self);
	//exit(1);
#if 0
	bf_get_reloc_table_code_section(handle_void);
	
	tmp = bf_print_reloc_table_code_section(handle_void);
	bf_get_reloc_table_data_section(handle_void);
#endif
#if 0
	for (n = 0; n < handle->reloc_table_data_sz; n++) {
		debug_print(DEBUG_MAIN, 1, "reloc_table_data:addr = 0x%"PRIx64", size = 0x%"PRIx64", value = 0x%"PRIx64", section_index = 0x%"PRIx64", section_name=%s, symbol_name=%s\n",
			handle->reloc_table_data[n].address,
			handle->reloc_table_data[n].size,
			handle->reloc_table_data[n].value,
			handle->reloc_table_data[n].section_index,
			handle->reloc_table_data[n].section_name,
			handle->reloc_table_data[n].symbol_name);
	}
#endif
#if 0
	bf_get_reloc_table_rodata_section(handle_void);
	for (n = 0; n < handle->reloc_table_rodata_sz; n++) {
		debug_print(DEBUG_MAIN, 1, "reloc_table_rodata:addr = 0x%"PRIx64", size = 0x%"PRIx64", value = 0x%"PRIx64", section_index = 0x%"PRIx64", section_name=%s, symbol_name=%s\n",
			handle->reloc_table_rodata[n].address,
			handle->reloc_table_rodata[n].size,
			handle->reloc_table_rodata[n].value,
			handle->reloc_table_rodata[n].section_index,
			handle->reloc_table_rodata[n].section_name,
			handle->reloc_table_rodata[n].symbol_name);
	}
#endif	
	debug_print(DEBUG_MAIN, 1, "handle=%p\n", handle_void);
	tmp = bf_disassemble_init(handle_void, self->sections[section_code_index].content_size, self->sections[section_code_index].content);
	//tmp = bf_disassembler_set_options(handle_void, "att");

	dis_instructions.bytes_used = 0;
	inst_exe = &inst_log_entry[0];

	tmp = external_functions_init(self);
	if (tmp) return 1;

	tmp = external_entry_points_init(external_entry_points, self->load_sections_offset, handle_void);
	if (tmp) return 1;

#if 0
	/* FIXME: Special code to reduce processing to only one external_entry_point */
	for (n = 0; n < 4; n++) {
		external_entry_points[n].valid = 0;
	}
	for (n = 5; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
		external_entry_points[n].valid = 0;
	}
#endif

	debug_print(DEBUG_MAIN, 1, "List of functions\n");
	for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
		if (external_entry_points[n].valid != 0) {
		debug_print(DEBUG_MAIN, 1, "%d: type = %d, symtab_index = %d, sect_id = 0x%x, sect_index = 0x%x, &%s() = 0x%04"PRIx64"\n",
			n,
			external_entry_points[n].type,
			external_entry_points[n].symtab_index,
			external_entry_points[n].section_id,
			external_entry_points[n].section_index,
			external_entry_points[n].name,
			external_entry_points[n].value);
		}
	}
#if 0
	tmp = bf_link_reloc_table_code_to_external_entry_point(handle_void, external_entry_points);
	if (tmp) return 1;
#endif

#if 0
	reloc_table_size = bf_get_reloc_table_code_size(handle_void);
	reloc_table = bf_get_reloc_table_code(handle_void);
	for (n = 0; n < reloc_table_size; n++) {
		debug_print(DEBUG_MAIN, 1, "reloc_table_code:addr = 0x%"PRIx64", size = 0x%"PRIx64", type = 0x%x, function_index = 0x%"PRIx64", section_name=%s, symbol_name=%s, symbol_value = 0x%"PRIx64"\n",
			reloc_table[n].address,
			reloc_table[n].size,
			reloc_table[n].type,
			reloc_table[n].external_functions_index,
			reloc_table[n].section_name,
			reloc_table[n].symbol_name,
			reloc_table[n].symbol_value);
	}
#endif			
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid != 0) &&
			(external_entry_points[l].type == 1)) {  /* 1 == Implemented in this .o file */
			struct process_state_s *process_state;
			struct entry_point_s *entry_point = self->entry_point;
			
			debug_print(DEBUG_MAIN, 1, "Start function block: 0x%x:%s:0x%"PRIx64"\n", l, external_entry_points[l].name, external_entry_points[l].value);
			process_state = &external_entry_points[l].process_state;
			memory_text = process_state->memory_text;
			memory_stack = process_state->memory_stack;
			memory_reg = process_state->memory_reg;
			memory_data = process_state->memory_data;
			memory_used = process_state->memory_used;
			external_entry_points[l].inst_log = inst_log;
			/* EIP is a parameter for process_block */
			/* Update EIP */
			//memory_reg[2].offset_value = 0;
			//inst_log_prev = 0;
			entry_point[0].used = 1;
			entry_point[0].esp_section_id = memory_reg[0].section_id;
			entry_point[0].esp_section_index = memory_reg[0].section_index;
			entry_point[0].esp_init_value = memory_reg[0].init_value;
			entry_point[0].esp_offset_value = memory_reg[0].offset_value;
			entry_point[0].ebp_section_id = memory_reg[1].section_id;
			entry_point[0].ebp_section_index = memory_reg[1].section_index;
			entry_point[0].ebp_init_value = memory_reg[1].init_value;
			entry_point[0].ebp_offset_value = memory_reg[1].offset_value;
			entry_point[0].eip_section_id = memory_reg[2].section_id;
			entry_point[0].eip_section_index = memory_reg[2].section_index;
			entry_point[0].eip_init_value = memory_reg[2].init_value;
			entry_point[0].eip_offset_value = memory_reg[2].offset_value;
			entry_point[0].previous_instuction = 0;

			print_mem(memory_reg, 1);
			debug_print(DEBUG_MAIN, 1, "LOGS: inst_log = 0x%"PRIx64"\n", inst_log);
			do {
				not_finished = 0;
				for (n = 0; n < self->entry_point_list_length; n++ ) {
					/* EIP is a parameter for process_block */
					/* Update EIP */
					//debug_print(DEBUG_MAIN, 1, "entry:%d\n",n);
					if (entry_point[n].used) {
						memory_reg[0].section_id = entry_point[n].esp_section_id;
						memory_reg[0].section_index = entry_point[n].esp_section_index;
						memory_reg[0].init_value = entry_point[n].esp_init_value;
						memory_reg[0].offset_value = entry_point[n].esp_offset_value;
						memory_reg[1].section_id = entry_point[n].ebp_section_id;
						memory_reg[1].section_index = entry_point[n].ebp_section_index;
						memory_reg[1].init_value = entry_point[n].ebp_init_value;
						memory_reg[1].offset_value = entry_point[n].ebp_offset_value;
						memory_reg[2].section_id = entry_point[n].eip_section_id;
						memory_reg[2].section_index = entry_point[n].eip_section_index;
						memory_reg[2].init_value = entry_point[n].eip_init_value;
						memory_reg[2].offset_value = entry_point[n].eip_offset_value;
						inst_log_prev = entry_point[n].previous_instuction;
						not_finished = 1;
						debug_print(DEBUG_MAIN, 1, "LOGS:0x%x:0x%x: EIPsection_id    = 0x%"PRIx64"\n", l, n, memory_reg[2].section_id);
						debug_print(DEBUG_MAIN, 1, "LOGS:0x%x:0x%x: EIPsection_index = 0x%"PRIx64"\n", l, n, memory_reg[2].section_index);
						debug_print(DEBUG_MAIN, 1, "LOGS:0x%x:0x%x: EIPinit          = 0x%"PRIx64"\n", l, n, memory_reg[2].init_value);
						debug_print(DEBUG_MAIN, 1, "LOGS:0x%x:0x%x: EIPoffset        = 0x%"PRIx64"\n", l, n, memory_reg[2].offset_value);
						err = process_block(self,
											process_state,
											inst_log_prev,
											self->sections[external_entry_points[l].section_index].content_size);
						/* clear the entry after calling process_block */
						if (err) {
							printf("process_block failed\n");
							return err;
						}
						entry_point[n].used = 0;
					}
				}
			} while (not_finished);	
			external_entry_points[l].inst_log_end = inst_log - 1;
			debug_print(DEBUG_MAIN, 1, "LOGS: inst_log_end = 0x%"PRIx64"\n", inst_log);
		}
	}
/*
	if (entry_point_list_length > 0) {
		for (n = 0; n < entry_point_list_length; n++ ) {
			debug_print(DEBUG_MAIN, 1, "eip = 0x%"PRIx64", prev_inst = 0x%"PRIx64"\n",
				entry_point[n].eip_offset_value,
				entry_point[n].previous_instuction);
		}
	}
*/
	//inst_log--;
	debug_print(DEBUG_MAIN, 1, "EXE FINISHED\n");
	debug_print(DEBUG_MAIN, 1, "Instructions=%"PRId64", entry_point_list_length=%"PRId64"\n",
		inst_log,
		self->entry_point_list_length);

	/* Correct inst_log to identify how many dis_instructions there have been */
	//inst_log--;

	print_dis_instructions(self);
	debug_print(DEBUG_MAIN, 1, "start tidy\n");
	tmp = tidy_inst_log(self);
	print_dis_instructions(self);
	self->flag_dependency = calloc(inst_log, sizeof(int));
	self->flag_dependency_opcode = calloc(inst_log, sizeof(int));
	self->flag_result_users = calloc(inst_log, sizeof(int));
	self->flag_dependency_size = inst_log;
	debug_print(DEBUG_MAIN, 1, "got here I-0\n");
	debug_print(DEBUG_MAIN, 1, "INFO: flag_dep_size initialised to 0x%"PRIx64"\n", inst_log);
	if (inst_log > 0xe2c) {
		debug_print(DEBUG_MAIN, 1, "INFO: flag_result_users 0xe2c = 0x%x\n", self->flag_result_users[0xe2c]);
	}
	debug_print(DEBUG_MAIN, 1, "start build_flag_dependency_table\n");
	tmp = build_flag_dependency_table(self);
	debug_print(DEBUG_MAIN, 1, "got here I-1\n");
	if (inst_log > 0xe2c) {
		debug_print(DEBUG_MAIN, 1, "INFO: flag_result_users 0xe2c = 0x%x\n", self->flag_result_users[0xe2c]);
	}
	debug_print(DEBUG_MAIN, 1, "got here I-2\n");
	debug_print(DEBUG_MAIN, 1, "start print_flag_dependency_table\n");
	tmp = print_flag_dependency_table(self);
	debug_print(DEBUG_MAIN, 1, "got here I-3\n");
	if (inst_log > 0xe2c) {
		debug_print(DEBUG_MAIN, 1, "INFO: flag_result_users 0xe2c = 0x%x\n", self->flag_result_users[0xe2c]);
	}
	debug_print(DEBUG_MAIN, 1, "got here I-4\n");
	/* This function changes SBB to other instructions, like the CMP to ICMP. */
	tmp = fix_flag_dependency_instructions(self);
	if (inst_log > 0xe2c) {
		debug_print(DEBUG_MAIN, 1, "INFO: flag_result_users 0xe2c = 0x%x\n", self->flag_result_users[0xe2c]);
	}
	//tmp = insert_nop_after(self, 4);
	print_dis_instructions(self);
	/* Build the control flow nodes from the instructions. */
	tmp = build_control_flow_nodes(self, nodes, &nodes_size);
	self->nodes_size = nodes_size;
	tmp = print_control_flow_nodes(self, nodes, nodes_size);
//	print_dis_instructions(self);
	debug_print(DEBUG_MAIN, 1, "got here 1\n");
	/* enter the start node into each external_entry_point */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid) && (external_entry_points[l].type == 1)) {
			tmp = find_node_from_inst(self, nodes, nodes_size, external_entry_points[l].inst_log);
			if (tmp == 0) {
				debug_print(DEBUG_MAIN, 1, "find_node_from_inst failed. entry[0x%x:%s]:start inst = 0x%"PRIx64", start node = 0x%x\n",
					l,
					external_entry_points[l].name,
					external_entry_points[l].inst_log,
					external_entry_points[l].start_node);
				exit(1);
			}
			external_entry_points[l].start_node = tmp;
			debug_print(DEBUG_MAIN, 1, "entry[0x%x]:start inst = 0x%"PRIx64", start node = 0x%x\n",
				l,
				external_entry_points[l].inst_log,
				external_entry_points[l].start_node);
		}
	}
	/* extract the nodes from the global nodes list and assign them to each external_entry point.
	 * extract the instructions from the global instruction log and assign them to each external_entry_point.
	 * This will permit future optimizations, allowing processing of each external_entry point in parallel. */
	/* This will also permit early complexity analysis by gathering the number of branches in each function
	 * and multiplying them together. This will give the number of required "paths". */
	/* This will also permit a labels table per function, so local varibales in one function
	 * can have the same label as a local varibale in another function because they have no overlapping scope.
	 * This is particularly useful for stack variables naming and their subsequent representation in LLVM IR.
	 */
	/* tmp = create_function_node_members() mapping from nodes in externel_entry_point to the global nodes list. */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid) && (external_entry_points[l].type == 1)) {
			tmp = create_function_node_members(self, &external_entry_points[l]);
		}
	}
	
	tmp = output_cfg_dot_basic(self, nodes, nodes_size);
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			debug_print(DEBUG_MAIN, 1, "print_control_flow_nodes1 for function %x:%s\n", l, external_entry_points[l].name);
			tmp = print_control_flow_nodes(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
		}
	}

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid) && (external_entry_points[l].type == 1)) {
			tmp = output_cfg_dot_basic2(self, &external_entry_points[l], l);
		}
	}
	paths = calloc(paths_size, sizeof(struct path_s));
	for (n = 0; n < paths_size; n++) {
		paths[n].path = calloc(1000, sizeof(int));
	}
	loops = calloc(loops_size, sizeof(struct loop_s));

	for (n = 0; n < loops_size; n++) {
		loops[n].list = calloc(1000, sizeof(int));
	}

#if 0
	ast = calloc(1, sizeof(struct ast_s));
	ast->ast_container = calloc(AST_SIZE, sizeof(struct ast_container_s));
	ast->ast_if_then_else = calloc(AST_SIZE, sizeof(struct ast_if_then_else_s));
	ast->ast_if_then_goto = calloc(AST_SIZE, sizeof(struct ast_if_then_goto_s));
	ast->ast_loop = calloc(AST_SIZE, sizeof(struct ast_loop_s));
	ast->ast_loop_container = calloc(AST_SIZE, sizeof(struct ast_loop_container_s));
	ast->ast_loop_then_else = calloc(AST_SIZE, sizeof(struct ast_loop_then_else_s));
	ast->ast_entry = calloc(AST_SIZE, sizeof(struct ast_entry_s));
	ast->container_size = 0;
	ast->if_then_else_size = 0;
	ast->if_then_goto_size = 0;
	ast->loop_size = 0;
	ast->loop_container_size = 0;
	ast->loop_then_else_size = 0;
#endif

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
//	for (l = 17; l < 19; l++) {
//	for (l = 37; l < 38; l++) {
//		if (external_entry_points[l].valid) {
//			nodes[external_entry_points[l].start_node].entry_point = l + 1;
//		}
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			debug_print(DEBUG_MAIN, 1, "Starting external entry point %d:%s\n", l, external_entry_points[l].name);
			int paths_used = 0;
			int loops_used = 0;
			int *multi_ret = NULL;
			int multi_ret_size;

			for (n = 0; n < paths_size; n++) {
				paths[n].used = 0;
				paths[n].path_prev = 0;
				paths[n].path_prev_index = 0;
				paths[n].path_size = 0;
				paths[n].type = PATH_TYPE_UNKNOWN;
				paths[n].loop_head = 0;
			}
			for (n = 0; n < loops_size; n++) {
				loops[n].size = 0;
				loops[n].head = 0;
				loops[n].nest = 0;
			}

			tmp = build_control_flow_paths(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size,
				paths, &paths_size, &paths_used, 1);
			debug_print(DEBUG_MAIN, 1, "tmp = %d, PATHS used = %d\n", tmp, paths_used);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Failed at external entry point %d:%s\n", l, external_entry_points[l].name);
				exit(1);
			}
			for (n = 1; n < external_entry_points[l].nodes_size; n++) {
				debug_print(DEBUG_MAIN, 1, "TEST10: node:0x%x: next_size = 0x%x\n", n, external_entry_points[l].nodes[n].next_size);
			};
				

			tmp = analyse_multi_ret(self, paths, &paths_size, &multi_ret_size, &multi_ret);
			if (multi_ret_size) {
				debug_print(DEBUG_MAIN, 1, "tmp = %d, multi_ret_size = %d\n", tmp, multi_ret_size);
				for (m = 0; m < multi_ret_size; m++) {
					debug_print(DEBUG_MAIN, 1, "multi_ret: node 0x%x\n", multi_ret[m]);
				}
				if (multi_ret_size == 2) {
					/* FIXME: disable this temporarily. It is broken */
					debug_print(DEBUG_MAIN, 1, "analyse_merge_nodes: 0x%x, 0x%x\n", multi_ret[0], multi_ret[1]);
					tmp = analyse_merge_nodes(self, l, multi_ret[0], multi_ret[1]);
					tmp = build_control_flow_paths(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size,
						paths, &paths_size, &paths_used, 1);
				} else if (multi_ret_size > 2) {
					debug_print(DEBUG_MAIN, 1, "multi_ret_size > 2 not yet handled\n");
					exit(1);
				}
			}
			for (n = 1; n < external_entry_points[l].nodes_size; n++) {
				debug_print(DEBUG_MAIN, 1, "TEST10: node:0x%x: next_size = 0x%x\n", n, external_entry_points[l].nodes[n].next_size);
			};
			//tmp = print_control_flow_paths(self, paths, &paths_size);

			tmp = build_control_flow_loops(self, paths, &paths_size, loops, &loops_size);
			tmp = build_control_flow_loops_node_members(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size, loops, &loops_size);
			tmp = build_node_paths(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size, paths, &paths_size, l + 1);

			external_entry_points[l].paths_size = paths_used;

			external_entry_points[l].paths = calloc(paths_used, sizeof(struct path_s));
			if (0 == paths_used) {
				debug_print(DEBUG_MAIN, 1, "INFO: paths_used = 0, %s, %p\n", external_entry_points[l].name, external_entry_points[l].paths);
				exit(1);
			}
			for (n = 0; n < paths_used; n++) {
				external_entry_points[l].paths[n].used = paths[n].used;
				external_entry_points[l].paths[n].path_prev = paths[n].path_prev;
				external_entry_points[l].paths[n].path_prev_index = paths[n].path_prev_index;
				external_entry_points[l].paths[n].path_size = paths[n].path_size;
				external_entry_points[l].paths[n].type = paths[n].type;
				external_entry_points[l].paths[n].loop_head = paths[n].loop_head;

				external_entry_points[l].paths[n].path = calloc(paths[n].path_size, sizeof(int));
				for (m = 0; m  < paths[n].path_size; m++) {
					external_entry_points[l].paths[n].path[m] = paths[n].path[m];
				}

			}
			for (n = 0; n < loops_size; n++) {
				if (loops[n].size != 0) {
					loops_used = n + 1;
				}
			}
			debug_print(DEBUG_MAIN, 1, "loops_used = 0x%x\n", loops_used);
			external_entry_points[l].loops_size = loops_used;
			external_entry_points[l].loops = calloc(loops_used, sizeof(struct loop_s));
			for (n = 0; n < loops_used; n++) {
				external_entry_points[l].loops[n].head = loops[n].head;
				external_entry_points[l].loops[n].size = loops[n].size;
				external_entry_points[l].loops[n].nest = loops[n].nest;
				external_entry_points[l].loops[n].list = calloc(loops[n].size, sizeof(int));
				for (m = 0; m  < loops[n].size; m++) {
					external_entry_points[l].loops[n].list[m] = loops[n].list[m];
				}
			}
		}
	}
	debug_print(DEBUG_MAIN, 1, "got here 2\n");
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			debug_print(DEBUG_MAIN, 1, "print_control_flow_nodes for function %x:%s\n", l, external_entry_points[l].name);
			tmp = print_control_flow_nodes(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
		}
	}
	/* Node specific processing */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			debug_print(DEBUG_MAIN, 1, "got here 2a\n");
			tmp = build_node_dominance(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
			debug_print(DEBUG_MAIN, 1, "got here 2b\n");
			tmp = analyse_control_flow_node_links(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
			debug_print(DEBUG_MAIN, 1, "got here 2c\n");
			tmp = build_node_type(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
			debug_print(DEBUG_MAIN, 1, "got here 2d\n");
			//tmp = build_control_flow_depth(self, nodes, &nodes_size,
			//		paths, &paths_size, &paths_used, external_entry_points[l].start_node);
			tmp = build_control_flow_loops_multi_exit(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size,
				external_entry_points[l].loops, external_entry_points[l].loops_size);
			debug_print(DEBUG_MAIN, 1, "got here 2e\n");
		}
	}
	debug_print(DEBUG_MAIN, 1, "got here 3\n");

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			debug_print(DEBUG_MAIN, 1, "print_control_flow_nodes for function %x:%s\n", l, external_entry_points[l].name);
			tmp = print_control_flow_nodes(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
		}
	}
	debug_print(DEBUG_MAIN, 1, "got here 4\n");

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = build_node_if_tail(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
			for (n = 0; n < external_entry_points[l].nodes_size; n++) {
				if (!(external_entry_points[l].nodes[n].valid)) {
					continue;
				}
				if ((external_entry_points[l].nodes[n].type == NODE_TYPE_IF_THEN_ELSE) &&
					(external_entry_points[l].nodes[n].if_tail == 0)) {
					debug_print(DEBUG_MAIN, 1, "FAILED: Node 0x%x with no if_tail\n", n);
				}
			}
		}
	}
	/* Build the node members list for each function */
	/* This allows us to output a single function in the .dot output files. */	
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid) {
			/* Not needed any more */
			/* tmp = build_entry_point_node_members(self, &external_entry_points[l], nodes_size); */
			tmp = print_entry_point_node_members(self, &external_entry_points[l]);
		}
	}
	
#if 1
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
//	for (l = 21; l < 22; l++) {
//	for (l = 37; l < 38; l++) {
		if (external_entry_points[l].valid) {
			debug_print(DEBUG_ANALYSE_PATHS, 1, "External entry point %d: type=%d, name=%s inst_log=0x%lx, start_node=0x%x\n", l, external_entry_points[l].type, external_entry_points[l].name, external_entry_points[l].inst_log, 1);
			tmp = print_control_flow_paths(self, external_entry_points[l].paths, &(external_entry_points[l].paths_size));
			tmp = print_control_flow_loops(self, external_entry_points[l].loops, &(external_entry_points[l].loops_size));
		}
	}
#endif
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			debug_print(DEBUG_MAIN, 1, "print_control_flow_nodes for function %s\n", external_entry_points[l].name);
			tmp = print_control_flow_nodes(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
		}
	}

//	Doing this after SSA now.
#if 0
//      Don't bother with the AST output for now 
//	tmp = output_cfg_dot(self, nodes, nodes_size);
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
//	for (l = 0; l < 21; l++) {
//	for (l = 21; l < 22; l++) {
//	for (l = 4; l < 5; l++) {
//		if (l == 21) continue;

		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			/* Control flow graph to Abstract syntax tree */
			debug_print(DEBUG_MAIN, 1, "cfg_to_ast. external entry point %d:%s\n", l, external_entry_points[l].name);
			external_entry_points[l].start_ast_container = ast->container_size;
			tmp = cfg_to_ast(self, nodes, &nodes_size, ast, external_entry_points[l].start_node);
			tmp = print_ast(self, ast);
		}
	}
	tmp = output_ast_dot(self, ast, nodes, &nodes_size);
	/* FIXME */
	//goto end_main;
#endif

#if 1


	if (self->entry_point_list_length > 0) {
		for (n = 0; n < self->entry_point_list_length; n++ ) {
			struct entry_point_s *entry_point = self->entry_point;

			if (entry_point[n].used) {
				debug_print(DEBUG_MAIN, 1, "%d, eip = 0x%"PRIx64", prev_inst = 0x%"PRIx64"\n",
					entry_point[n].used,
					entry_point[n].eip_offset_value,
					entry_point[n].previous_instuction);
			}
		}
	}


	/****************************************************************
	 * This section deals with building the node_used_register table
	 * The nodes can be processed in any order for this step.
	 * SRC, DST -> PHI SRC
	 * DST, SRC -> No PHI needed.
	 * DST first -> No PHI needed.
	 * SRC first -> PHI SRC.
	 * 0 = not seen.
	 * 1 = SRC first
	 * 2 = DST first
	 * If SRC and DST in same instruction, set SRC first.
	 ****************************************************************/
	/* FIXME: TODO convert nodes to external_entry_points[l].nodes */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = init_node_used_register_table(self, l);
		}
	}
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = fill_node_used_register_table(self, l);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "FIXME: fill node used register table failed\n");
				exit(1);
			}
		}
	}
	/* print node_used_register_table */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = print_node_used_register_table(self, l);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "FIXME: print node used register table failed\n");
				exit(1);
			}
		}
	}


	/****************************************************************
	 * This section deals with building the initial PHI DST instructions
	 * Create a PHI instruction for each entry in the node_used_register table,
	 * the PHI instruction DST register is identified and set.
         * This problem is then reduced to a node level problem, and not an instruction level problem.
         * The nodes can be processed in any order for this step.
	 ****************************************************************/

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = fill_node_phi_dst(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
		}
	}

	/****************************************************************
	 * Then for each path running through each PHI node, locate the previous node that used that register.
	 * Enter the path number, previously used node into the phi list for that register.
	 * The nodes must be processed in path order for this step.
	 * Optimizations can be made if paths are not unique at the current PHI node or above.
	 * Start at end of path, search back down the path to the current node,
	 * return which base path it is on. Only process if not a previous path.
	 ****************************************************************/

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = fill_node_phi_src(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
		}
	}
	/* Scan each of the list of paths in the src, and reduce the list to
	 * a list of immediately/first previous nodes with assocated node that assigned the register.
         * Also do sanity checks on the path nodes lists based on first_prev_node. 
	 * This reduces the PHI to a format similar to that used in LLVM */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = fill_phi_node_list(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
		}
	}

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid) && (external_entry_points[l].type == 1)) {
			tmp = find_function_simple_params_reg(self, l);
			debug_print(DEBUG_MAIN, 1, "simple_params_reg_size = %d\n", external_entry_points[l].simple_params_reg_size);
		}
	}
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid) && (external_entry_points[l].type == 1)) {
			tmp = fill_in_call_params(self, l);
		}
	}
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid) && (external_entry_points[l].type == 1)) {
			tmp = output_cfg_dot_simple(self, &external_entry_points[l], l);
		}
	}
	//debug_print(DEBUG_MAIN, 1, "Exiting before assigning labels\n");
	//exit(1);
	/************************************************************
	 * This section deals with starting true SSA.
	 * This bit sets the valid_id to 0 for both dst and src.
	 ************************************************************/
	for (n = 1; n < inst_log; n++) {
		inst_log1 =  &inst_log_entry[n];
		inst_log1->value1.value_id = 0;
		inst_log1->value2.value_id = 0;
		inst_log1->value3.value_id = 0;
	}
	
	/************************************************************
	 * Initialise Labels.
	 ************************************************************/
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			external_entry_points[l].label_redirect = calloc(10000, sizeof(struct label_redirect_s));
			external_entry_points[l].labels = calloc(10000, sizeof(struct label_s));
			external_entry_points[l].tip2 = calloc(10000, sizeof(struct tip2_s));
			external_entry_points[l].variable_id = 0x100;

			/* Init special labels */
			/* param_stack0000 == EIP on the stack */
			external_entry_points[l].label_redirect[3].domain = 1;
			external_entry_points[l].label_redirect[3].index = 3;
			external_entry_points[l].labels[3].scope = 2;
			external_entry_points[l].labels[3].type = 2;
			external_entry_points[l].labels[3].value = 0;
			//external_entry_points[l].labels[3].size_bits = 64;
			//external_entry_points[l].labels[3].lab_pointer = 1;

			debug_print(DEBUG_MAIN, 1, "NAME DST: 0x%x:%s\n",
				l, external_entry_points[l].name);
			for (n = 0; n < MEMORY_STACK_SIZE; n++) {
				if (external_entry_points[l].process_state.memory_stack[n].valid == 1) {
					debug_print(DEBUG_MAIN, 1, "0x%x:memory_stack[%d].start_address = 0x%"PRIx64"\n",
						l, n, external_entry_points[l].process_state.memory_stack[n].start_address);
				}
			}
			for (n = 1; n < external_entry_points[l].nodes_size; n++) {
				if (!(external_entry_points[l].nodes[n].valid)) {
					continue;
				}
				debug_print(DEBUG_ANALYSE, 1, "e1_node[0x%x]_start = inst 0x%x\n", n, external_entry_points[l].nodes[n].inst_start);
				debug_print(DEBUG_ANALYSE, 1, "e1_node[0x%x]_end = inst 0x%x\n", n, external_entry_points[l].nodes[n].inst_end);
			}
		}
	}

	/************************************************************
	 * This bit assigned a variable ID and label to each assignment (dst).
	 ************************************************************/
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].nodes_size; n++) {
				if (!external_entry_points[l].nodes[n].valid) {
					/* Only output nodes that are valid */
					continue;
				}
				tmp = assign_labels_to_dst(self, l, n);
				if (tmp) {
					printf("assign_labels_to_dst() failed\n");
					exit(1);
				}
			}
		}
	}

#if 0
	for (n = 0x100; n < 0x130; n++) {
		struct label_s *label;
		tmp = label_redirect[n].redirect;
		label = &labels[tmp];
		printf("Label 0x%x:", n);
		tmp = output_label(label, stdout);
		printf("\n");
	}
#endif
	/* Assign labels to PHI instructions dst */

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].nodes_size; n++) {
				if (!(external_entry_points[l].nodes[n].valid)) {
					/* Only output nodes that are valid */
					continue;
				}
				debug_print(DEBUG_ANALYSE_PHI, 1, "TEST: scanning node phi 0x%x\n", n);
				if (external_entry_points[l].nodes[n].phi_size) {
					debug_print(DEBUG_ANALYSE_PHI, 1, "TEST: phi insts found at node 0x%x\n", n);
					for (m = 0; m < external_entry_points[l].nodes[n].phi_size; m++) {
						external_entry_points[l].nodes[n].phi[m].value_id = external_entry_points[l].variable_id;
						external_entry_points[l].label_redirect[external_entry_points[l].variable_id].domain = 1;
						external_entry_points[l].label_redirect[external_entry_points[l].variable_id].index = external_entry_points[l].variable_id;
						external_entry_points[l].labels[external_entry_points[l].variable_id].scope = 1;
						external_entry_points[l].labels[external_entry_points[l].variable_id].type = 1;
						//external_entry_points[l].labels[external_entry_points[l].variable_id].lab_pointer = 0;
						external_entry_points[l].labels[external_entry_points[l].variable_id].value = external_entry_points[l].variable_id;
						external_entry_points[l].variable_id++;
					}
				}
			}
		}
	}

	/* TODO: add code to process the used_registers to identify registers
	 * that are assigned dst in a previous node or function param
	 */

	/* Fill in the reg dependency table */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].nodes_size; n++) {
				if (!external_entry_points[l].nodes[n].valid) {
					/* Only output nodes that are valid */
					continue;
				}
				tmp = fill_reg_dependency_table(self, &external_entry_points[l], n);
				if (tmp) {
					printf("fill_reg_dependency_table() failed\n");
					exit(1);
				}
			}
		}
	}

	/* print node_used_register_table */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = print_node_used_register_table(self, l);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "FIXME: print node used register table failed\n");
				exit(1);
			}
		}
	}

#if 0
	for (n = 1; n <= nodes_size; n++) {
		for (m = 0; m < MAX_REG; m++) {
			if (nodes[n].used_register[m].seen) {
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].seen = 0x%x\n", n, m, 
					nodes[n].used_register[m].seen);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].size = 0x%x\n", n, m, 
					nodes[n].used_register[m].size);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].src = 0x%x\n", n, m, 
					nodes[n].used_register[m].src);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].dst = 0x%x\n", n, m, 
					nodes[n].used_register[m].dst);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].src_fist_value_id = 0x%x\n", n, m, 
					nodes[n].used_register[m].src_first_value_id);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].src_fist_node = 0x%x\n", n, m, 
					nodes[n].used_register[m].src_first_node);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].src_fist_label = 0x%x\n", n, m, 
					nodes[n].used_register[m].src_first_label);
			}
		}
	}
#endif
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for (m = 0; m < MAX_REG; m++) {
				if (self->external_entry_points[l].param_reg_label[m]) {
					debug_print(DEBUG_MAIN, 1, "Entry Point 0x%x: Found reg 0x%x as param label 0x%x\n", l, m,
						self->external_entry_points[l].param_reg_label[m]);
				}
			}
		}
	}
	/* Fill in reg_params_size */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for (m = 0; m < reg_params_order_size; m++) {
				if (self->external_entry_points[l].param_reg_label[reg_params_order[m]]) {
					debug_print(DEBUG_MAIN, 1, "Entry Point 0x%x: Found reg_params_order 0x%x as param label 0x%x\n", l, m,
						self->external_entry_points[l].param_reg_label[reg_params_order[m]]);
					 self->external_entry_points[l].reg_params_size = m + 1;
				}
			}
			debug_print(DEBUG_MAIN, 1, "Entry Point 0x%x: external_entry_point->reg_params_size = 0x%x\n",
				l, self->external_entry_points[l].reg_params_size);
		}
	}
	/* Enter value id/label id of param into phi with src node 0. */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = fill_phi_src_value_id(self, l);
		}
	}
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = fill_phi_dst_size_from_src_size(self, l);
		}
	}

	/* Assign labels to instructions src */
	/* TODO: WIP: Work in progress */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].nodes_size; n++) {
				if (!external_entry_points[l].nodes[n].valid) {
					/* Only output nodes that are valid */
					continue;
				}
				tmp = assign_labels_to_src(self, l, n);
				if (tmp) {
					printf("assign_labels_to_src() failed\n");
					exit(1);
				}
			}
		}
	}

	/* Build TIP table */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].nodes_size; n++) {
				if (!external_entry_points[l].nodes[n].valid) {
					/* Only output nodes that are valid */
					continue;
				}
				tmp = build_tip2_table(self, l, n);
				if (tmp) {
					printf("build_tip_table() failed\n");
					exit(1);
				}
			}
		}
	}
	/* Print TIP rules */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			rule_print(self, l);
		}
	}
	/* Fixup TIP with zext and trunk when integer bit widths vary for a single label. */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tip_fixup_bit_width(self, l);
		}
	}

	/* Print instuctions showing any new ones inserted */
	//print_dis_instructions(self);

	/* Process TIP rules */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tip_rules_process(self, l);
		}
	}
	/* Print TIP results */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tip_result_print(self, l);
		}
	}
#if 0
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			int previous_variable_id = external_entry_points[l].variable_id;
			for(n = 1; n < previous_variable_id; n++) {
				tmp = tip_add_zext(self, l, n);
			}
		}
	}

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].variable_id; n++) {
				tmp = tip_process_label(self, l, n);
			}
		}
	}

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].variable_id; n++) {
				tmp = tip_print_label(self, l, n);
			}
		}
	}
#endif
#if 1
	/* Change ADD to GEP1 where the ADD involves pointers */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].nodes_size; n++) {
				if (!external_entry_points[l].nodes[n].valid) {
					/* Only output nodes that are valid */
					continue;
				}
				tmp = change_add_to_gep1(self, &external_entry_points[l], n);
				if (tmp) {
					printf("change_add_to_gep1() failed\n");
					exit(1);
				}
			}
		}
	}
#endif

	/* turn "MOV reg, reg" into a NOP from the SSA perspective. Make the dst = src label */
	/* FIXME: Comment out mov label merge, due to zext/trunc code */
	/* FIXME: TODO: This needs to be more careful about the merge. */
	/*        It should check that both types are the same before merging */
#if 1
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].nodes_size; n++) {
				if (!external_entry_points[l].nodes[n].valid) {
					/* Only output nodes that are valid */
					continue;
				}
				tmp = redirect_mov_reg_reg_labels(self, &external_entry_points[l], n);
				if (tmp) {
					printf("redirect_mov_reg_reg() failed\n");
					exit(1);
				}
			}
		}
	}
#endif
	/* Discover the function return type */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].nodes_size; n++) {
				uint64_t label_index = 0;
				if (!external_entry_points[l].nodes[n].valid) {
					/* Only output nodes that are valid */
					continue;
				}
				label_index = function_find_return_label(self, &external_entry_points[l], n);
				if (label_index) {
					/* Found the return */
					debug_print(DEBUG_MAIN, 1, "function_return: 0x%x:0x%lx\n", l, label_index);
					external_entry_points[l].function_return_type = label_index;
					break;
				}
			}
		}
	}

	/* For the second time, once function params and return types are discovered */
	/* Process TIP rules */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tip_rules_process(self, l);
		}
	}
	/* Print TIP results */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tip_result_print(self, l);
		}
	}

#if 0
	/* Discover pointer types */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].nodes_size; n++) {
				if (!external_entry_points[l].nodes[n].valid) {
					/* Only output nodes that are valid */
					continue;
				}
				tmp = discover_pointer_types(self, &external_entry_points[l], n);
				if (tmp) {
					printf("discover_pointer_types() failed\n");
					exit(1);
				}
			}
		}
	}

#endif
	//print_dis_instructions(self);

	dump_labels_table(self, buffer);

	/************************************************************
	 * This section deals with correcting SSA for branches/joins.
	 * This bit creates the labels table, ready for the next step.
	 ************************************************************/
//	debug_print(DEBUG_MAIN, 1, "Number of labels = 0x%x\n", self->local_counter);
	/* FIXME: +1 added as a result of running valgrind, but need a proper fix */
//	label_redirect = calloc(self->local_counter + 1, sizeof(struct label_redirect_s));
//	labels = calloc(self->local_counter + 1, sizeof(struct label_s));
//	debug_print(DEBUG_MAIN, 1, "TEST6: self->local_counter=%d\n", self->local_counter);
//	FIXME:  Move the EIP, ESP, EBP pointer tagging to the TIP processing.
#if 0
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			external_entry_points[l].labels[0].lab_pointer = 1; /* EIP */
			external_entry_points[l].labels[1].lab_pointer = 1; /* ESP */
			external_entry_points[l].labels[2].lab_pointer = 1; /* EBP */
		}
	}
#endif
#if 0	
	/* n <= inst_log verified to be correct limit */
	for (n = 1; n <= inst_log; n++) {
		struct label_s label;
		uint64_t value_id;
		uint64_t value_id2;
		uint64_t value_id3;

		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		debug_print(DEBUG_MAIN, 1, "value to log_to_label:n = 0x%x: 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64"\n",
				n,
				instruction->srcA.indirect,
				instruction->srcA.index,
				instruction->srcA.relocated,
				inst_log1->value1.value_scope,
				inst_log1->value1.value_id,
				inst_log1->value1.indirect_offset_value);

		switch (instruction->opcode) {
		case MOV:
		case ADD:
		case ADC:
		case SUB:
		case SBB:
		case MUL:
		case IMUL:
		case OR:
		case XOR:
		case rAND:
		case NOT:
		case NEG:
		case SHL:
		case SHR:
		case SAL:
		case SAR:
		case SEX:
			if (IND_MEM == instruction->dstA.indirect) {
				debug_print(DEBUG_MAIN, 1, "SEX: dstA Illegal indirect\n");
				return 1;
			} else {
				value_id3 = inst_log1->value3.value_id;
			}
			if (value_id3 > self->local_counter) {
				debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
				return 1;
			}
			memset(&label, 0, sizeof(struct label_s));
			tmp = log_to_label(instruction->dstA.store,
				instruction->dstA.indirect,
				instruction->dstA.index,
				instruction->dstA.relocated,
				inst_log1->value3.value_scope,
				inst_log1->value3.value_id,
				inst_log1->value3.indirect_offset_value,
				&label);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x, value3 unknown label %x\n", n);
			}
			if (!tmp && value_id3 > 0) {
				label_redirect[value_id3].redirect = value_id3;
				labels[value_id3].scope = label.scope;
				labels[value_id3].type = label.type;
				labels[value_id3].lab_pointer += label.lab_pointer;
				labels[value_id3].value = label.value;
			}

			if (IND_MEM == instruction->srcA.indirect) {
				debug_print(DEBUG_MAIN, 1, "SEX: srcA Illegal indirect\n");
				return 1;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			if (value_id > self->local_counter) {
				debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
				return 1;
			}
			memset(&label, 0, sizeof(struct label_s));
			tmp = log_to_label(instruction->srcA.store,
				instruction->srcA.indirect,
				instruction->srcA.index,
				instruction->srcA.relocated,
				inst_log1->value1.value_scope,
				inst_log1->value1.value_id,
				inst_log1->value1.indirect_offset_value,
				&label);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x, value1 unknown label %x\n", n);
			}
			if (!tmp && value_id > 0) {
				label_redirect[value_id].redirect = value_id;
				labels[value_id].scope = label.scope;
				labels[value_id].type = label.type;
				labels[value_id].lab_pointer += label.lab_pointer;
				labels[value_id].value = label.value;
			}
			break;

		/* Specially handled because value3 is not assigned and writen to a destination. */
		case TEST:
		case CMP:
			if (IND_MEM == instruction->dstA.indirect) {
				debug_print(DEBUG_MAIN, 1, "CMP: dstA Illegal indirect\n");
				return 1;
			} else {
				value_id2 = inst_log1->value2.value_id;
			}
			if (value_id2 > self->local_counter) {
				debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
				return 1;
			}
			memset(&label, 0, sizeof(struct label_s));
			tmp = log_to_label(instruction->dstA.store,
				instruction->dstA.indirect,
				instruction->dstA.index,
				instruction->dstA.relocated,
				inst_log1->value2.value_scope,
				inst_log1->value2.value_id,
				inst_log1->value2.indirect_offset_value,
				&label);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x, value3 unknown label %x\n", n);
			}
			if (!tmp && value_id2 > 0) {
				label_redirect[value_id2].redirect = value_id2;
				labels[value_id2].scope = label.scope;
				labels[value_id2].type = label.type;
				labels[value_id2].lab_pointer += label.lab_pointer;
				labels[value_id2].value = label.value;
			}

			if (IND_MEM == instruction->srcA.indirect) {
				debug_print(DEBUG_MAIN, 1, "CMP: srcA Illegal indirect\n");
				return 1;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			if (value_id > self->local_counter) {
				debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
				return 1;
			}
			memset(&label, 0, sizeof(struct label_s));
			tmp = log_to_label(instruction->srcA.store,
				instruction->srcA.indirect,
				instruction->srcA.index,
				instruction->srcA.relocated,
				inst_log1->value1.value_scope,
				inst_log1->value1.value_id,
				inst_log1->value1.indirect_offset_value,
				&label);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x, value1 unknown label %x\n", n);
			}
			if (!tmp && value_id > 0) {
				label_redirect[value_id].redirect = value_id;
				labels[value_id].scope = label.scope;
				labels[value_id].type = label.type;
				labels[value_id].lab_pointer += label.lab_pointer;
				labels[value_id].value = label.value;
			}
			break;

		case CALL:
			debug_print(DEBUG_MAIN, 1, "SSA CALL inst_log 0x%x\n", n);
			if (IND_MEM == instruction->dstA.indirect) {
				debug_print(DEBUG_MAIN, 1, "CALL: dstA Illegal indirect\n");
				return 1;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			if (value_id > self->local_counter) {
				debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
				return 1;
			}
			memset(&label, 0, sizeof(struct label_s));
			tmp = log_to_label(instruction->dstA.store,
				instruction->dstA.indirect,
				instruction->dstA.index,
				instruction->dstA.relocated,
				inst_log1->value3.value_scope,
				inst_log1->value3.value_id,
				inst_log1->value3.indirect_offset_value,
				&label);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x, value3 unknown label %x\n", n);
			}
			if (!tmp && value_id > 0) {
				label_redirect[value_id].redirect = value_id;
				labels[value_id].scope = label.scope;
				labels[value_id].type = label.type;
				labels[value_id].lab_pointer += label.lab_pointer;
				labels[value_id].value = label.value;
			}

			if (IND_MEM == instruction->srcA.indirect) {
				debug_print(DEBUG_MAIN, 1, "CALL: srcA Illegal indirect\n");
				return 1;
			} else {
				value_id = inst_log1->value1.value_id;
				if (value_id > self->local_counter) {
					debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
					return 1;
				}
				memset(&label, 0, sizeof(struct label_s));
				tmp = log_to_label(instruction->srcA.store,
					instruction->srcA.indirect,
					instruction->srcA.index,
					instruction->srcA.relocated,
					inst_log1->value1.value_scope,
					inst_log1->value1.value_id,
					inst_log1->value1.indirect_offset_value,
					&label);
				if (tmp) {
					debug_print(DEBUG_MAIN, 1, "Inst:0x, value1 unknown label %x\n", n);
				}
				if (!tmp && value_id > 0) {
					label_redirect[value_id].redirect = value_id;
					labels[value_id].scope = label.scope;
					labels[value_id].type = label.type;
					labels[value_id].lab_pointer += label.lab_pointer;
					labels[value_id].value = label.value;
				}
			}
			break;
		case IF:
		case RET:
		case JMP:
		case JMPT:
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "SSA1 failed for Inst:0x%x, OP 0x%x\n", n, instruction->opcode);
			return 1;
			break;
		}
	}
	for (n = 0; n < self->local_counter; n++) {
		debug_print(DEBUG_MAIN, 1, "labels 0x%x: redirect=0x%"PRIx64", scope=0x%"PRIx64", type=0x%"PRIx64", lab_pointer=0x%"PRIx64", value=0x%"PRIx64"\n",
			n, label_redirect[n].redirect, labels[n].scope, labels[n].type, labels[n].lab_pointer, labels[n].value);
	}
	
	/************************************************************
	 * This section deals with correcting SSA for branches/joins.
	 * It build bi-directional links to instruction operands.
	 * This section does work for local_reg case. FIXME
	 ************************************************************/
	for (n = 1; n < inst_log; n++) {
		uint64_t value_id;
		uint64_t value_id1;
		uint64_t value_id2;
		uint64_t size;
		uint64_t *inst_list;
		uint64_t mid_start_size;
		struct mid_start_s *mid_start;

		size = 0;
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		value_id1 = inst_log1->value1.value_id;
		value_id2 = inst_log1->value2.value_id;
		switch (instruction->opcode) {
		case MOV:
		case LOAD:
		case STORE:
		case ADD:
		case ADC:
		case MUL:
		case OR:
		case XOR:
		case rAND:
		case SHL:
		case SHR:
		case CMP:
		/* FIXME: TODO */
			value_id = label_redirect[value_id1].redirect;
			if ((1 == labels[value_id].scope) &&
				(1 == labels[value_id].type)) {
				debug_print(DEBUG_MAIN, 1, "Found local_reg Inst:0x%x:value_id:0x%"PRIx64"\n", n, value_id1);
				if (0 == inst_log1->prev_size) {
					debug_print(DEBUG_MAIN, 1, "search_back ended\n");
					return 1;
				}
				if (0 < inst_log1->prev_size) {
					mid_start = calloc(inst_log1->prev_size, sizeof(struct mid_start_s));
					mid_start_size = inst_log1->prev_size;
					for (l = 0; l < inst_log1->prev_size; l++) {
						mid_start[l].mid_start = inst_log1->prev[l];
						mid_start[l].valid = 1;
						debug_print(DEBUG_MAIN, 1, "mid_start added 0x%"PRIx64" at 0x%x\n", mid_start[l].mid_start, l);
					}
					tmp = search_back_local_reg_stack(self, mid_start_size, mid_start, 1, inst_log1->instruction.srcA.index, 0, &size, self->search_back_seen, &inst_list);
					if (tmp) {
						debug_print(DEBUG_MAIN, 1, "SSA search_back Failed at inst_log 0x%x\n", n);
						return 1;
					}
				}
			}
			debug_print(DEBUG_MAIN, 1, "SSA inst:0x%x:size=0x%"PRIx64"\n", n, size);
			/* Renaming is only needed if there are more than one label present */
			if (size > 0) {
				uint64_t value_id_highest = value_id;
				inst_log1->value1.prev = calloc(size, sizeof(int *));
				inst_log1->value1.prev_size = size;
				for (l = 0; l < size; l++) {
					struct inst_log_entry_s *inst_log_l;
					inst_log_l = &inst_log_entry[inst_list[l]];
					inst_log1->value1.prev[l] = inst_list[l];
					inst_log_l->value3.next = realloc(inst_log_l->value3.next, (inst_log_l->value3.next_size + 1) * sizeof(inst_log_l->value3.next));
					inst_log_l->value3.next[inst_log_l->value3.next_size] =
						 inst_list[l];
					inst_log_l->value3.next_size++;
					if (label_redirect[inst_log_l->value3.value_id].redirect > value_id_highest) {
						value_id_highest = label_redirect[inst_log_l->value3.value_id].redirect;
					}
					debug_print(DEBUG_MAIN, 1, "rel inst:0x%"PRIx64"\n", inst_list[l]);
				}
				debug_print(DEBUG_MAIN, 1, "Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
					label_redirect[value_id1].redirect,
					value_id_highest);
				label_redirect[value_id1].redirect =
					value_id_highest;
				for (l = 0; l < size; l++) {
					struct inst_log_entry_s *inst_log_l;
					inst_log_l = &inst_log_entry[inst_list[l]];
					debug_print(DEBUG_MAIN, 1, "Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
						label_redirect[inst_log_l->value3.value_id].redirect,
						value_id_highest);
					label_redirect[inst_log_l->value3.value_id].redirect =
						value_id_highest;
				}
			}
			break;
		default:
			break;
		}
	}
	/************************************************************
	 * This section deals with correcting SSA for branches/joins.
	 * It build bi-directional links to instruction operands.
	 * This section does work for local_stack case.
	 ************************************************************/
	for (n = 1; n < inst_log; n++) {
		uint64_t value_id;
		uint64_t value_id1;
		uint64_t size;
		uint64_t *inst_list;
		uint64_t mid_start_size;
		struct mid_start_s *mid_start;

		size = 0;
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		value_id1 = inst_log1->value1.value_id;
		
		if (value_id1 > self->local_counter) {
			debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
			return 1;
		}
		switch (instruction->opcode) {
		case MOV:
		case LOAD:
		case STORE:
		case ADD:
		case ADC:
		case SUB:
		case SBB:
		case MUL:
		case IMUL:
		case OR:
		case XOR:
		case rAND:
		case NOT:
		case NEG:
		case SHL:
		case SHR:
		case SAL:
		case SAR:
		case CMP:
		case TEST:
		case SEX:
			value_id = label_redirect[value_id1].redirect;
			if ((1 == labels[value_id].scope) &&
				(2 == labels[value_id].type)) {
				debug_print(DEBUG_MAIN, 1, "Found local_stack Inst:0x%x:value_id:0x%"PRIx64"\n", n, value_id1);
				if (0 == inst_log1->prev_size) {
					debug_print(DEBUG_MAIN, 1, "search_back ended\n");
					return 1;
				}
				if (0 < inst_log1->prev_size) {
					mid_start = calloc(inst_log1->prev_size, sizeof(struct mid_start_s));
					mid_start_size = inst_log1->prev_size;
					for (l = 0; l < inst_log1->prev_size; l++) {
						mid_start[l].mid_start = inst_log1->prev[l];
						mid_start[l].valid = 1;
						debug_print(DEBUG_MAIN, 1, "mid_start added 0x%"PRIx64" at 0x%x\n", mid_start[l].mid_start, l);
					}
					tmp = search_back_local_reg_stack(self, mid_start_size, mid_start, 2, inst_log1->value1.indirect_init_value, inst_log1->value1.indirect_offset_value, &size, self->search_back_seen, &inst_list);
					if (tmp) {
						debug_print(DEBUG_MAIN, 1, "SSA search_back Failed at inst_log 0x%x\n", n);
						return 1;
					}
				}
			}
			debug_print(DEBUG_MAIN, 1, "SSA inst:0x%x:size=0x%"PRIx64"\n", n, size);
			/* Renaming is only needed if there are more than one label present */
			if (size > 0) {
				uint64_t value_id_highest = value_id;
				inst_log1->value1.prev = calloc(size, sizeof(int *));
				inst_log1->value1.prev_size = size;
				for (l = 0; l < size; l++) {
					struct inst_log_entry_s *inst_log_l;
					inst_log_l = &inst_log_entry[inst_list[l]];
					inst_log1->value1.prev[l] = inst_list[l];
					inst_log_l->value3.next = realloc(inst_log_l->value3.next, (inst_log_l->value3.next_size + 1) * sizeof(inst_log_l->value3.next));
					inst_log_l->value3.next[inst_log_l->value3.next_size] =
						 inst_list[l];
					inst_log_l->value3.next_size++;
					if (label_redirect[inst_log_l->value3.value_id].redirect > value_id_highest) {
						value_id_highest = label_redirect[inst_log_l->value3.value_id].redirect;
					}
					debug_print(DEBUG_MAIN, 1, "rel inst:0x%"PRIx64"\n", inst_list[l]);
				}
				debug_print(DEBUG_MAIN, 1, "Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
					label_redirect[value_id1].redirect,
					value_id_highest);
				label_redirect[value_id1].redirect =
					value_id_highest;
				for (l = 0; l < size; l++) {
					struct inst_log_entry_s *inst_log_l;
					inst_log_l = &inst_log_entry[inst_list[l]];
					debug_print(DEBUG_MAIN, 1, "Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
						label_redirect[inst_log_l->value3.value_id].redirect,
						value_id_highest);
					label_redirect[inst_log_l->value3.value_id].redirect =
						value_id_highest;
				}
			}
			break;
		case IF:
		case RET:
		case JMP:
		case JMPT:
			break;
		case CALL:
			//debug_print(DEBUG_MAIN, 1, "SSA2 failed for inst:0x%x, CALL\n", n);
			//return 1;
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "SSA2 failed for inst:0x%x, OP 0x%x\n", n, instruction->opcode);
			return 1;
			break;
		/* FIXME: TODO */
		}
	}
#endif
	/********************************************************
	 * This section filters out duplicate param_reg entries.
         * from the labels table: FIXME: THIS IS NOT NEEDED NOW
	 ********************************************************/
#if 0
	for (n = 0; n < (self->local_counter - 1); n++) {
		int tmp1;
		tmp1 = label_redirect[n].redirect;
		debug_print(DEBUG_MAIN, 1, "param_reg:scanning base label 0x%x\n", n);
		if ((tmp1 == n) &&
			(labels[tmp1].scope == 2) &&
			(labels[tmp1].type == 1)) {
			int tmp2;
			/* This is a param_stack */
			for (l = n + 1; l < self->local_counter; l++) {
				debug_print(DEBUG_MAIN, 1, "param_reg:scanning label 0x%x\n", l);
				tmp2 = label_redirect[l].redirect;
				if ((tmp2 == n) &&
					(labels[tmp2].scope == 2) &&
					(labels[tmp2].type == 1) &&
					(labels[tmp1].value == labels[tmp2].value) ) {
					debug_print(DEBUG_MAIN, 1, "param_stack:found duplicate\n");
					label_redirect[l].redirect = n;
				}
			}
		}
	}
#endif
	/***************************************************
	 * Register labels in order to print:
	 * 	Function params,
	 *	local vars.
	 ***************************************************/
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid &&
			external_entry_points[l].type == 1) {
		tmp = scan_for_labels_in_function_body(self, l);
		if (tmp) {
			debug_print(DEBUG_MAIN, 1, "Unhandled scan instruction 0x%x\n", l);
			return 1;
		}

		/* Expected param order: %rdi, %rsi, %rdx, %rcx, %r08, %r09 
		                         0x40, 0x38, 0x18, 0x10, 0x50, 0x58, then stack */
		
		debug_print(DEBUG_MAIN, 1, "scanned: params = 0x%x, locals = 0x%x\n",
			external_entry_points[l].params_size,
			external_entry_points[l].locals_size);
		}
	}

#if 0
	/***************************************************
	 * FIXME: temporary here until full param works.
	 * To help LLVM IR output.
	 ***************************************************/
	n = 0;
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		struct external_entry_point_s *entry_point = &(external_entry_points[l]);
		if (entry_point->valid &&
			entry_point->type == 1) {
			for (m = 0; m < entry_point->variable_id; m++) {
				struct label_s *label = &(entry_point->labels[m]);
				if ((label) &&
					(label->scope == 2)) {
					debug_print(DEBUG_MAIN, 1, "sizes: params = 0x%x, locals = 0x%x\n",
						entry_point->params_size,
						entry_point->locals_size);
					(entry_point->params_size)++;
					entry_point->params = realloc(entry_point->params, entry_point->params_size * sizeof(int));
					entry_point->params[entry_point->params_size - 1] = m;

				}
			}
		}
	}
#endif				
	
	/***************************************************
	 * This section takes the external entry point params and orders them into params_reg_ordered
	 ***************************************************/
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid) {
			debug_print(DEBUG_MAIN, 1, "TEST5: entry point valid 0x%x\n", l);
			for (m = 0; m < REG_PARAMS_ORDER_MAX; m++) {
			struct label_s *label;
				for (n = 0; n < external_entry_points[l].params_size; n++) {
					uint64_t tmp_param;
					tmp_param = external_entry_points[l].params[n];
					debug_print(DEBUG_MAIN, 1, "TEST5: labels 0x%lx, params_size=%d\n", tmp_param, external_entry_points[l].params_size);
					/* Sanity check */
					if (tmp_param >= external_entry_points[l].variable_id) {
						debug_print(DEBUG_MAIN, 1, "Invalid entry point 0x%x, l=%d, m=%d, n=%d, params_size=%d\n",
							tmp, l, m, n, external_entry_points[l].params_size);
						return 1;
					}
					label = &(external_entry_points[l].labels[tmp_param]);
					debug_print(DEBUG_MAIN, 1, "TEST5: labels 0x%x\n", external_entry_points[l].params[n]);
					debug_print(DEBUG_MAIN, 1, "TEST5: label=%p, l=%d, m=%d, n=%d\n", label, l, m, n);
					debug_print(DEBUG_MAIN, 1, "reg_params_order = 0x%x,", reg_params_order[m]);
					debug_print(DEBUG_MAIN, 1, " label->value = 0x%"PRIx64"\n", label->value);
					if ((label->scope == 2) &&
						(label->type == 1) &&
						(label->value == reg_params_order[m])) {
						external_entry_points[l].params_reg_ordered[m] = tmp_param;
						external_entry_points[l].params_reg_ordered_size = m + 1;
					}
				}
			}
		}
	}

	/***************************************************
	 * This section takes the external entry point params and orders them into params_stack_ordered
	 ***************************************************/
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid) {
			int stack_size = 0;
			struct label_s *label;
			uint64_t tmp_param;
			for (n = 0; n < external_entry_points[l].params_size; n++) {
				tmp_param = external_entry_points[l].params[n];
				label = &(external_entry_points[l].labels[tmp_param]);
				if ((label->scope == 2) &&
					(label->type == 2)) {
					stack_size++;
				}
			}
			external_entry_points[l].params_stack_ordered = calloc(stack_size, sizeof(int));
			external_entry_points[l].params_stack_ordered_size = stack_size;
			stack_size = 0;
			for (n = 0; n < external_entry_points[l].params_size; n++) {
				tmp_param = external_entry_points[l].params[n];
				label = &(external_entry_points[l].labels[tmp_param]);
				if ((label->scope == 2) &&
					(label->type == 2)) {
					external_entry_points[l].params_stack_ordered[stack_size] = tmp_param;
					stack_size++;
				}
			}
		}
	}

	/***************************************************
	 * This section, PARAM, deals with converting
	 * function params to reference locals.
	 * e.g. Change local0011 = function(param_reg0040);
	 *      to     local0011 = function(local0009);
	 ***************************************************/
#if 0
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for(n = 1; n < external_entry_points[l].nodes_size; n++) {
				if (!external_entry_points[l].nodes[n].valid) {
					/* Only output nodes that are valid */
					continue;
				}
				tmp = call_params_to_locals(self, l, n);
				if (tmp) {
					printf("call_params_to_locals failed\n");
					exit(1);
				}
			}
		}
	}
#endif
	/**************************************************
	 * This section deals with variable types, scanning forwards
	 * FIXME: Need to make this a little more intelligent
	 * It might fall over with complex loops and program flow.
	 * Maybe iterate up and down until no more changes need doing.
	 * Problem with iterations, is that it could suffer from bistable flips
	 * causing the iteration to never exit.
	 **************************************************/
	/* FIXME: change this to per external_entry_point */
#if 0
	for (n = 1; n < inst_log; n++) {
		uint64_t value_id;
		uint64_t value_id3;

		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		debug_print(DEBUG_MAIN, 1, "value to log_to_label:n = 0x%x: 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64"\n",
				n,
				instruction->srcA.indirect,
				instruction->srcA.index,
				instruction->srcA.relocated,
				inst_log1->value1.value_scope,
				inst_log1->value1.value_id,
				inst_log1->value1.indirect_offset_value);

		switch (instruction->opcode) {
		case MOV:
			if (IND_MEM == instruction->dstA.indirect) {
				debug_print(DEBUG_MAIN, 1, "MOV: dstA Illegal indirect\n");
				return 1;
			} else {
				value_id3 = inst_log1->value3.value_id;
			}

			if (IND_MEM == instruction->srcA.indirect) {
				debug_print(DEBUG_MAIN, 1, "MOV: srcA Illegal indirect\n");
				return 1;
			} else {
				value_id = inst_log1->value1.value_id;
			}

			if (labels[value_id3].lab_pointer != labels[value_id].lab_pointer) {
				labels[value_id3].lab_pointer += labels[value_id].lab_pointer;
				labels[value_id].lab_pointer = labels[value_id3].lab_pointer;
			}
			debug_print(DEBUG_MAIN, 1,TEST4: value_id = 0x%"PRIx64", lab_pointer = 0x%"PRIx64", value_id3 = 0x%"PRIx64", lab_pointer = 0x%"PRIx64"\n",
				value_id, labels[value_id].lab_pointer, value_id3, labels[value_id3].lab_pointer);
			break;

		default:
			break;
		}
	}

	/**************************************************
	 * This section deals with variable types, scanning backwards
	 **************************************************/
	for (n = inst_log; n > 0; n--) {
		uint64_t value_id;
		uint64_t value_id3;

		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		debug_print(DEBUG_MAIN, 1, "value to log_to_label:n = 0x%x: 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64"\n",
				n,
				instruction->srcA.indirect,
				instruction->srcA.index,
				instruction->srcA.relocated,
				inst_log1->value1.value_scope,
				inst_log1->value1.value_id,
				inst_log1->value1.indirect_offset_value);

		switch (instruction->opcode) {
		case MOV:
			if (IND_MEM == instruction->dstA.indirect) {
				debug_print(DEBUG_MAIN, 1, "MOV: dstA Illegal indirect\n");
				return 1;
			} else {
				value_id3 = inst_log1->value3.value_id;
			}

			if (IND_MEM == instruction->srcA.indirect) {
				debug_print(DEBUG_MAIN, 1, "MOV: srcA Illegal indirect\n");
				return 1;
			} else {
				value_id = inst_log1->value1.value_id;
			}

			if (labels[value_id3].lab_pointer != labels[value_id].lab_pointer) {
				labels[value_id3].lab_pointer += labels[value_id].lab_pointer;
				labels[value_id].lab_pointer = labels[value_id3].lab_pointer;
			}
			debug_print(DEBUG_MAIN, 1, "TEST4: value_id = 0x%"PRIx64", lab_pointer = 0x%"PRIx64", value_id3 = 0x%"PRIx64", lab_pointer = 0x%"PRIx64"\n",
				value_id, labels[value_id].lab_pointer, value_id3, labels[value_id3].lab_pointer);
			break;

		default:
			break;
		}
	}

#endif

	tmp = analyse_memory_log(self);
	tmp = print_memory_log(self);
	debug_print(DEBUG_MAIN, 1, "analyse_memory_log done\n");

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid) && (external_entry_points[l].type == 1)) {
			debug_print(DEBUG_MAIN, 1, "name = %s\n", external_entry_points[l].name);
			debug_print(DEBUG_MAIN, 1, "params size = 0x%x\n", external_entry_points[l].params_size);
			for (n = 0; n < external_entry_points[l].params_size; n++) {
				debug_print(DEBUG_MAIN, 1, "params = 0x%x\n", external_entry_points[l].params[n]);
			}
		}
	}

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid) && (external_entry_points[l].type == 1)) {
			tmp = output_cfg_dot(self, external_entry_points[l].label_redirect, external_entry_points[l].labels, NULL, l);
		}
	}
	/***************************************************
	 * This section deals with outputting the .c file.
	 ***************************************************/
	filename = "test.c";
	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		debug_print(DEBUG_MAIN, 1, "Failed to open file %s, error=%d\n", filename, fd);
		return 1;
	}
	debug_print(DEBUG_MAIN, 1, ".c fd=%d\n", fd);
	debug_print(DEBUG_MAIN, 1, "writing out to file\n");
	tmp = dprintf(fd, "#include <stdint.h>\n\n");
	debug_print(DEBUG_MAIN, 1, "PRINTING MEMORY_DATA\n");
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		struct process_state_s *process_state;
		if (external_entry_points[l].valid) {
			process_state = &external_entry_points[l].process_state;
			memory_data = process_state->memory_data;
			for (n = 0; n < 4; n++) {
				debug_print(DEBUG_MAIN, 1, "memory_data:0x%x: 0x%"PRIx64" bytes=%d\n",
                                           n, memory_data[n].valid, memory_data[n].length);
				if (memory_data[n].valid) {
	
					tmp = bf_relocated_data(handle_void, memory_data[n].start_address, 4);
					if (tmp) {
						debug_print(DEBUG_MAIN, 1, "int *data%04"PRIx64" = &data%04"PRIx64"\n",
							memory_data[n].start_address,
							memory_data[n].init_value);
						tmp = dprintf(fd, "int *data%04"PRIx64" = &data%04"PRIx64";\n",
							memory_data[n].start_address,
							memory_data[n].init_value);
					} else {
						debug_print(DEBUG_MAIN, 1, "int data%04"PRIx64" = 0x%04"PRIx64"\n",
							memory_data[n].start_address,
							memory_data[n].init_value);
						tmp = dprintf(fd, "int data%04"PRIx64" = 0x%"PRIx64";\n",
							memory_data[n].start_address,
							memory_data[n].init_value);
					}
				}
			}
		}
	}
	tmp = dprintf(fd, "\n");
	debug_print(DEBUG_MAIN, 1, "\n");
#if 0
	for (n = 0; n < 100; n++) {
		param_present[n] = 0;
	}
		
	for (n = 0; n < 10; n++) {
		if (memory_stack[n].start_address > 0x10000) {
			uint64_t present_index;
			present_index = memory_stack[n].start_address - 0x10000;
			if (present_index >= 100) {
				debug_print(DEBUG_MAIN, 1, "param limit reached:memory_stack[%d].start_address == 0x%"PRIx64"\n",
					n, memory_stack[n].start_address);
				continue;
			}
			param_present[present_index] = 1;
			param_size[present_index] = memory_stack[n].length;
		}
	}
	for (n = 0; n < 100; n++) {
		if (param_present[n]) {
			debug_print(DEBUG_MAIN, 1, "param%04x\n", n);
			tmp = param_size[n];
			n += tmp;
		}
	}
#endif

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		/* FIXME: value == 0 for the first function in the .o file. */
		/*        We need to be able to handle more than
		          one function per .o file. */
		if (external_entry_points[l].valid) {
			debug_print(DEBUG_MAIN, 1, "%d:%s:start=%"PRIu64", end=%"PRIu64"\n", l,
					external_entry_points[l].name,
					external_entry_points[l].inst_log,
					external_entry_points[l].inst_log_end);
		}
		if (external_entry_points[l].valid &&
			external_entry_points[l].type == 1) {
			struct process_state_s *process_state;
			int tmp_state;
			struct label_s *label;
			struct tip2_s *tip2;
			
			process_state = &external_entry_points[l].process_state;

			tmp = dprintf(fd, "\n");
			label = &(external_entry_points[l].labels[external_entry_points[l].returned_label]);
			tip2 = &(external_entry_points[l].tip2[external_entry_points[l].returned_label]);
			dprintf(fd, "int%"PRId64"_t ",
				tip2->integer_size);
			if (tip2->pointer) {
				dprintf(fd, "*");
			}
			output_function_name(fd, &external_entry_points[l]);
			/* FIXME: Params */
			if (external_entry_points[l].params_size > 0) {
				char buffer[1024];
				for (n = 0; n < external_entry_points[l].params_size; n++) {
					int label_index;
					label_index = external_entry_points[l].params[n];
					tmp = label_to_string(&external_entry_points[l].labels[label_index], buffer, 1023);
					dprintf(fd, "%s", buffer);
					if (n + 1 < external_entry_points[l].params_size) {
						tmp = dprintf(fd, ", ");
					}
				}
			}
#if 0
			tmp_state = 0;
			/* Output param_reg */
			for (n = 0; n < external_entry_points[l].params_reg_ordered_size; n++) {
				struct label_s *label;
				char buffer[1024];
				label = &(external_entry_points[l].labels[external_entry_points[l].params_reg_ordered[n]]);
				debug_print(DEBUG_MAIN, 1, "reg_params_order = 0x%x, label->value = 0x%"PRIx64"\n", reg_params_order[n], label->value);
				if ((label->scope == 2) &&
					(label->type == 1)) {
					if (tmp_state > 0) {
						dprintf(fd, ", ");
					}
					dprintf(fd, "int%"PRId64"_t ",
						label->size_bits);
					if (label->lab_pointer) {
						dprintf(fd, "*");
					}
					tmp = label_to_string(label, buffer, 1023);
					dprintf(fd, "%s", buffer);
					tmp_state++;
				}
			}
			/* Output param_stack */
			for (n = 0; n < external_entry_points[l].params_size; n++) {
				struct label_s *label;
				char buffer[1024];
				label = &(external_entry_points[l].labels[external_entry_points[l].params[n]]);
				if ((label->scope == 2) &&
					(label->type == 1)) {
					continue;
				}
				if (tmp_state > 0) {
					dprintf(fd, ", ");
				}
				dprintf(fd, "int%"PRId64"_t ",
					label->size_bits);
				if (label->lab_pointer) {
					dprintf(fd, "*");
				}
				tmp = label_to_string(label, buffer, 1023);
				dprintf(fd, "%s", buffer);
				tmp_state++;
			}
#endif
			tmp = dprintf(fd, ")\n{\n");
			for (n = 0; n < external_entry_points[l].locals_size; n++) {
				struct label_s *label;
				struct tip2_s *tip2;
				char buffer[1024];
				label = &(external_entry_points[l].labels[external_entry_points[l].locals[n]]);
				tip2 = &(external_entry_points[l].tip2[external_entry_points[l].locals[n]]);
				dprintf(fd, "\tint%"PRId64"_t ",
					tip2->integer_size);
				if (tip2->pointer) {
					dprintf(fd, "*");
				}
				tmp = label_to_string(label, buffer, 1023);
				dprintf(fd, "%s", buffer);
				dprintf(fd, ";\n");
			}
			dprintf(fd, "\n");
					
			tmp = output_function_body(self, process_state,
				fd,
				external_entry_points[l].inst_log,
				external_entry_points[l].inst_log_end,
				external_entry_points[l].label_redirect,
				external_entry_points[l].labels,
				NULL);
			if (tmp) {
				return 1;
			}
//   This code is not doing anything, so comment it out
//			for (n = external_entry_points[l].inst_log; n <= external_entry_points[l].inst_log_end; n++) {
//			}			
		}
	}

	close(fd);

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid &&
			external_entry_points[l].type == 1) {
			for (n = 1; n < external_entry_points[l].nodes_size; n++) {
				debug_print(DEBUG_MAIN, 1, "TEST11: node:0x%x: next_size = 0x%x\n", n, external_entry_points[l].nodes[n].next_size);
			};
		}
	}
	tmp = llvm_export(self);

	bf_test_close_file(handle_void);
	debug_print(DEBUG_MAIN, 1, "PRINTING REG_DATA\n");
	print_mem(memory_reg, 1);
	debug_print(DEBUG_MAIN, 1, "PRINTING EXEC_BIN_DATA\n");
	for (n = 0; n < self->sections[section_code_index].content_size; n++) {
		debug_print(DEBUG_MAIN, 1, "0x%04x: %d\n", n, memory_used[n]);
	}
	debug_print(DEBUG_MAIN, 1, "PRINTING MEMORY_DATA\n");
	for (n = 0; n < 4; n++) {
		if (memory_data[n].valid) {
			print_mem(memory_data, n);
			debug_print(DEBUG_MAIN, 1, "\n");
		}
	}
	debug_print(DEBUG_MAIN, 1, "PRINTING STACK_DATA\n");
	for (n = 0; n < 10; n++) {
            if (memory_stack[n].valid) {
		print_mem(memory_stack, n);
		debug_print(DEBUG_MAIN, 1, "\n");
            }
	}
	for (n = 0; n < 100; n++) {
		param_present[n] = 0;
	}
		
	for (n = 0; n < 10; n++) {
		if (memory_stack[n].start_address >= tmp) {
			uint64_t present_index;
			present_index = memory_stack[n].start_address - 0x10000;
			if (present_index >= 100) {
				debug_print(DEBUG_MAIN, 1, "param limit reached:memory_stack[%d].start_address == 0x%"PRIx64"\n",
					n, memory_stack[n].start_address);
				continue;
			}
			param_present[present_index] = 1;
			param_size[present_index] = memory_stack[n].length;
		}
	}

	for (n = 0; n < 100; n++) {
		if (param_present[n]) {
			debug_print(DEBUG_MAIN, 1, "param%04x\n", n);
			tmp = param_size[n];
			n += tmp;
		}
	}
#endif
//end_main:
	debug_print(DEBUG_MAIN, 1, "END - FINISHED PROCESSING\n");
	return 0;
}

