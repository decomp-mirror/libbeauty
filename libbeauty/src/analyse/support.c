/*
 *  Copyright (C) 2004  The libbeauty Team
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
 * 05-05-2018 Updates.
 *   Copyright (C) 2004-2018 James Courtier-Dutton James@superbug.co.uk
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

void stack_trace()
{
	void *trace[16];
	char **messages = (char **)NULL;
	int i, trace_size = 0;

	trace_size = backtrace(trace, 16);
	messages = backtrace_symbols(trace, trace_size);
	printf("[stack trace]>>>\n");
	for (i=0; i < trace_size; i++)
		printf("%s\n", messages[i]);
	printf("<<<[stack trace]\n");
	free(messages);
}

#define EIP_START 0x40000000
/* Search the used register table for the value ID to use. */
int get_value_id_from_node_reg(struct self_s *self, int entry_point, int node, int reg, int *value_id)
{
	struct control_flow_node_s *nodes =  self->nodes;
	int inst;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct instruction_s *instruction;
	int ret = 0;

	*value_id = 0;
	printf("get_value:node:0x%x, reg:0x%x\n", node, reg);
	if (node < 1) {
		*value_id = self->external_entry_points[entry_point].param_reg_label[reg];
		printf("get_value:value_id:0x%x\n", *value_id);
		return 0;
	}
	inst = nodes[node].used_register[reg].dst;
	printf("inst:0x%x\n", inst);
	inst_log1 = &inst_log_entry[inst];
	instruction =  &inst_log1->instruction;
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
	case SEX:
		if ((instruction->dstA.store == STORE_REG) &&
			(instruction->dstA.indirect == IND_DIRECT)) {
			*value_id = inst_log1->value3.value_id;
			}
		break;
	/* DSTA = nothing, SRCA, SRCB == DSTA */
	case TEST:
	/* DSTA = nothing, SRCA, SRCB == DSTA */
	case CMP:
		ret = 1;
		break;
	/* DSTA = EAX, SRCN = parameters */
	case CALL:
		if ((instruction->dstA.store == STORE_REG) &&
			(instruction->dstA.indirect == IND_DIRECT)) {
			*value_id = inst_log1->value3.value_id;
			}
		break;
	case IF:
		/* This does nothing to the table */
		ret = 1;
		break;
	/* DSTA = nothing, SRCA, SRCB = nothing */
	case RET:
		ret = 1;
		break;
	/* DSTA = nothing, SRCN = nothing */
	case JMP:
		ret = 1;
		break;
	/* DSTA = nothing, SRCA = table index , but not known yet. = Pointer + 8 * index.
	 * Eventually it will be the label for the index */
	case JMPT:
		ret = 1;
		break;
	default:
		debug_print(DEBUG_MAIN, 1, "FIXME: get_value_id: unknown instruction OP 0x%x\n", instruction->opcode);
		ret = 1;
		break;
	}
	return ret;
}

int init_node_used_register_table(struct self_s *self, int entry_point)
{
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	struct control_flow_node_s *nodes = external_entry_points[entry_point].nodes;
	int nodes_size = external_entry_points[entry_point].nodes_size;
	int node;
	for (node = 1; node < nodes_size; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		nodes[node].used_register = calloc(MAX_REG, sizeof(struct node_used_register_s));
	}
	return 0;
}

int print_node_used_register_table(struct self_s *self, int entry_point)
{
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	struct control_flow_node_s *nodes = external_entry_points[entry_point].nodes;
	int nodes_size = external_entry_points[entry_point].nodes_size;
	int node;
	int n;

	for (node = 1; node < nodes_size; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		for (n = 0; n < MAX_REG; n++) {
			if (nodes[node].used_register[n].seen) {
				debug_print(DEBUG_MAIN, 1, "entry_point 0x%x, node 0x%x:node_used_reg 0x%x:seen=0x%x, size=0x%x, src=0x%x, dst=0x%x, src_first=0x%x, value_id=0x%x, node=0x%x, label=0x%x\n",
					entry_point,
					node,
					n,
					nodes[node].used_register[n].seen,
					nodes[node].used_register[n].size,
					nodes[node].used_register[n].src,
					nodes[node].used_register[n].dst,
					nodes[node].used_register[n].src_first,
					nodes[node].used_register[n].src_first_value_id,
					nodes[node].used_register[n].src_first_node,
					nodes[node].used_register[n].src_first_label);
			}
		}
	}
	return 0;
}

int fill_node_used_register_table(struct self_s *self, int entry_point)
{
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	struct control_flow_node_s *nodes = external_entry_points[entry_point].nodes;
	int nodes_size = external_entry_points[entry_point].nodes_size;
	int node;
	int inst;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct instruction_s *instruction;

	for (node = 1; node < nodes_size; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		inst = nodes[node].inst_start;
		debug_print(DEBUG_MAIN, 1, "Entry_point:0x%x, In Block:0x%x\n", entry_point, node);
		do {
			inst_log1 = &inst_log_entry[inst];
			instruction =  &inst_log1->instruction;
			print_inst(self, instruction, inst, NULL);
			switch (instruction->opcode) {
			case NOP:
				/* Nothing to do */
				break;
			/* DSTA, SRCA, SRCB == nothing */
			case MOV:
			case TRUNC:
			case BITCAST:
				/* If SRC and DST in same instruction, let SRC dominate. */
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1:0x%"PRIx64", SRC\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1\n");
					}
				}
				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect != IND_DIRECT)) {
					debug_print(DEBUG_MAIN, 1, "ERROR: MOV,TRUNC dstA.indirect\n");
					exit(1);
				}

				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->dstA.index].dst = inst;
					debug_print(DEBUG_MAIN, 1, "Seen2:0x%"PRIx64", DST\n", instruction->dstA.index);
					if (nodes[node].used_register[instruction->dstA.index].seen == 0) {
						nodes[node].used_register[instruction->dstA.index].seen = 2;
						nodes[node].used_register[instruction->dstA.index].size = instruction->dstA.value_size;
						debug_print(DEBUG_MAIN, 1, "Set2\n");
					}
				}
				break;
			/* DSTA, SRCA, SRCB == DSTA */
			case LOAD:
				/* If SRC and DST in same instruction, let SRC dominate. */
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect != IND_DIRECT)) {
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1:0x%"PRIx64", SRC\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1\n");
					}
				}
				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect != IND_DIRECT)) {
					debug_print(DEBUG_MAIN, 1, "ERROR: MOV dstA.indirect\n");
					exit(1);
				}

				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->dstA.index].dst = inst;
					debug_print(DEBUG_MAIN, 1, "Seen2:0x%"PRIx64", DST\n", instruction->dstA.index);
					if (nodes[node].used_register[instruction->dstA.index].seen == 0) {
						nodes[node].used_register[instruction->dstA.index].seen = 2;
						nodes[node].used_register[instruction->dstA.index].size = instruction->dstA.value_size;
						debug_print(DEBUG_MAIN, 1, "Set2\n");
					}
				}
				break;
			/* DSTA, SRCA, SRCB == DSTA */
			case STORE:
				/* If SRC and DST in same instruction, let SRC dominate. */
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1:0x%"PRIx64", SRC\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1\n");
					}
				}
				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect != IND_DIRECT)) {
					/* This is a special case, where the dst register is indirect, so actually a src. */
					nodes[node].used_register[instruction->dstA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1D:0x%"PRIx64", DST\n", instruction->dstA.index);
					if (nodes[node].used_register[instruction->dstA.index].seen == 0) {
						nodes[node].used_register[instruction->dstA.index].seen = 1;
						nodes[node].used_register[instruction->dstA.index].size = instruction->dstA.value_size;
						nodes[node].used_register[instruction->dstA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1D\n");
					}
				}

				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect == IND_DIRECT)) {
					debug_print(DEBUG_MAIN, 1, "ERROR: MOV dstA.indirect\n");
					exit(1);
				}
				break;
			/* DSTA, SRCA, SRCB == DSTA */
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
			case ZEXT:
			case ICMP:
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1A:0x%"PRIx64", SRC\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						if (instruction->srcA.value_size == 0) {
							debug_print(DEBUG_MAIN, 1, "ERROR: Size == 0\n");
							exit(1);
						}
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1A\n");
					}
				}
				if ((instruction->srcB.store == STORE_REG) &&
					(instruction->srcB.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->srcB.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1B:0x%"PRIx64" SRC\n", instruction->srcB.index);
					if (nodes[node].used_register[instruction->srcB.index].seen == 0) {
						if (instruction->srcB.value_size == 0) {
							debug_print(DEBUG_MAIN, 1, "ERROR: Size == 0\n");
							exit(1);
						}
						nodes[node].used_register[instruction->srcB.index].seen = 1;
						nodes[node].used_register[instruction->srcB.index].size = instruction->srcB.value_size;
						nodes[node].used_register[instruction->srcB.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1B\n");
					}
				}
				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->dstA.index].dst = inst;
					debug_print(DEBUG_MAIN, 1, "Seen2:0x%"PRIx64", DST\n", instruction->dstA.index);
					if (nodes[node].used_register[instruction->dstA.index].seen == 0) {
						if (instruction->dstA.value_size == 0) {
							debug_print(DEBUG_MAIN, 1, "ERROR: Size == 0\n");
							exit(1);
						}
						nodes[node].used_register[instruction->dstA.index].seen = 2;
						nodes[node].used_register[instruction->dstA.index].size = instruction->dstA.value_size;
						debug_print(DEBUG_MAIN, 1, "Set2\n");
					}
				}
				break;

			/* Specially handled because value3 is not assigned and writen to a destination. */
			/* DSTA = nothing, SRCA, SRCB == DSTA */
			case TEST:
			/* DSTA = nothing, SRCA, SRCB == DSTA */
			case CMP:
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					/* CMP and TEST do not have a dst */
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1A:0x%"PRIx64", SRCA\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1A\n");
					}
				}
				if ((instruction->srcB.store == STORE_REG) &&
					(instruction->srcB.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->srcB.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1B:0x%"PRIx64", SRCB\n", instruction->srcB.index);
					if (nodes[node].used_register[instruction->srcB.index].seen == 0) {
						nodes[node].used_register[instruction->srcB.index].seen = 1;
						nodes[node].used_register[instruction->srcB.index].size = instruction->srcB.value_size;
						nodes[node].used_register[instruction->srcB.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1B\n");
					}
				}
				break;

			/* DSTA = EAX, SRCN = parameters */
			case CALL:
				/* FIXME: TODO params */
				/* Handle RSP and RBP for now */
				nodes[node].used_register[REG_SP].src = inst;
				debug_print(DEBUG_MAIN, 1, "Call Seen RSP\n");
				if (nodes[node].used_register[REG_SP].seen == 0) {
					nodes[node].used_register[REG_SP].seen = 1;
					nodes[node].used_register[REG_SP].size = 64;
					nodes[node].used_register[REG_SP].src_first = inst;
					debug_print(DEBUG_MAIN, 1, "Set1A\n");
				}
				nodes[node].used_register[REG_BP].src = inst;
				debug_print(DEBUG_MAIN, 1, "Call Seen RBP\n");
				if (nodes[node].used_register[REG_BP].seen == 0) {
					nodes[node].used_register[REG_BP].seen = 1;
					nodes[node].used_register[REG_BP].size = 64;
					nodes[node].used_register[REG_BP].src_first = inst;
					debug_print(DEBUG_MAIN, 1, "Set1B\n");
				}
				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->dstA.index].dst = inst;
					debug_print(DEBUG_MAIN, 1, "CALL Seen2:0x%"PRIx64", DST\n", instruction->dstA.index);
					if (nodes[node].used_register[instruction->dstA.index].seen == 0) {
						nodes[node].used_register[instruction->dstA.index].seen = 2;
						nodes[node].used_register[instruction->dstA.index].size = instruction->dstA.value_size;
						debug_print(DEBUG_MAIN, 1, "Set2\n");
					}
				}
				break;

			/* DSTA = EAX, SRCN = parameters */
			case CALLM:
				/* FIXME: TODO params */
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					/* SRCA is the function pointer */
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "CALLM Seen1A:0x%"PRIx64", SRCA\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1A\n");
					}
				}

				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->dstA.index].dst = inst;
					debug_print(DEBUG_MAIN, 1, "CALLM Seen2:0x%"PRIx64", DST\n", instruction->dstA.index);
					if (nodes[node].used_register[instruction->dstA.index].seen == 0) {
						nodes[node].used_register[instruction->dstA.index].seen = 2;
						nodes[node].used_register[instruction->dstA.index].size = instruction->dstA.value_size;
						debug_print(DEBUG_MAIN, 1, "Set2\n");
					}
				}
				break;

			case IF:
				/* This does nothing to the table */
				break;
			case BRANCH:
				/* Branch Conditional */
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					/* CMP and TEST do not have a dst */
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1A:0x%"PRIx64", SRC\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1A\n");
					}
				}
			/* DSTA = nothing, SRCA, SRCB = nothing */
			case RET:
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1:0x%"PRIx64", SRC\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1\n");
					}
				}
				break;
			/* DSTA = nothing, SRCN = nothing */
			case JMP:
			/* DSTA = nothing, SRCA = table index , but not known yet. = Pointer + 8 * index.
			 * Eventually it will be the label for the index */
			case JMPT:
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT) &&
					(nodes[node].used_register[instruction->srcA.index].seen == 0)) {
					/* TODO: Add register src index here */
					debug_print(DEBUG_MAIN, 1, "Seen1:0x%"PRIx64" SET\n", instruction->srcA.index);
					nodes[node].used_register[instruction->srcA.index].seen = 1;
					nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
					nodes[node].used_register[instruction->srcA.index].src_first = inst;
				}
				break;
			default:
				debug_print(DEBUG_MAIN, 1, "FIXME: fill node used register table: unknown instruction OP 0x%x\n", instruction->opcode);
				exit(1);
				break;
			}
		if (!inst_log1->node_end) {
			inst = inst_log1->next[0];
		}

        	} while (!(inst_log1->node_end));
	}
	return 0;
}

int search_back_for_join(struct control_flow_node_s *nodes, int nodes_size, int node, int *phi_node) 
{
	struct control_flow_node_s *this_node;

	*phi_node = 0;
	do {
		this_node = &(nodes[node]);
		if (this_node->prev_size > 1) {
			*phi_node = node;
			return 0;
		}
		if (this_node->prev_size == 1) {
			node = this_node->prev_node[0];
		}
	} while (node > 0 && this_node->prev_size == 1);

	return 1;
}

int add_phi_to_node(struct control_flow_node_s *node, int reg)
{
	int n;

	if (node->phi_size == 0) {
		node->phi = calloc(1, sizeof(struct phi_s));
		node->phi[0].reg = reg;
		node->phi[0].path_node_size = 0;
		node->phi_size = 1;
	} else {
		for (n = 0; n < node->phi_size; n++) {
			if (node->phi[n].reg == reg) {
				return 1;
			}
		}
		node->phi = realloc(node->phi, (node->phi_size + 1) * sizeof(struct phi_s));
		node->phi[node->phi_size].reg = reg;
		node->phi[node->phi_size].path_node_size = 0;
		node->phi_size++;
	}
	return 0;
}

/* Input: path to search in.
 *        node to search for.
 * Output: common base_path that the node is part of.
 *         common base_step that the node is part of.
 */
int path_node_to_base_path(struct self_s *self, struct path_s *paths, int paths_size, int path, int node, int *base_path, int *base_step)
{
	int step;
	int tmp;
	int ret;

	ret = 0;
	*base_path = path;
	step = paths[path].path_size - 1; /* convert size to index */
	*base_step = step;
	tmp = paths[path].path[step];
	if (tmp == node) {
		*base_path = path;
		ret = 0;
		goto exit_path_node_to_base_path;
	}
	while (1) {
		step--;
		if (step < 0) {
			/* If path_prev == path, we have reached the beginning of the path list */
			if (paths[path].path_prev != path) {
				tmp = paths[path].path_prev;
				step = paths[path].path_prev_index;
				path = tmp;
			} else {
				/* Node not found in path */
				ret = 1;
				break;
			}
		}
		tmp = paths[path].path[step];
		if (tmp == node) {
			*base_path = path;
			*base_step = step;
			ret = 0;
			break;
		}
	}
exit_path_node_to_base_path:
	return ret;
}

/* Input: path to search in.
 *        step to step back from.
	  node is the current node.
 * Output: prev_path that is the previous node.
 *         prev_step that is the previous node.
 *	   prev_node
 */
int find_prev_path_step_node(struct self_s *self, struct path_s *paths, int paths_size, int path, int step, int node, int *prev_path, int *prev_step, int *prev_node)
{
	int tmp;
	int ret;

	ret = 0;
	*prev_node = 0;
	*prev_path = 0;
	*prev_step = 0;
	/* Sanity checks */
	if (step > paths[path].path_size - 1) { /* convert size to index */
		ret = 1;
		goto exit_find_prev_path_step_node;
	}
	/* Sanity checks */
	if (path >= paths_size) {
		ret = 1;
		goto exit_find_prev_path_step_node;
	}
	/* Sanity checks */
	tmp = paths[path].path[step];
	if (tmp != node) {
		ret = 1;
		goto exit_find_prev_path_step_node;
	}

	step--;
	if (step < 0) {
		/* If path_prev == path, we have reached the beginning of the path list */
		if (paths[path].path_prev != path) {
			tmp = paths[path].path_prev;
			step = paths[path].path_prev_index;
			path = tmp;
		} else {
			/* finished following path */
			ret = 1;
			goto exit_find_prev_path_step_node;
		}
	}
	*prev_node = paths[path].path[step];
	*prev_path = path;
	*prev_step = step;

exit_find_prev_path_step_node:
	return ret;
}

int fill_node_phi_dst(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size)
{
	int node;
	int phi_node;
	int n;
	int tmp;

	for (node = 1; node < nodes_size; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		tmp = search_back_for_join(nodes, nodes_size, node, &phi_node);
		if (tmp) {
			/* No previous join node found */
			continue;
		}
		for (n = 0; n < MAX_REG; n++) {
			if (nodes[node].used_register[n].seen == 1) {
				debug_print(DEBUG_ANALYSE_PHI, 1, "Adding register 0x%x to phi_node 0x%x\n", n, phi_node);
				tmp = add_phi_to_node(&(nodes[phi_node]), n);
				debug_print(DEBUG_ANALYSE_PHI, 1, "Adding register 0x%x to phi_node 0x%x, status = %d\n", n, phi_node, tmp);
			}
		}
	}
	return 0;
}

int find_phi_src_node_reg(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, struct path_s *paths, int paths_size, int path, int step, int node, int reg, int *src_node, int *first_prev_node)
{
	int prev_path;
	int prev_step;
	int prev_node;
	int tmp = 0;
	int tmp2 = 0;
	int tmp_node;
	int ret = 1;
	int first = 1;
	int n;
	

	*src_node = 0;
	*first_prev_node = 0;
	tmp_node = node;
	while (tmp == 0) {
		tmp = find_prev_path_step_node(self, paths, paths_size, path, step, tmp_node, &prev_path, &prev_step, &prev_node);
		path = prev_path;
		step = prev_step;
		tmp_node = prev_node;
		if (first) {
			*first_prev_node = prev_node;
			first = 0;
		}
		if (tmp == 0) {
			/* Check used_registers of the prev_node. tmp2 points to the last instruction in the node/block */
			tmp2 = nodes[tmp_node].used_register[reg].dst;
			if (node <= 4) {
				debug_print(DEBUG_ANALYSE_PHI, 1, "phi_src:tmp = 0x%x, tmp2 = 0x%x, prev_path = 0x%x, prev_step = 0x%x, prev_node = 0x%x\n", tmp, tmp2, prev_path, prev_step, prev_node);
				}
			if (tmp2) {
				*src_node = tmp_node;
				ret = 0; /* Found */
				goto exit_find_phi_src_node_reg;
			}
			/* Check phi of the prev_node */
			for (n = 0; n < nodes[tmp_node].phi_size; n++) {
				if (nodes[tmp_node].phi[n].reg == reg) {
					*src_node = tmp_node;
					ret = 0; /* Found */
					debug_print(DEBUG_ANALYSE_PHI, 1, "FOUND PHI: node = 0x%x, src_node = 0x%x, reg = 0x%x\n", node, tmp_node, reg);
					goto exit_find_phi_src_node_reg;
				}
			}
		}
	}
exit_find_phi_src_node_reg:
	return ret;
}

int fill_node_phi_src(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size)
{
	int path;
	int node;
	int tmp;
	int node_size_limited;
	int base_path;
	int base_step;
	int src_node;
	int first_prev_node;
	struct path_s *paths;
	int paths_size;
	int reg = 0;
	int n, m;
	struct external_entry_point_s *external_entry_points = self->external_entry_points;

	node_size_limited = nodes_size;
#if 0
	if (node_size_limited > 50) {
		node_size_limited = 50;
	}
#endif
	for (node = 1; node < node_size_limited; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		if (nodes[node].phi_size > 0) {
			for (n = 0; n < nodes[node].phi_size; n++) {
				debug_print(DEBUG_ANALYSE_PHI, 1, "phi_src:node=0x%x, node->entry:0x%x, name=%s\n", node, nodes[node].entry_point,
					external_entry_points[nodes[node].entry_point - 1].name);
				paths = external_entry_points[nodes[node].entry_point - 1].paths;
				paths_size = external_entry_points[nodes[node].entry_point - 1].paths_size;
				debug_print(DEBUG_ANALYSE_PHI, 1, "phi_src:paths = %p, paths_size = 0x%x\n", paths, paths_size);
				reg = nodes[node].phi[n].reg;
				if (nodes[node].path_size > 0) {
					nodes[node].phi[n].path_node = calloc(nodes[node].path_size, sizeof(struct path_node_s));
					nodes[node].phi[n].path_node_size = nodes[node].path_size;
				} else {
					nodes[node].phi[n].path_node_size = 0;
				}
				if (nodes[node].looped_path_size > 0) {
					nodes[node].phi[n].looped_path_node = calloc(nodes[node].looped_path_size, sizeof(struct path_node_s));
					nodes[node].phi[n].looped_path_node_size = nodes[node].looped_path_size;
				} else {
					nodes[node].phi[n].looped_path_node_size = 0;
				}

				for (m = 0; m < nodes[node].path_size; m++) {
					path = nodes[node].path[m];
					tmp = path_node_to_base_path(self, paths, paths_size, path, node, &base_path, &base_step);
					debug_print(DEBUG_ANALYSE_PHI, 1, "path:tmp = %d, reg = 0x%x, base_path = 0x%x, base_step = 0x%x\n", tmp, reg, base_path, base_step);
					tmp = find_phi_src_node_reg(self, nodes, nodes_size, paths, paths_size, base_path, base_step, node, reg, &src_node, &first_prev_node);
					debug_print(DEBUG_ANALYSE_PHI, 1, "path:path = 0x%x, tmp = 0x%x, src_node = 0x%x, first_prev_node = 0x%x\n", path, tmp, src_node, first_prev_node);
					debug_print(DEBUG_ANALYSE_PHI, 1, "node = 0x%x, phi:n = 0x%x, path_node:m = 0x%x\n", node, n, m);
					nodes[node].phi[n].path_node[m].path = path;
					nodes[node].phi[n].path_node[m].first_prev_node = first_prev_node;
					nodes[node].phi[n].path_node[m].node = src_node;
					
				}
				for (m = 0; m < nodes[node].looped_path_size; m++) {
					path = nodes[node].looped_path[m];
					tmp = path_node_to_base_path(self, paths, paths_size, path, node, &base_path, &base_step);
					debug_print(DEBUG_ANALYSE_PHI, 1, "looped_path:tmp = %d, reg = 0x%x, base_path = 0x%x, base_step = 0x%x\n", tmp, reg, base_path, base_step);
					tmp = find_phi_src_node_reg(self, nodes, nodes_size, paths, paths_size, base_path, base_step, node, reg, &src_node, &first_prev_node);
					debug_print(DEBUG_ANALYSE_PHI, 1, "looped_path:path = 0x%x, tmp = 0x%x, src_node = 0x%x, first_prev_node = 0x%x\n", path, tmp, src_node, first_prev_node);
					debug_print(DEBUG_ANALYSE_PHI, 1, "node = 0x%x, phi:n = 0x%x, path_node:m = 0x%x\n", node, n, m);
					nodes[node].phi[n].looped_path_node[m].path = path;
					nodes[node].phi[n].looped_path_node[m].first_prev_node = first_prev_node;
					nodes[node].phi[n].looped_path_node[m].node = src_node;
				}
			}
		}
	}
		
	return 0;
}

int fill_phi_node_list(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size)
{
	int node;
	int n;
	int m;
	int l;
	debug_print(DEBUG_ANALYSE_PHI, 1, "fill_phi: entered\n");

	for (node = 1; node < nodes_size; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		printf("node = 0x%x\n", node);
		if (nodes[node].phi_size > 0) {
			debug_print(DEBUG_ANALYSE_PHI, 1, "nodes[node].phi_size = 0x%x, nodes[node].prev_size = 0x%x\n",
				nodes[node].phi_size,
				nodes[node].prev_size);
			for (n = 0; n < nodes[node].phi_size; n++) {
				nodes[node].phi[n].phi_node = calloc(nodes[node].prev_size, sizeof(struct phi_node_s));
				nodes[node].phi[n].phi_node_size = nodes[node].prev_size;
				for (m = 0; m < nodes[node].prev_size; m++) {
					debug_print(DEBUG_ANALYSE_PHI, 1, "n = 0x%x, m = 0x%x\n", n, m);
					nodes[node].phi[n].phi_node[m].first_prev_node = nodes[node].prev_node[m];
					nodes[node].phi[n].phi_node[m].node = 0;
					nodes[node].phi[n].phi_node[m].path_count = 0;
					nodes[node].phi[n].phi_node[m].value_id = 0;
					for (l = 0; l < nodes[node].phi[n].path_node_size; l++) {
						if (nodes[node].phi[n].path_node[l].first_prev_node == nodes[node].phi[n].phi_node[m].first_prev_node) {
							if ((nodes[node].phi[n].phi_node[m].path_count > 0) &&
								(nodes[node].phi[n].phi_node[m].node != nodes[node].phi[n].path_node[l].node)) {
								debug_print(DEBUG_ANALYSE_PHI, 1, "FAILED at node 0x%x, phi_node = 0x%x, path_node = 0x%x\n",
									node,
									nodes[node].phi[n].phi_node[m].node,
									nodes[node].phi[n].path_node[l].node);
							}
							nodes[node].phi[n].phi_node[m].node = 
								nodes[node].phi[n].path_node[l].node;
							nodes[node].phi[n].phi_node[m].path_count++;
						}
					}
					for (l = 0; l < nodes[node].phi[n].looped_path_node_size; l++) {
						if (nodes[node].phi[n].looped_path_node[l].first_prev_node == nodes[node].phi[n].phi_node[m].first_prev_node) {
							nodes[node].phi[n].phi_node[m].node = 
								nodes[node].phi[n].looped_path_node[l].node;
							nodes[node].phi[n].phi_node[m].path_count++;
						}
					}
					debug_print(DEBUG_ANALYSE_PHI, 1, "fill_phi: first_prev_node = 0x%x, node = 0x%x, path_count = 0x%x\n",
						nodes[node].phi[n].phi_node[m].first_prev_node,
						nodes[node].phi[n].phi_node[m].node,
						nodes[node].phi[n].phi_node[m].path_count);
				}
			}
		}
	}
	debug_print(DEBUG_ANALYSE_PHI, 1, "fill_phi: exit\n");
	return 0;
}

int fill_phi_src_value_id(struct self_s *self, int entry_point)
{
	struct control_flow_node_s *nodes = self->external_entry_points[entry_point].nodes;
	int nodes_size = self->external_entry_points[entry_point].nodes_size;
	struct label_s *labels = self->external_entry_points[entry_point].labels;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int node;
	int n;
	int m;
	int l;
	int inst;
	int node_source;
	int value_id;
	int reg;
	int tmp;
	printf("fill_phi_src_value_id: entered\n");

	for (node = 1; node < nodes_size; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		printf("node = 0x%x\n", node);
		if (nodes[node].phi_size > 0) {
			printf("nodes[node].phi_size = 0x%x, nodes[node].prev_size = 0x%x\n", nodes[node].phi_size, nodes[node].prev_size);
			for (n = 0; n < nodes[node].phi_size; n++) {
				reg = nodes[node].phi[n].reg;
				printf("n = 0x%x, nodes[node].phi[n].reg = 0x%x, phi_node_size = 0x%x\n", n, reg, nodes[node].phi[n].phi_node_size);
				for (m = 0; m < nodes[node].phi[n].phi_node_size; m++) {
					node_source = nodes[node].phi[n].phi_node[m].node;
					printf("m = 0x%x, node_source = 0x%x\n", m, node_source);
					/* FIXME: What to do if node_source == 0 ? */
					if (node_source > 0) {
						inst = nodes[node_source].used_register[reg].dst;
						printf("inst = nodes[node_source].used_register[reg].dst = 0x%x\n", inst);
						if (inst == 0) {
							/* Use the node_source phi instead. */
							for (l = 0; l < nodes[node_source].phi_size; l++) {
								tmp = nodes[node_source].phi[l].reg;
								if (reg == tmp) {
									value_id = nodes[node_source].phi[l].value_id;
									break;
								}
							}
							printf("fill_phi_src_value_id inst = 0x%x, value_id = 0x%x\n", inst, value_id);
						} else {
							/* FIXME: Check that value3 is the same reg */
							inst_log1 =  &inst_log_entry[inst];
							instruction =  &inst_log1->instruction;
							if ((instruction->dstA.store == 1) &&
								(instruction->dstA.indirect == 0) &&
								(instruction->dstA.index == reg)) {
								value_id = inst_log1->value3.value_id;
							} else {
								printf("JCD:VALUE3:fill_phi_src_value_id inst = 0x%x, value_id = 0x%x, reg = 0x0%x\n", inst, value_id, reg);
								print_inst(self, instruction, inst, labels);
								debug_print(DEBUG_ANALYSE_PHI, 1,
									"FAILED: fill_phi_src_value_id: src reg does not equal dst reg\n");
									exit(1);
							}
						}
						if (value_id == 0) {
							printf("FAILED: fill_phi_src_value_id value_id should not be 0\n");
							exit(1);
						}
						nodes[node].phi[n].phi_node[m].value_id = value_id;
					}
				}
			}
		}
	}
	printf("fill_phi_src_value_id: exit\n");
	return 0;
}

int fill_phi_dst_size_from_src_size(struct self_s *self, int entry_point)
{
	struct label_s *labels = self->external_entry_points[entry_point].labels;
	struct label_redirect_s *label_redirect = self->external_entry_points[entry_point].label_redirect;
	struct control_flow_node_s *nodes = self->external_entry_points[entry_point].nodes;
	int nodes_size = self->external_entry_points[entry_point].nodes_size;
	int node;
	int n;
	int m;
	int l;
	int value_id;
	int first_size = 0;
	uint64_t size_bits;
	struct label_s *label;
	printf("fill_phi_dst_size: entered\n");

	for (node = 1; node < nodes_size; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		printf("node = 0x%x\n", node);
		if (nodes[node].phi_size > 0) {
			printf("phi_size = 0x%x, prev_size = 0x%x\n", nodes[node].phi_size, nodes[node].prev_size);
			for (n = 0; n < nodes[node].phi_size; n++) {
				first_size = 0;
				for (m = 0; m < nodes[node].phi[n].phi_node_size; m++) {
					value_id = nodes[node].phi[n].phi_node[m].value_id;
					if (labels[value_id].tip2) {
						size_bits = self->external_entry_points[entry_point].tip2[labels[value_id].tip2].integer_size;
					} else {
						size_bits = 0;
					}
					printf("fill_phi_dst_size node = 0x%x, phi_reg = 0x%x, value_id = 0x%x, size = 0x%lx, label_redirect = 0x%lx:0x%lx\n",
						node, nodes[node].phi[n].reg, value_id, size_bits,
						label_redirect[value_id].domain, label_redirect[value_id].index);
					if (size_bits == 0) {
						continue;
					}
					if ((first_size == 0) && (size_bits != 0)) {
						first_size = size_bits;
					} else if (first_size != size_bits) {
						printf("fill_phi_dst_size src sized do not match first_size 0x%x\n", first_size);
						exit(1);
					}
				}
				value_id = nodes[node].phi[n].value_id;
				//label = &labels[nodes[node].phi[n].value_id];
				printf("fill_phi_dst_size setting phi dst value_id = 0x%x size_bits to 0x%x\n", value_id, first_size);
				self->external_entry_points[entry_point].tip2[labels[value_id].tip2].integer_size = first_size;
				//label->size_bits = first_size;
			}
		}
	}
	printf("fill_phi_dst_size: exit\n");
	return 0;
}

int find_reg_in_phi_list(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, int node, int reg, int *value_id)
{
	int n;
	int ret = 1;

	*value_id = 0;
	for (n = 0; n < nodes[node].phi_size; n++) {
		if (nodes[node].phi[n].reg == reg) {
			ret = 0;
			*value_id = nodes[node].phi[n].value_id;
			break;
		}
	}
	return ret;
}

/* Not need any more as it is built earler without needing the paths */
#if 0
int build_entry_point_node_members(struct self_s *self, struct external_entry_point_s *external_entry_point, int nodes_size)
{
	int *nodes;
	int members_size;
	int members_offset;
	int n, m;
	nodes = calloc(nodes_size + 1, sizeof(int));
	if (!nodes) {
		return 1;
	}
	for (n = 0; n < external_entry_point->paths_size; n++) {
		for (m = 0; m < external_entry_point->paths[n].path_size; m++) {
			nodes[external_entry_point->paths[n].path[m]] = 1;
		}
	}	
	for (n = 0; n < external_entry_point->paths_size; n++) {
		for (m = 0; m < external_entry_point->paths[n].path_size; m++) {
			nodes[external_entry_point->paths[n].path[m]] = 1;
		}
	}
	members_size = 0;
	for (n = 0; n <= nodes_size; n++) {
		if (nodes[n] == 1) {
			members_size++;
		}
	}
	external_entry_point->member_nodes = calloc(members_size, sizeof(int));
	external_entry_point->member_nodes_size = members_size;
	members_offset = 0;
	for (n = 0; n <= nodes_size; n++) {
		if (nodes[n] == 1) {
			external_entry_point->member_nodes[members_offset] = n;
			members_offset++;
		}
	}
	free(nodes);
	return 0;
}
#endif

int print_entry_point_node_members(struct self_s *self, struct external_entry_point_s *external_entry_point)
{
	int n;

	printf("0x%x node Members of function %s\n", external_entry_point->member_nodes_size, external_entry_point->name);
	for (n = 0; n < external_entry_point->member_nodes_size; n++) {
		printf("0x%x ", external_entry_point->member_nodes[n]);
	}
	printf("\n");
	return 0;
}

/* FIXME: Implement */
int search_back_for_register(struct self_s *self, int l, int node, int inst, int source,
						struct label_s *label, int *new_label) {
	/* 1) search back from this instruction until the beginning of the node */
	/* 2) search the PHI instructions for the register. */
	/* 3) search for a previous node. This is only needed is special cases, i.e. only one previous node.
		The step (2) PHI should have taken care of the more than one previous node.
		This step (3) is unlikely to occur. */
	/* 4) reached the beginning of the function. Previous nodes == 0. label it as a param. */
	
	return 0;
}

int assign_id_label_dst(struct self_s *self, int function, int n, struct inst_log_entry_s *inst_log1, struct label_s *label);

int assign_labels_to_dst(struct self_s *self, int entry_point, int node)
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int variable_id = external_entry_point->variable_id;
	int next;
	int inst;
	int tmp;
	
	debug_print(DEBUG_MAIN, 1, "START entry_point = 0x%x, node = 0x%x, Start variable_id = 0x%x\n",
		entry_point, node, variable_id);
	next = nodes[node].inst_start;
	do {
		struct label_s label;
		inst = next;
		inst_log1 =  &inst_log_entry[inst];
		instruction =  &inst_log1->instruction;
		/* returns 0 for id and label set. 1 for error */
		debug_print(DEBUG_MAIN, 1, "START1 entry_point = 0x%x, node = 0x%x, inst = 0x%x, variable_id = 0x%x\n",
			entry_point, node, inst, variable_id);
		debug_print(DEBUG_MAIN, 1, "label address = %p\n", &label);
		tmp  = assign_id_label_dst(self, entry_point, inst, inst_log1, &label);
#if 0
		debug_print(DEBUG_MAIN, 1, "value to log_to_label:inst = 0x%x: 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64"\n",
			inst,
			instruction->dstA.indirect,
			instruction->dstA.index,
			instruction->dstA.relocated,
			inst_log1->value3.value_scope,
			inst_log1->value3.value_id,
			inst_log1->value3.indirect_offset_value);
#endif
		if (!tmp) {
			debug_print(DEBUG_MAIN, 1, "variable_id = %x\n", variable_id);
			if (variable_id >= 10000) {
				debug_print(DEBUG_MAIN, 1, "ERROR: variable_id overrun 10000 limit. Trying to write to %d\n", variable_id);
				exit(1);
			}
			label_redirect[variable_id].domain = 1;
			label_redirect[variable_id].index = variable_id;
			labels[variable_id].scope = label.scope;
			labels[variable_id].type = label.type;
			labels[variable_id].value = label.value;
			//labels[variable_id].size_bits = label.size_bits;
			//labels[variable_id].lab_pointer += label.lab_pointer;
			variable_id++;
			/* Needed by assign_id_label_dst() */
			external_entry_point->variable_id = variable_id;
			debug_print(DEBUG_MAIN, 1, "variable_id increased to = %x\n", variable_id);
		} else {
			debug_print(DEBUG_MAIN, 1, "ERROR: assign_id_label_dst() failed. entry_point = 0x%x, node = 0x%x, inst = 0x%x\n",
				entry_point, node, inst);
			exit(1);
		}

		if (inst_log1->next_size) {
			next = inst_log1->next[0];
		} else if (inst != nodes[node].inst_end) {
			debug_print(DEBUG_MAIN, 1, "ERROR: DST inst 0x%x, entry_point = 0x%x, node = 0x%x next failure. No inst_end!!! inst_end1 = 0x%x, inst_end2 = 0x%x\n",
				inst, entry_point, node, nodes[node].inst_end, nodes[node - 1].inst_end);
			exit(1);
		}
		debug_print(DEBUG_MAIN, 1, "END1\n");
	} while (inst != nodes[node].inst_end);

	debug_print(DEBUG_MAIN, 1, "END variable_id = 0x%x, 0x%x\n", variable_id, self->external_entry_points[entry_point].variable_id);
	return 0;
}

int assign_labels_to_src(struct self_s *self, int entry_point, int node)
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	int l, m, n;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int variable_id = external_entry_point->variable_id;
	uint64_t stack_address;
	uint64_t data_address;
	struct memory_s *memory;
	struct extension_call_s *call;
	int tmp;

	/* n is the node to process */
	int inst;
	int size;
	struct label_s label;
	int found = 0, ret = 1;
	int reg_tracker[MAX_REG];
	char *function_name;
	debug_print(DEBUG_MAIN, 1, "assign_labels_to_src() node 0x%x\n", node);
	/* Initialise the reg_tracker at each node */
	for (m = 0; m < MAX_REG; m++) {
		if (nodes[node].used_register[m].seen == 1) {
			reg_tracker[m] = nodes[node].used_register[m].src_first_value_id;
			debug_print(DEBUG_MAIN, 1, "Node 0x%x: reg 0x%x given value_id = 0x%x\n", node, m,
				reg_tracker[m]);
		} else {
			reg_tracker[m] = 0;
			//debug_print(DEBUG_MAIN, 1, "Node 0x%x: reg 0x%x given value_id zero value\n", node, m);
		}
	}

	inst = nodes[node].inst_start;
	do {
		inst_log1 =  &inst_log_entry[inst];
		instruction =  &inst_log1->instruction;
		switch (instruction->opcode) {
		case NOP:
			break;
		case MOV:
		case BITCAST:
			switch (instruction->srcA.store) {
			case STORE_DIRECT:
				memset(&label, 0, sizeof(struct label_s));
				if (instruction->srcA.indirect == IND_MEM) {
					label.scope = 3;
					label.type = 1;
					//label.lab_pointer = 1;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else if (instruction->srcA.relocated) {
					label.scope = 3;
					label.type = 2;
					//label.lab_pointer = 0;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else {
					label.scope = 3;
					label.type = 3;
					//label.lab_pointer = 0;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				}
				
				inst_log1->value1.value_id = variable_id;
				label_redirect[variable_id].domain = 1;
				label_redirect[variable_id].index = variable_id;
				labels[variable_id].scope = label.scope;
				labels[variable_id].type = label.type;
				//labels[variable_id].lab_pointer += label.lab_pointer;
				labels[variable_id].value = label.value;
				//labels[variable_id].size_bits = label.size_bits;
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:MOV srcA direct given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value1.value_id); 
				variable_id++;
				break;
			case STORE_REG:
				/* FIXME: TODO*/
				switch(instruction->srcA.indirect) {
				case IND_DIRECT:
					inst_log1->value1.value_id = 
						reg_tracker[instruction->srcA.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:MOV srcA given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						inst_log1->value1.value_id);
					break;
				default:
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%04x:MOV UNHANDLED srcA.indirect = 0x%x\n",
						entry_point, inst, instruction->srcA.indirect);
					exit(1);
					break;
				}
				break;
			}

			/* Used to update the reg_tracker while stepping through the assign src */
			switch (instruction->dstA.store) {
			case STORE_DIRECT:
				break;
			case STORE_REG:
				switch(instruction->dstA.indirect) {
				case IND_DIRECT:
					reg_tracker[instruction->dstA.index] = inst_log1->value3.value_id;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: MOV dstA reg 0x%"PRIx64" given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						instruction->dstA.index,
						inst_log1->value3.value_id);
					break;
				case IND_STACK:
					break;
				}
				break;
			}
			break;
		case LOAD:
			switch (instruction->srcA.store) {
			/* Memory pointed to by fixed number pointer */
			case STORE_DIRECT:
				memset(&label, 0, sizeof(struct label_s));
				if (instruction->srcA.indirect == IND_MEM) {
					label.scope = 3;
					label.type = 1;
					//label.lab_pointer = 1;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else if (instruction->srcA.relocated) {
					label.scope = 3;
					label.type = 2;
					//label.lab_pointer = 0;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else {
					label.scope = 3;
					label.type = 3;
					//label.lab_pointer = 0;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				}
				
				inst_log1->value1.value_id = variable_id;
				label_redirect[variable_id].domain = 1;
				label_redirect[variable_id].index = variable_id;
				labels[variable_id].scope = label.scope;
				labels[variable_id].type = label.type;
				//labels[variable_id].lab_pointer += label.lab_pointer;
				labels[variable_id].value = label.value;
				//labels[variable_id].size_bits = label.size_bits;
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:LOAD srcA direct given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value1.value_id); 
				variable_id++;
				break;
			case STORE_REG:
				switch(instruction->srcA.indirect) {
				case IND_STACK:
					stack_address = inst_log1->value1.indirect_init_value + inst_log1->value1.indirect_offset_value;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:LOAD assign_id: stack_address = 0x%"PRIx64"\n",
						entry_point, node, inst, stack_address);
					memory = search_store(
						external_entry_point->process_state.memory_stack,
						stack_address,
						inst_log1->instruction.srcA.indirect_size);
					if (memory) {
						if (memory->value_id) {
							inst_log1->value1.value_id = memory->value_id;
							debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:LOAD srcA reg given value_id = 0x%"PRIx64"\n",
								entry_point, node, inst,
								inst_log1->value1.value_id); 
						} else {
							debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:LOAD stack found: no value_id. stack_address = 0x%"PRIx64"\n",
								entry_point, node, inst, stack_address);

							if (memory->value_scope == 1) {
								/* PARAM stack */
								inst_log1->value1.value_id = variable_id;
								memory->value_id = variable_id;
								memset(&label, 0, sizeof(struct label_s));
								ret = log_to_label(instruction->srcA.store,
									instruction->srcA.indirect,
									instruction->srcA.index,
									instruction->srcA.value_size,
									instruction->srcA.relocated,
									inst_log1->value1.value_scope,
									inst_log1->value1.value_id,
									inst_log1->value1.indirect_offset_value,
									&label);
								if (ret) {
									debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:LOAD srcA unknown label\n",
										entry_point, node, inst);
									exit(1);
								}

								debug_print(DEBUG_MAIN, 1, "value to log_to_label:inst = 0x%x:0x%x:0x%04x: LOAD 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64"\n",
									entry_point,
									node,
									inst,
									instruction->srcA.indirect,
									instruction->srcA.index,
									instruction->srcA.relocated,
									inst_log1->value1.value_scope,
									inst_log1->value1.value_id,
									inst_log1->value1.indirect_offset_value);

								debug_print(DEBUG_MAIN, 1, "variable_id = 0x%x\n", variable_id);
								if (variable_id >= 10000) {
									debug_print(DEBUG_MAIN, 1, "variable_id overrun 10000 limit. Trying to write to %d\n",
											variable_id);
									exit(1);
								}

								external_entry_point->label_redirect[variable_id].domain = 1;
								external_entry_point->label_redirect[variable_id].index = variable_id;
								external_entry_point->labels[variable_id].scope = label.scope;
								external_entry_point->labels[variable_id].type = label.type;
								external_entry_point->labels[variable_id].value = label.value;
								//external_entry_point->labels[variable_id].size_bits = label.size_bits;
								//external_entry_point->labels[variable_id].lab_pointer += label.lab_pointer;
								variable_id++;
							} else if (memory->value_scope == 2) {
								/* LOCAL stack */
								inst_log1->value1.value_id = variable_id;
								memory->value_id = variable_id;
								memset(&label, 0, sizeof(struct label_s));
								ret = log_to_label(instruction->srcA.store,
									instruction->srcA.indirect,
									instruction->srcA.index,
									instruction->srcA.value_size,
									instruction->srcA.relocated,
									inst_log1->value1.value_scope,
									inst_log1->value1.value_id,
									inst_log1->value1.indirect_offset_value,
									&label);
								if (ret) {
									debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:LOAD srcA unknown label\n",
										entry_point, node, inst);
									exit(1);
								}

								debug_print(DEBUG_MAIN, 1, "value to log_to_label:inst = 0x%x:0x%x:0x%04x: LOAD 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64"\n",
									entry_point,
									node,
									inst,
									instruction->srcA.indirect,
									instruction->srcA.index,
									instruction->srcA.relocated,
									inst_log1->value1.value_scope,
									inst_log1->value1.value_id,
									inst_log1->value1.indirect_offset_value);

								debug_print(DEBUG_MAIN, 1, "variable_id = 0x%x\n", variable_id);
								if (variable_id >= 10000) {
									debug_print(DEBUG_MAIN, 1, "variable_id overrun 10000 limit. Trying to write to %d\n",
											variable_id);
									exit(1);
								}

								external_entry_point->label_redirect[variable_id].domain = 1;
								external_entry_point->label_redirect[variable_id].index = variable_id;
								external_entry_point->labels[variable_id].scope = label.scope;
								external_entry_point->labels[variable_id].type = label.type;
								external_entry_point->labels[variable_id].value = label.value;
								//external_entry_point->labels[variable_id].size_bits = label.size_bits;
								//external_entry_point->labels[variable_id].lab_pointer += label.lab_pointer;
								variable_id++;
							} else {
								debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:LOAD value_scope = 0x%x not in param_stack range!\n",
									entry_point, node, inst, memory->value_scope);
								exit(1);
							}
						}
					} else {
						debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:LOAD stack not found: stack_address = 0x%"PRIx64"\n",
							entry_point, node, inst, stack_address);
						exit(1);
						/* FIXME: Handle a new memory case */
					}
					break;
				case IND_MEM:
					inst_log1->value1.value_id = 0;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:LOAD FIXME: srcA mem given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						inst_log1->value1.value_id);
					data_address = inst_log1->value3.indirect_init_value + inst_log1->value3.indirect_offset_value;
					debug_print(DEBUG_MAIN, 1, "assign_id: data_address = 0x%"PRIx64"\n", data_address);
					print_store(external_entry_point->process_state.memory_data);
					memory = search_store(
						external_entry_point->process_state.memory_data,
						data_address,
						inst_log1->instruction.srcA.indirect_size);
					if (memory) {
						debug_print(DEBUG_MAIN, 1, "MEM memory = %p\n", memory);
						if (memory->value_id) {
							inst_log1->value1.value_id = memory->value_id;
							ret = 0;
							break;
						} else {
							inst_log1->value1.value_id = variable_id;
							memory->value_id = variable_id;
							memset(&label, 0, sizeof(struct label_s));
							ret = log_to_label(instruction->srcA.store,
								instruction->srcA.indirect,
								instruction->srcA.index,
								instruction->srcA.value_size,
								instruction->srcA.relocated,
								inst_log1->value1.value_scope,
								inst_log1->value1.value_id,
								inst_log1->value1.indirect_offset_value,
								&label);
							if (ret) {
								debug_print(DEBUG_MAIN, 1, "assign_id: IND_MEM log_to_label failed\n");
								exit(1);
							}
							debug_print(DEBUG_MAIN, 1, "MEM variable_id = 0x%x\n", variable_id);
							if (variable_id >= 10000) {
								debug_print(DEBUG_MAIN, 1, "variable_id overrun 10000 limit. Trying to write to %d\n",
										variable_id);
								exit(1);
							}
							/* FIXME: Should this be domain 2 */
							external_entry_point->label_redirect[variable_id].domain = 1;
							external_entry_point->label_redirect[variable_id].index = variable_id;
							external_entry_point->labels[variable_id].scope = label.scope;
							external_entry_point->labels[variable_id].type = label.type;
							external_entry_point->labels[variable_id].value = label.value;
							//external_entry_point->labels[variable_id].size_bits = label.size_bits;
							//external_entry_point->labels[variable_id].lab_pointer += label.lab_pointer;
							variable_id++;
						}
					} else {
						debug_print(DEBUG_MAIN, 1, "FIXME: assign_id: memory not found for mem address\n");
						exit(1);
					}
					break;
				default:
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:LOAD UNHANDLED srcA.indirect = 0x%x\n",
						entry_point, node, inst, instruction->srcA.indirect);
					exit(1);
					break;
				}
				break;
			}

			switch (instruction->srcB.store) {
			case STORE_DIRECT:
				memset(&label, 0, sizeof(struct label_s));
				if (instruction->srcB.indirect == IND_MEM) {
					label.scope = 3;
					label.type = 1;
					//label.lab_pointer = 1;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				} else if (instruction->srcB.relocated) {
					label.scope = 3;
					label.type = 2;
					//label.lab_pointer = 0;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				} else {
					label.scope = 3;
					label.type = 3;
					//label.lab_pointer = 0;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				}
				
				inst_log1->value2.value_id = variable_id;
				label_redirect[variable_id].domain = 1;
				label_redirect[variable_id].index = variable_id;
				labels[variable_id].scope = label.scope;
				labels[variable_id].type = label.type;
				//labels[variable_id].lab_pointer += label.lab_pointer;
				labels[variable_id].value = label.value;
				//labels[variable_id].size_bits = label.size_bits;
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: LOAD srcB direct given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value2.value_id); 
				variable_id++;
				break;
			case STORE_REG:
				/* FIXME: TODO*/
				switch(instruction->srcB.indirect) {
				case IND_DIRECT:
					inst_log1->value2.value_id = 
						reg_tracker[instruction->srcB.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: LOAD srcB given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						inst_log1->value2.value_id);
					break;
				case IND_STACK:
					stack_address = inst_log1->value2.indirect_init_value + inst_log1->value2.indirect_offset_value;
					debug_print(DEBUG_MAIN, 1, "assign_id: stack_address = 0x%"PRIx64"\n", stack_address);
					memory = search_store(
						external_entry_point->process_state.memory_stack,
						stack_address,
						inst_log1->instruction.srcB.indirect_size);
					if (memory) {
						if (memory->value_id) {
							inst_log1->value2.value_id = memory->value_id;
							debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: LOAD srcB direct given value_id = 0x%"PRIx64"\n",
								entry_point, node, inst,
								inst_log1->value2.value_id); 
						}
					}
				}
				break;
			}

			/* Used to update the reg_tracker while stepping through the assign src */
			switch (instruction->dstA.store) {
			case STORE_DIRECT:
				break;
			case STORE_REG:
				switch(instruction->dstA.indirect) {
				case IND_DIRECT:
					reg_tracker[instruction->dstA.index] = inst_log1->value3.value_id;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: LOAD dstA reg 0x%"PRIx64" given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						instruction->dstA.index,
						inst_log1->value3.value_id);
					break;
				case IND_STACK:
					break;
				}
				break;
			}
			break;
		case STORE:
			switch (instruction->srcA.store) {
			case STORE_DIRECT:
				memset(&label, 0, sizeof(struct label_s));
				if (instruction->srcA.indirect == IND_MEM) {
					label.scope = 3;
					label.type = 1;
					//label.lab_pointer = 1;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else if (instruction->srcA.relocated) {
					label.scope = 3;
					label.type = 2;
					//label.lab_pointer = 0;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else {
					label.scope = 3;
					label.type = 3;
					//label.lab_pointer = 0;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				}
				
				inst_log1->value1.value_id = variable_id;
				label_redirect[variable_id].domain = 1;
				label_redirect[variable_id].index = variable_id;
				labels[variable_id].scope = label.scope;
				labels[variable_id].type = label.type;
				//labels[variable_id].lab_pointer += label.lab_pointer;
				labels[variable_id].value = label.value;
				//labels[variable_id].size_bits = label.size_bits;
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:STORE srcA direct given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value1.value_id); 
				variable_id++;
				break;
			case STORE_REG:
				/* FIXME: TODO*/
				switch(instruction->srcA.indirect) {
				case IND_DIRECT:
					inst_log1->value1.value_id = 
						reg_tracker[instruction->srcA.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:STORE srcA given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						inst_log1->value1.value_id);
					break;
				case IND_STACK:
					stack_address = inst_log1->value1.indirect_init_value + inst_log1->value1.indirect_offset_value;
					debug_print(DEBUG_MAIN, 1, "assign_id:STORE stack_address = 0x%"PRIx64"\n", stack_address);
					memory = search_store(
						external_entry_point->process_state.memory_stack,
						stack_address,
						inst_log1->instruction.srcA.indirect_size);
					if (memory) {
						if (memory->value_id) {
							inst_log1->value1.value_id = memory->value_id;
						}
					}
					break;
				case IND_MEM:
					inst_log1->value1.value_id = 
						reg_tracker[instruction->srcA.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:STORE FIXME srcA given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						inst_log1->value1.value_id);
					exit(1);
					break;
				default:
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:STORE UNHANDLED srcA.indirect = 0x%x\n",
						entry_point, node, inst, instruction->srcA.indirect);
					exit(1);
					break;
				}
				break;
			}
			switch (instruction->srcB.store) {
			case STORE_DIRECT:
				memset(&label, 0, sizeof(struct label_s));
				if (instruction->srcB.indirect == IND_MEM) {
					label.scope = 3;
					label.type = 1;
					//label.lab_pointer = 1;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				} else if (instruction->srcB.relocated) {
					label.scope = 3;
					label.type = 2;
					//label.lab_pointer = 0;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				} else {
					label.scope = 3;
					label.type = 3;
					//label.lab_pointer = 0;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				}
				
				inst_log1->value2.value_id = variable_id;
				label_redirect[variable_id].domain = 1;
				label_redirect[variable_id].index = variable_id;
				labels[variable_id].scope = label.scope;
				labels[variable_id].type = label.type;
				//labels[variable_id].lab_pointer += label.lab_pointer;
				labels[variable_id].value = label.value;
				//labels[variable_id].size_bits = label.size_bits;
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: STORE srcB direct given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value2.value_id); 
				variable_id++;
				break;
			case STORE_REG:
				/* FIXME: TODO*/
				switch(instruction->srcB.indirect) {
				case IND_DIRECT:
					inst_log1->value2.value_id = 
						reg_tracker[instruction->srcB.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: STORE srcA given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						inst_log1->value2.value_id);
					break;
				case IND_STACK:
					stack_address = inst_log1->value2.indirect_init_value + inst_log1->value2.indirect_offset_value;
					debug_print(DEBUG_MAIN, 1, "assign_id: stack_address = 0x%"PRIx64"\n", stack_address);
					memory = search_store(
						external_entry_point->process_state.memory_stack,
						stack_address,
						inst_log1->instruction.srcB.indirect_size);
					if (memory) {
						if (memory->value_id) {
							inst_log1->value2.value_id = memory->value_id;
							debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: STORE srcB direct given value_id = 0x%"PRIx64"\n",
								entry_point, node, inst,
								inst_log1->value2.value_id); 
						}
					}
				}
				break;
			}
			break;
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
		case ZEXT:
		case ICMP:
			switch (instruction->srcA.store) {
			case STORE_DIRECT:
				memset(&label, 0, sizeof(struct label_s));
				if (instruction->srcA.indirect == IND_MEM) {
					label.scope = 3;
					label.type = 1;
					//label.lab_pointer = 1;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else if (instruction->srcA.relocated) {
					label.scope = 3;
					label.type = 2;
					//label.lab_pointer = 1;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else {
					printf("srcA.index = 0x%"PRIx64"\n", instruction->srcA.index);
					label.scope = 3;
					label.type = 3;
					//label.lab_pointer = 0;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				}
				
				inst_log1->value1.value_id = variable_id;
				label_redirect[variable_id].domain = 1;
				label_redirect[variable_id].index = variable_id;
				labels[variable_id].scope = label.scope;
				labels[variable_id].type = label.type;
				//labels[variable_id].lab_pointer += label.lab_pointer;
				labels[variable_id].value = label.value;
				//labels[variable_id].size_bits = label.size_bits;
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: ARITH srcA direct given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value1.value_id); 
				variable_id++;
				break;
			case STORE_REG:
				/* FIXME: TODO*/
				switch(instruction->srcA.indirect) {
				case IND_DIRECT:
					inst_log1->value1.value_id = 
						reg_tracker[instruction->srcA.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: ARITH srcA given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						inst_log1->value1.value_id);
					break;
				case IND_STACK:
					stack_address = inst_log1->value1.indirect_init_value + inst_log1->value1.indirect_offset_value;
					debug_print(DEBUG_MAIN, 1, "assign_id: stack_address = 0x%"PRIx64"\n", stack_address);
					memory = search_store(
						external_entry_point->process_state.memory_stack,
						stack_address,
						inst_log1->instruction.srcA.indirect_size);
					if (memory) {
						if (memory->value_id) {
							inst_log1->value1.value_id = memory->value_id;
							debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: ARITH srcA direct given value_id = 0x%"PRIx64"\n",
								entry_point, node, inst,
								inst_log1->value1.value_id); 
						}
					}
				}
				break;
			}
			switch (instruction->srcB.store) {
			case STORE_DIRECT:
				memset(&label, 0, sizeof(struct label_s));
				if (instruction->srcB.indirect == IND_MEM) {
					label.scope = 3;
					label.type = 1;
					//label.lab_pointer = 1;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				} else if (instruction->srcB.relocated) {
					label.scope = 3;
					label.type = 2;
					//label.lab_pointer = 1;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				} else {
					label.scope = 3;
					label.type = 3;
					//label.lab_pointer = 0;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				}
				
				inst_log1->value2.value_id = variable_id;
				label_redirect[variable_id].domain = 1;
				label_redirect[variable_id].index = variable_id;
				labels[variable_id].scope = label.scope;
				labels[variable_id].type = label.type;
				//labels[variable_id].lab_pointer += label.lab_pointer;
				labels[variable_id].value = label.value;
				//labels[variable_id].size_bits = label.size_bits;
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: ARITH srcB direct given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value2.value_id); 
				variable_id++;
				break;
			case STORE_REG:
				/* FIXME: TODO*/
				switch(instruction->srcB.indirect) {
				case IND_DIRECT:
					inst_log1->value2.value_id = 
						reg_tracker[instruction->srcB.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: ARITH srcB given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						inst_log1->value2.value_id);
					break;
				case IND_STACK:
					stack_address = inst_log1->value2.indirect_init_value + inst_log1->value2.indirect_offset_value;
					debug_print(DEBUG_MAIN, 1, "assign_id: stack_address = 0x%"PRIx64"\n", stack_address);
					memory = search_store(
						external_entry_point->process_state.memory_stack,
						stack_address,
						inst_log1->instruction.srcB.indirect_size);
					if (memory) {
						if (memory->value_id) {
							inst_log1->value2.value_id = memory->value_id;
							debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: ARITH srcB direct given value_id = 0x%"PRIx64"\n",
								entry_point, node, inst,
								inst_log1->value2.value_id); 
						}
					}
				}
				break;
			}
			switch (instruction->dstA.store) {
			case STORE_DIRECT:
				break;
			case STORE_REG:
				switch(instruction->dstA.indirect) {
				case IND_DIRECT:
					reg_tracker[instruction->dstA.index] = inst_log1->value3.value_id;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: ARITH dstA reg 0x%"PRIx64" given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						instruction->dstA.index,
						inst_log1->value3.value_id); 
					break;
				case IND_STACK:
					break;
				}
				break;
			}
			break;
		/* Specially handled because value3 is not assigned and writen to a destination. */
		case TEST:
		case CMP:
			/* FIXME: TODO*/
			switch (instruction->srcA.store) {
			case STORE_DIRECT:
				memset(&label, 0, sizeof(struct label_s));
				if (instruction->srcA.indirect == IND_MEM) {
					label.scope = 3;
					label.type = 1;
					//label.lab_pointer = 1;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else if (instruction->srcA.relocated) {
					label.scope = 3;
					label.type = 2;
					//label.lab_pointer = 0;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else {
					printf("srcA.index = 0x%"PRIx64"\n", instruction->srcA.index);
					label.scope = 3;
					label.type = 3;
					//label.lab_pointer = 0;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				}
				
				inst_log1->value1.value_id = variable_id;
				label_redirect[variable_id].domain = 1;
				label_redirect[variable_id].index = variable_id;
				labels[variable_id].scope = label.scope;
				labels[variable_id].type = label.type;
				//labels[variable_id].lab_pointer += label.lab_pointer;
				labels[variable_id].value = label.value;
				//labels[variable_id].size_bits = label.size_bits;
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: TEST/CMP srcA direct given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value1.value_id); 
				variable_id++;
				break;
			case STORE_REG:
				/* FIXME: TODO*/
				/* srcA */
				//tmp = search_back_for_register(self, l, node, entry_point, inst, 0,
				//	&label, &new_label);
				inst_log1->value1.value_id = 
					reg_tracker[instruction->srcA.index];
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: TEST/CMP srcA given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value1.value_id); 
				break;
			}
			switch (instruction->srcB.store) {
			case STORE_DIRECT:
				memset(&label, 0, sizeof(struct label_s));
				if (instruction->srcB.indirect == IND_MEM) {
					label.scope = 3;
					label.type = 1;
					//label.lab_pointer = 1;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				} else if (instruction->srcB.relocated) {
					label.scope = 3;
					label.type = 2;
					//label.lab_pointer = 0;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				} else {
					label.scope = 3;
					label.type = 3;
					//label.lab_pointer = 0;
					label.value = instruction->srcB.index;
					//label.size_bits = instruction->srcB.value_size;
				}
				
				inst_log1->value2.value_id = variable_id;
				label_redirect[variable_id].domain = 1;
				label_redirect[variable_id].index = variable_id;
				labels[variable_id].scope = label.scope;
				labels[variable_id].type = label.type;
				//labels[variable_id].lab_pointer += label.lab_pointer;
				labels[variable_id].value = label.value;
				//labels[variable_id].size_bits = label.size_bits;
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: TEST/CMP srcB direct given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value2.value_id); 
				variable_id++;
				break;
			case STORE_REG:
				/* FIXME: TODO*/
				/* srcB */
				//search_back_for_register(self, l, node, entry_point, inst, 1,
				//	&label, &new_label);
				inst_log1->value2.value_id = 
					reg_tracker[instruction->srcB.index];
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: TEST/CMP srcB given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value2.value_id); 
				break;
			}
			break;
		case CALL:
			/* FIXME: TODO. Handle the params passed */
			/* Store reg_tracker state in CALL info, for use later.
			 * This is so forward references to as yet unprocessed functions
			 * are handled correctly.
			 */
			if (!(inst_log1->extension)) {
				debug_print(DEBUG_MAIN, 1, "CALL no extension set\n");
				inst_log1->extension = calloc(1, sizeof(struct extension_call_s));
			}
			call = inst_log1->extension;
			for (m = 0; m < MAX_REG; m++) {
				call->reg_tracker[m] = reg_tracker[m];
			}
			for (m = 0; m < MAX_REG; m++) {
				if (call->reg_tracker[m]) {
					debug_print(DEBUG_MAIN, 1, "Inst:0x%x, call->reg_tracker[0x%x] = 0x%x\n",
						inst,
						m,
						call->reg_tracker[m]);
				}
			}
			switch (instruction->srcA.relocated) {
			case 1:
			case 2:
				l = instruction->srcA.index;
				size = self->external_entry_points[l].simple_params_reg_size;
				call->params_reg = calloc(size, sizeof(int));
				call->params_reg_size = size;
				for (n = 0; n < size; n++) {
					int reg = self->external_entry_points[l].simple_params_reg[n];
					int tmp_label = call->reg_tracker[reg];
					call->params_reg[n] = tmp_label;
				}
				break;

			case 3:
				debug_print(DEBUG_MAIN, 1, "srcA.relocated = %d\n", instruction->srcA.relocated);
				debug_print(DEBUG_MAIN, 1, "srcA.index = %ld\n", instruction->srcA.index);
				debug_print(DEBUG_MAIN, 1, "srcA.relocated_external_function = %d\n", instruction->srcA.relocated_external_function);
				l = instruction->srcA.relocated_external_function;
				tmp = input_external_function_get_name(self, l, &function_name);

				debug_print(DEBUG_MAIN, 1, "CALL3a function_name = %s\n",
					function_name);
				tmp = input_external_function_get_size(self, l, &size);

				debug_print(DEBUG_MAIN, 1, "fields_size = %d\n",
					size);
				//    self->external_functions[2].field_type 
				call->params_reg = calloc(size, sizeof(int));
				call->params_reg_size = size;
				for (n = 0; n < size; n++) {
					int reg = reg_params_order[2 + n];
					int tmp_label = call->reg_tracker[reg];
					call->params_reg[n] = tmp_label;
				}
				break;

			default:
				debug_print(DEBUG_MAIN, 1, "srcA.relocated = %d\n", instruction->srcA.relocated);
				exit(1);
				break;
			}

			if (call->params_reg_size > 0) {
				debug_print(DEBUG_MAIN, 1, "first reg 0x%x = 0x%x value\n", call->params_reg[0], call->reg_tracker[call->params_reg[0]]);
			}
			//debug_print(DEBUG_MAIN, 1, "CALL exiting\n");
			//exit(1);
			/* Used to update the reg_tracker while stepping through the assign src */
			switch (instruction->dstA.store) {
			case STORE_DIRECT:
				break;
			case STORE_REG:
				switch(instruction->dstA.indirect) {
				case IND_DIRECT:
					reg_tracker[instruction->dstA.index] = inst_log1->value3.value_id;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: CALL reg 0x%"PRIx64" given value_id = 0x%"PRIx64"\n",
						entry_point, node, inst,
						instruction->dstA.index,
						inst_log1->value3.value_id); 
					break;
				case IND_STACK:
					break;
				}
				break;
			}
			break;
		case IF:
			break;
		case BRANCH:
			switch (instruction->srcA.store) {
			case STORE_DIRECT:
				memset(&label, 0, sizeof(struct label_s));
				if (instruction->srcA.indirect == IND_MEM) {
					label.scope = 3;
					label.type = 1;
					//label.lab_pointer = 1;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else if (instruction->srcA.relocated) {
					label.scope = 3;
					label.type = 2;
					//label.lab_pointer = 0;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				} else {
					label.scope = 3;
					label.type = 3;
					//label.lab_pointer = 0;
					label.value = instruction->srcA.index;
					//label.size_bits = instruction->srcA.value_size;
				}
				
				inst_log1->value1.value_id = variable_id;
				label_redirect[variable_id].domain = 1;
				label_redirect[variable_id].index = variable_id;
				labels[variable_id].scope = label.scope;
				labels[variable_id].type = label.type;
				//labels[variable_id].lab_pointer += label.lab_pointer;
				labels[variable_id].value = label.value;
				//labels[variable_id].size_bits = label.size_bits;
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: BRANCH srcA direct given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value1.value_id); 
				variable_id++;
				break;
			case STORE_REG:
				/* FIXME: TODO*/
				inst_log1->value1.value_id = 
					reg_tracker[instruction->srcA.index];
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x: BRANCH srcA given value_id = 0x%"PRIx64"\n",
					entry_point, node, inst,
					inst_log1->value1.value_id); 
				break;
			}
		case RET:
			inst_log1->value1.value_id = 
				reg_tracker[instruction->srcA.index];
			debug_print(DEBUG_MAIN, 1, "Inst 0x%x:0x%x:0x%04x:RET srcA given value_id = 0x%"PRIx64"\n",
				entry_point, node, inst,
				inst_log1->value1.value_id); 
			external_entry_point->returned_label = inst_log1->value1.value_id;
			break;
		case JMP:
			break;
		case JMPT:
			/* FIXME: TODO*/
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "SSA1 failed for entry point 0x%x, Inst:0x%x:0x%04x, OP 0x%x\n",
				entry_point, node, inst, instruction->opcode);
			exit(1);
			return 1;
			break;
		}
		if (inst == nodes[node].inst_end) {
			found = 1;
		}
		if (inst_log1->next_size > 0) {
			inst = inst_log1->next[0];
		} else {
			/* Exit here */
			found = 1;
		}
	} while (!found);
	external_entry_point->variable_id = variable_id;
	return 0;
}

int check_domain(struct label_redirect_s *label_redirect)
{
	if (1 != label_redirect->domain) {
		debug_print(DEBUG_MAIN, 1, "check_domain failed 0x%lx\n", label_redirect->domain);
		printf("check_domain failed\n");
		//assert(0);
		exit(1);
	}
	return 0;
}


int rule_add(struct self_s *self, int entry_point, int node, int inst, int phi, int operand,
	int label_index, int tipA_derived_from, int tipB_derived_from, int tip_derived_from_this, int pointer, int pointer_to_tip2, int size_bits)
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct tip2_s *tip = external_entry_point->tip2;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int value_id;
	int redirect_value_id;
	int tmp;
	int index;
	struct label_s *label;
	check_domain(&(label_redirect[label_index]));
	uint64_t label_redirect_index = label_redirect[label_index].index;
	label = &labels[label_redirect_index];
	if (label->tip2 == 0) {
		label->tip2 = label_redirect_index;
		tip[label_redirect_index].valid = 1;
		tip[label_redirect_index].associated_label = label_redirect_index;
	};
	struct tip2_s *tip_this = &(tip[label_redirect_index]);
	
	inst_log1 =  &inst_log_entry[inst];
	instruction =  &inst_log1->instruction;
	if (inst) {
		index = tip_this->rule_size;
		tip_this->rule_size++;
		tip_this->rules = realloc(tip_this->rules, sizeof(struct rule_s) * tip_this->rule_size);
		tip_this->rules[index].node = node;
		tip_this->rules[index].inst_number = inst;
		tip_this->rules[index].phi_number = phi;
		tip_this->rules[index].operand = operand;
		tip_this->rules[index].tipA_derived_from = tipA_derived_from;
		tip_this->rules[index].tipB_derived_from = tipB_derived_from;
		tip_this->rules[index].tip_derived_from_this = tip_derived_from_this;
		tip_this->rules[index].pointer = pointer;
		tip_this->rules[index].pointer_to_tip2 = pointer_to_tip2;
		if (pointer) {
			/* If its a pointer, it has no size yet. The size is only filled in if it might be an int */
			tip_this->rules[index].size_bits = 0;
		} else {
			tip_this->rules[index].size_bits = size_bits;
		}
		debug_print(DEBUG_ANALYSE_TIP, 1, "0x%x:0x%lx node = 0x%x, inst = 0x%04x:%s, phi = 0x%x, operand = 0x%x, tipA_derived_from = 0x%x, tipB_derived_from = 0x%x, tip_derived_from_this = 0x%x, pointer = 0x%x, pointer_to_tip2 = 0x%x, size_bits = 0x%x\n",
			label_index,
			label_redirect_index,
			tip_this->rules[index].node,
			tip_this->rules[index].inst_number,
			opcode_table[instruction->opcode],
			tip_this->rules[index].phi_number,
			tip_this->rules[index].operand,
			tip_this->rules[index].tipA_derived_from,
			tip_this->rules[index].tipB_derived_from,
			tip_this->rules[index].tip_derived_from_this,
			tip_this->rules[index].pointer,
			tip_this->rules[index].pointer_to_tip2,
			tip_this->rules[index].size_bits);
		if (label_index == 0) {
			debug_print(DEBUG_ANALYSE_TIP, 1, "ERROR: label_index should not be zero\n");
			exit(1);
		}
	} else if (phi) {

	} else {
	}
	return 0;
}

int rule_print(struct self_s *self, int entry_point) 
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct tip2_s *tip = external_entry_point->tip2;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int l,m;

	debug_print(DEBUG_ANALYSE_TIP, 1, "entered\n");

	for(l = 0; l < 1000; l++) {
		if (tip[l].valid == 0) {
			//debug_print(DEBUG_ANALYSE_TIP, 1, "0x%x empty\n", l);
			continue;
		}
		for(m = 0; m < tip[l].rule_size; m++) {
			inst_log1 =  &inst_log_entry[tip[l].rules[m].inst_number];
			instruction =  &inst_log1->instruction;
			debug_print(DEBUG_ANALYSE_TIP, 1, "0x%x node = 0x%x, inst = 0x%x OP=0x%x:%s, phi = 0x%x, operand = 0x%x, tipA_derived_from = 0x%x, tipB_derived_from = 0x%x, tip_derived_from_this = 0x%x, pointer = 0x%x, pointer_to_tip2 = 0x%x, size_bits = 0x%x\n",
				l,
				tip[l].rules[m].node,
				tip[l].rules[m].inst_number,
				instruction->opcode,
				opcode_table[instruction->opcode],
				tip[l].rules[m].phi_number,
				tip[l].rules[m].operand,
				tip[l].rules[m].tipA_derived_from,
				tip[l].rules[m].tipB_derived_from,
				tip[l].rules[m].tip_derived_from_this,
				tip[l].rules[m].pointer,
				tip[l].rules[m].pointer_to_tip2,
				tip[l].rules[m].size_bits);
		}
	}
	return 0;
}

int tip_result_print(struct self_s *self, int entry_point) 
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct tip2_s *tip = external_entry_point->tip2;
	struct tip2_s *tip_this;
	struct rule_s *rule_this;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int l,m;
	int tmp;
	char buffer[1024];

	debug_print(DEBUG_ANALYSE_TIP, 1, "entered function 0x%x:%s\n", entry_point, external_entry_point->name);

	for(l = 0; l < 1000; l++) {
		tip_this = &(tip[l]);
		if (tip_this->valid == 0) {
			//debug_print(DEBUG_ANALYSE_TIP, 1, "0x%x empty\n", l);
			continue;
		}
		tmp = label_to_string(&(labels[tip_this->associated_label]), &(buffer[0]), 1023);
		debug_print(DEBUG_ANALYSE_TIP, 1, "tip:0x%x, associated_label = 0x%lx:%s, integer = 0x%lx, integer_size = 0x%lx, pointer = 0x%lx, pointer_to_tip = 0x%lx, probability = 0x%x, rule_size = 0x%lx\n",
			l,
			tip_this->associated_label,
			buffer,
			tip_this->integer,
			tip_this->integer_size,
			tip_this->pointer,
			tip_this->pointer_to_tip,
			tip_this->probability,
			tip_this->rule_size);
		for (m = 0; m < tip_this->rule_size; m++) {
			debug_print(DEBUG_ANALYSE_TIP, 1, "    Rule 0x%x node = 0x%x, inst = 0x%x, phi = 0x%x, operand = 0x%x, tipA_derived_from = 0x%x, tipB_derived_from = 0x%x, tip_derived_from_this = 0x%x, pointer = 0x%x, pointer_to_tip2 = 0x%x, size_bits = 0x%x\n",
				m,
				tip_this->rules[m].node,
				tip_this->rules[m].inst_number,
				tip_this->rules[m].phi_number,
				tip_this->rules[m].operand,
				tip_this->rules[m].tipA_derived_from,
				tip_this->rules[m].tipB_derived_from,
				tip_this->rules[m].tip_derived_from_this,
				tip_this->rules[m].pointer,
				tip_this->rules[m].pointer_to_tip2,
				tip_this->rules[m].size_bits);
		}
	}
	return 0;
}

int insert_nop_before(struct self_s *self, int inst, int *new_inst);
int insert_nop_after(struct self_s *self, int inst, int *new_inst);
int dis64_copy_operand(struct self_s *self, int inst_from, int operand_from, int inst_to, int operand_to, int size);

	/* This searches the tip list and discovers:
   If a label is used with different bit widths by different instructions, add a zext
   so that the label can be split into two, and thus not consist of multi-bit-size instructions.
 */
int tip_fixup1(struct self_s *self, int entry_point, int tip_index, int rule_index, int old_size, int new_size)
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	struct label_s *label;
	struct label_s label_local;
	struct tip2_s *tip = external_entry_point->tip2;
	struct tip2_s *tip_this;
	struct rule_s *rule_this;
	int n;
	int tmp;
	int variable_id;
	int variable_id_add_tip;
	int node;

	tip_this = &(tip[tip_index]);
	rule_this = &(tip_this->rules[rule_index]);
//	label = &labels[label_redirect[label_index].redirect];
	int inst_new;
	int inst_modified;
	int operand_modified;

	inst_modified = rule_this->inst_number;
	operand_modified = rule_this->operand;
	node = rule_this->node;
	tmp = insert_nop_before(self, inst_modified, &inst_new);
#if 0
				/* FIXME: Not support LOAD, STORE or MOV inst yet. */
				if (inst_log_entry[inst_modified].instruction.opcode == LOAD) {
					debug_print(DEBUG_ANALYSE_TIP, 1, "ZEXT/TRUNC before unhandled LOAD instruction\n");
					exit(1);
				}
				if (inst_log_entry[inst_modified].instruction.opcode == STORE) {
					debug_print(DEBUG_ANALYSE_TIP, 1, "ZEXT/TRUNC before unhandled STORE instruction\n");
					exit(1);
				}
				if (inst_log_entry[inst_modified].instruction.opcode == MOV) {
					debug_print(DEBUG_ANALYSE_TIP, 1, "ZEXT/TRUNC before unhandled MOV instruction\n");
					/* Need to first separate the label merge that the MOV instruction did,
					   Add the ZEXT/TRUNC.
					   Re-implement the new label merge that rhe MOV instruction should do.
					   NOTE: Maybe move the label merge to later?
					 */
					//exit(1);
				}
#endif
	if (old_size > new_size) {
		inst_log_entry[inst_new].instruction.opcode = TRUNC;
	} else {
		inst_log_entry[inst_new].instruction.opcode = ZEXT;
	}
	inst_log_entry[inst_new].instruction.flags = 0;
	debug_print(DEBUG_ANALYSE_TIP, 1, "label needed zext/trunc: size=0x%x, inst_new=0x%x. tip:0x%x node = 0x%x, inst = 0x%x, phi = 0x%x, operand = 0x%x, pointer = 0x%x, size_bits = 0x%x\n",
		old_size,
		inst_new,
		tip_index,
		rule_this->node,
		rule_this->inst_number,
		rule_this->phi_number,
		rule_this->operand,
		rule_this->pointer,
		rule_this->size_bits);
	tmp = dis64_copy_operand(self, inst_modified, operand_modified, inst_new, 1, old_size);
	tmp = dis64_copy_operand(self, inst_modified, operand_modified, inst_new, 3, new_size);
	inst_log_entry[inst_new].instruction.srcA.value_size = old_size;
	inst_log_entry[inst_new].instruction.dstA.index = REG_TMP3;
	inst_log_entry[inst_new].value3.value_id =
		external_entry_point->variable_id;
	if (operand_modified == 1) {
		inst_log_entry[inst_modified].instruction.srcA.index = REG_TMP3;
	} else if (operand_modified == 2) {
		inst_log_entry[inst_modified].instruction.srcB.index = REG_TMP3;
	} else if (operand_modified == 3) {
		inst_log_entry[inst_modified].instruction.dstA.index = REG_TMP3;
	} else {
		printf("operand out of range.\n");
		exit(1);
	}
	inst_log1 =  &inst_log_entry[inst_new];
	tmp  = assign_id_label_dst(self, entry_point, inst_new, inst_log1, &label_local);
	variable_id = external_entry_point->variable_id;
	variable_id_add_tip = variable_id;
	if (!tmp) {
		debug_print(DEBUG_ANALYSE_TIP, 1, "variable_id = %x\n", variable_id);
		if (variable_id >= 10000) {
			printf("ERROR: variable_id overrun 10000 limit. Trying to write to %d\n", variable_id);
			exit(1);
		}
		label_redirect[variable_id].domain = 1;
		label_redirect[variable_id].index = variable_id;
		labels[variable_id].scope = label_local.scope;
		labels[variable_id].type = label_local.type;
		labels[variable_id].value = label_local.value;
		//labels[variable_id].size_bits = label_local.size_bits;
		//labels[variable_id].lab_pointer += label_local.lab_pointer;
		variable_id++;
		external_entry_point->variable_id = variable_id;
		debug_print(DEBUG_ANALYSE_TIP, 1, "variable_id increased to = %x\n", variable_id);
	} else {
		printf("ERROR: assign_id_label_dst() failed. entry_point = 0x%x, inst = 0x%x\n",
			entry_point, inst_new);
		exit(1);
	}
	if (operand_modified == 1) {
		inst_log_entry[inst_modified].value1.value_id = variable_id_add_tip;
	} else if (operand_modified == 2) {
		inst_log_entry[inst_modified].value2.value_id = variable_id_add_tip;
	} else if (operand_modified == 3) {
		inst_log_entry[inst_modified].value3.value_id = variable_id_add_tip;
	} else {
		printf("operand out of range.\n");
		exit(1);
	}
	/* Now update the tip table with the changes */
	/* Update the tip to point to the new inst.
	   Update the label on the new instruction to include a tip for the
	   new inst, the REG_TMP3 and its label.
	*/
//int rule_add(struct self_s *self, int entry_point, int node, int inst, int phi, int operand,
//	int label_index, int tipA_derived_from, int tipB_derived_from, int tip_derived_from_this, int pointer, int pointer_to_tip2, int size_bits)
	tmp = rule_add(self, entry_point, node, inst_new, 0, 2, variable_id_add_tip, 0, 0, tip_index, 0, 0, new_size);
	tmp = rule_add(self, entry_point, node, inst_modified, 0, operand_modified, variable_id_add_tip, 0, 0, tip_index, 0, 0, new_size);
	rule_this->inst_number = inst_new;
	rule_this->operand = 1;
	rule_this->size_bits = old_size;
	return 0;
}

int tip_fixup_bit_width(struct self_s *self, int entry_point) 
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct tip2_s *tip = external_entry_point->tip2;
	struct tip2_s *tip_this;
	struct rule_s *rule_this;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int l,m;
	int size;

	debug_print(DEBUG_ANALYSE_TIP, 1, "entered\n");

	for(l = 0; l < 1000; l++) {
		tip_this = &(tip[l]);
		size = 0;
		if (tip_this->valid == 0) {
			//debug_print(DEBUG_ANALYSE_TIP, 1, "0x%x empty\n", l);
			continue;
		}
		for(m = 0; m < tip[l].rule_size; m++) {
			rule_this = &(tip_this->rules[m]);
			inst_log1 =  &inst_log_entry[rule_this->inst_number];
			instruction =  &inst_log1->instruction;
			if (!rule_this->pointer) {
				if (rule_this->size_bits) {
					debug_print(DEBUG_ANALYSE_TIP, 1, "0x%x:0x%x size = 0x%x\n", l, m, rule_this->size_bits);
					if ((size) && (rule_this->size_bits != size)) {
						printf("integer size varying. Need to add TRUNC or ZEXT or SEX in.\n");
						tip_fixup1(self, entry_point, l, m, size, rule_this->size_bits);
					}
					size = rule_this->size_bits;
				}
			}
		}
	}
	return 0;
}

int tip_rules_process(struct self_s *self, int entry_point) 
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct tip2_s *tip = external_entry_point->tip2;
	struct tip2_s *tip_this;
	struct rule_s *rule_this;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int l,m;
	int size;
	uint64_t index;
	uint64_t lab_pointer;
	uint64_t size_bits;
	int return_index;
	int tmp;


	debug_print(DEBUG_ANALYSE_TIP, 1, "entered\n");

	for(l = 0; l < 1000; l++) {
		tip_this = &(tip[l]);
		size = 0;
		if (tip_this->valid == 0) {
			//debug_print(DEBUG_ANALYSE_TIP, 1, "0x%x empty\n", l);
			continue;
		}
		for(m = 0; m < tip[l].rule_size; m++) {
			rule_this = &(tip_this->rules[m]);
			inst_log1 =  &inst_log_entry[rule_this->inst_number];
			instruction =  &inst_log1->instruction;
			debug_print(DEBUG_ANALYSE_TIP, 1, "Inst 0x%x: Opcode 0x%x\n", rule_this->inst_number, instruction->opcode);
			switch (instruction->opcode) {
			case CALL:
				/* FIXME: We should really do this in the order of depth first using the call dependancy graph.*/
				switch (instruction->srcA.relocated) {
				case 1:
				case 2:
					return_index = self->external_entry_points[instruction->srcA.index].function_return_type;
					lab_pointer = self->external_entry_points[instruction->srcA.index].tip2[return_index].pointer;
					size_bits = self->external_entry_points[instruction->srcA.index].tip2[return_index].integer_size;
					if (lab_pointer) {
						/* Pointer type */
						rule_this->pointer = 1;
					} else {
						/* Integer type */
						rule_this->size_bits = size_bits;
						debug_print(DEBUG_ANALYSE_TIP, 1, "Setting TIP to 0x%x bits\n", rule_this->size_bits);
					}
					break;
				case 3:
					tmp = input_external_function_get_return_type(self, instruction->srcA.relocated_external_function, &lab_pointer, &size_bits);
					/* FIXME: Handle more different types. */
					if (lab_pointer) {
						/* Pointer type */
						rule_this->pointer = 1;
					} else {
						/* Integer type */
						rule_this->size_bits = size_bits;
						debug_print(DEBUG_ANALYSE_TIP, 1, "Setting TIP to 0x%x bits\n", rule_this->size_bits);
					}
					break;
				default:
					debug_print(DEBUG_ANALYSE_TIP, 1, "CALL type not implemented yet relocated = 0x%x\n", instruction->srcA.relocated);
					exit(1);
					break;
				}
				// Fall thought
			default:
				if (rule_this->pointer) {
					tip_this->pointer = 1;
					if (rule_this->pointer_to_tip2) {
						tip_this->pointer_to_tip = rule_this->pointer_to_tip2;
						/* A pointer has no size yet */
						tip_this->integer_size = 0;
					}
				} else {
					if (rule_this->size_bits) {
						debug_print(DEBUG_ANALYSE_TIP, 1, "0x%x:0x%x size = 0x%x\n", l, m, rule_this->size_bits);
						if ((size) && (rule_this->size_bits != size)) {
							printf("integer size varying. Need to add TRUNC or ZEXT or SEX in.\n");
							exit(1);
						}
						size = rule_this->size_bits;
					}
				}
			}
		}
		if ((tip_this->pointer == 0) && size) {
			tip_this->integer_size = size;
		}
	}
	return 0;
}

int is_pointer_reg(struct operand_s *operand) {

	if ((operand->store == 1) &&
		(operand->index >= REG_SP) && 
		(operand->index <= REG_BP)) {
		return 1;
	}
	return 0;
}

int is_pointer_mem(struct label_s *labels, int value_id)
{
	struct label_s *label = &labels[value_id];
	int mem = 0;
	debug_print(DEBUG_ANALYSE_TIP, 1, "label: scope = 0x%lx type = 0x%lx\n", label->scope, label->type);
	if ((3 == label->scope) && (2 == label->type)) {
		mem = 1;
	}
/* FIXME: detect a @data0  type */
	return mem;
}


/* The TIP table is build initially to identify pointers first.
 * It can do this from the LOAD and STORE instructions.
 * It can also do this by analysing instructions that have stack pointers as operands.
 * value_id == 3 is the EIP on the stack.
 */
int build_tip2_table(struct self_s *self, int entry_point, int node)
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct tip2_s *tip2 = external_entry_point->tip2;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	struct label_s *label;
	int inst;
	int found = 0;
	int ret = 1;
	int tmp;
	int value_id, value_id1, value_id2, value_id3;
	int size_bits1, size_bits2, size_bits3;
	int is_pointer = 0;
	int is_pointer1 = 0;
	int is_pointer2 = 0;
	int is_pointer3 = 0;

	debug_print(DEBUG_ANALYSE_TIP, 1, "entered\n");
	inst = nodes[node].inst_start;
	do {
		inst_log1 =  &inst_log_entry[inst];
		instruction =  &inst_log1->instruction;
		switch (instruction->opcode) {
//int rule_add(struct self_s *self, int entry_point, int node, int inst, int phi, int operand,
//	int label_index, int tipA_derived_from, int tipB_derived_from, int tip_derived_from_this, int pointer, int pointer_to_tip2, int size_bits)
		case NOP:
			break;

		case MOV:
			value_id1 = inst_log1->value1.value_id;
			value_id3 = inst_log1->value3.value_id;
			size_bits1 = instruction->srcA.value_size;
			size_bits3 = instruction->dstA.value_size;
			is_pointer1 = is_pointer_reg(&(instruction->srcA));
			is_pointer2 = is_pointer_reg(&(instruction->dstA));
			is_pointer = is_pointer1 | is_pointer2;
			if (value_id1 == 3) is_pointer = 1;
			if (value_id3 == 3) is_pointer = 1;
			if (1 == instruction->srcA.relocated) {
				is_pointer = 1;
			}
			tmp = rule_add(self, entry_point, node, inst, 0, 1, value_id1, 0, 0, value_id3, is_pointer, 0, size_bits1);
			tmp = rule_add(self, entry_point, node, inst, 0, 3, value_id3, value_id1, 0, 0, is_pointer, 0, size_bits3);
			ret = 0;
			break;

		case BITCAST:
			value_id1 = inst_log1->value1.value_id;
			value_id3 = inst_log1->value3.value_id;
			size_bits1 = 0;
			size_bits3 = 0;
			is_pointer = 1;
			tmp = rule_add(self, entry_point, node, inst, 0, 1, value_id1, 0, 0, value_id3, is_pointer, 0, size_bits1);
			tmp = rule_add(self, entry_point, node, inst, 0, 3, value_id3, value_id1, 0, 0, is_pointer, 0, size_bits3);
			ret = 0;
			break;

		case LOAD:
			/* If the destination is a pointer register, the source must also be a pointer */
			value_id1 = inst_log1->value1.value_id;
			value_id2 = inst_log1->value2.value_id;
			value_id3 = inst_log1->value3.value_id;
			size_bits1 = instruction->srcA.value_size;
			size_bits2 = instruction->srcB.value_size;
			size_bits3 = instruction->dstA.value_size;
			is_pointer1 = is_pointer3 = is_pointer_reg(&(instruction->dstA));
			is_pointer2 = 1;
			if (value_id1 == 3) is_pointer1 = 1;
			if (value_id2 == 3) is_pointer2 = 1;
			if (value_id3 == 3) is_pointer3 = 1;
			tmp = rule_add(self, entry_point, node, inst, 0, 1, value_id1, 0, 0, value_id3, is_pointer1, 0, size_bits1);
			tmp = rule_add(self, entry_point, node, inst, 0, 2, value_id2, 0, 0, 0, is_pointer2, value_id1, size_bits2);
			tmp = rule_add(self, entry_point, node, inst, 0, 3, value_id3, value_id1, 0, 0, is_pointer3, 0, size_bits3);
			ret = 0;
			break;

		case STORE:
			/* If the source is a pointer register, the destination must also be a pointer */
			value_id1 = inst_log1->value1.value_id;
			value_id2 = inst_log1->value2.value_id;
			value_id3 = inst_log1->value3.value_id;
			size_bits1 = instruction->srcA.value_size;
			size_bits2 = instruction->srcB.value_size;
			size_bits3 = instruction->dstA.value_size;
			is_pointer1 = is_pointer3 = is_pointer_reg(&(instruction->srcA));
			if (value_id1 == 3) is_pointer1 = is_pointer3 = 1;
			tmp = rule_add(self, entry_point, node, inst, 0, 1, value_id1, 0, 0, value_id3, is_pointer1, 0, size_bits1);
			tmp = rule_add(self, entry_point, node, inst, 0, 2, value_id2, 0, 0, 0, 1, value_id3, size_bits2);
			tmp = rule_add(self, entry_point, node, inst, 0, 3, value_id3, value_id1, 0, 0, is_pointer3, 0, size_bits3);
			ret = 0;
			break;

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
		case ZEXT:
		case ICMP:
			value_id = inst_log1->value1.value_id;
			check_domain(&(label_redirect[value_id]));
			value_id1 = label_redirect[value_id].index;
			value_id = inst_log1->value2.value_id;
			check_domain(&(label_redirect[value_id]));
			value_id2 = label_redirect[value_id].index;
			value_id = inst_log1->value3.value_id;
			check_domain(&(label_redirect[value_id]));
			value_id3 = label_redirect[value_id].index;
			size_bits1 = instruction->srcA.value_size;
			size_bits2 = instruction->srcB.value_size;
			size_bits3 = instruction->dstA.value_size;
			is_pointer1 = is_pointer_reg(&(instruction->srcA));
			if (is_pointer_mem(labels, value_id1)) {
				is_pointer1 = 1;
			}
			if (value_id1 == 3) is_pointer1 = 1;
			is_pointer2 = is_pointer_reg(&(instruction->srcB));
			if (is_pointer_mem(labels, value_id2)) {
				is_pointer2 = 1;
			}
			if (value_id2 == 3) is_pointer2 = 1;
			is_pointer3 = is_pointer_reg(&(instruction->dstA));
			if (is_pointer_mem(labels, value_id3)) {
				is_pointer3 = 1;
			}
			if (value_id3 == 3) is_pointer3 = 1;
			debug_print(DEBUG_ANALYSE_TIP, 1, "ADD-SUB is_p1 0x%x, is_p2 0x%x, is_p3 0x%x\n",
					is_pointer1,
					is_pointer2,
					is_pointer3);
			tmp = rule_add(self, entry_point, node, inst, 0, 1, value_id1, 0, 0, value_id3, is_pointer1, 0, size_bits1);
			tmp = rule_add(self, entry_point, node, inst, 0, 2, value_id2, 0, 0, value_id3, is_pointer2, 0, size_bits2);
			tmp = rule_add(self, entry_point, node, inst, 0, 3, value_id3, value_id1, value_id2, 0, is_pointer3, 0, size_bits3);
			ret = 0;
			break;

		case RET:
			value_id1 = inst_log1->value1.value_id;
			//size_bits3 = instruction->dstA.value_size;
			size_bits3 = 0;
			tmp = rule_add(self, entry_point, node, inst, 0, 1, value_id1, 0, 0, 0, 0, 0, size_bits3);
			//value_id = inst_log1->value3.value_id;
			//tmp = tip_add(self, entry_point, node, inst, 0, 3, value_id, 0, 0, 0, instruction->dstA.value_size);
			ret = 0;
			break;

		case JMP:
			/* No value_id with JMP */
			/* FIXME: Test the case where the operand is a register. */
			/*        That will probably be the JMPT case */
			ret = 0;
			break;

		case BRANCH:
			value_id1 = inst_log1->value1.value_id;
			/* size_bits = 1 for a BRANCH */
			tmp = rule_add(self, entry_point, node, inst, 0, 1, value_id1, 0, 0, 0, 0, 0, 1);
			ret = 0;
			break;

		case CALL:
			/* FIXME: No info yet. */
			value_id3 = inst_log1->value3.value_id;
			//size_bits3 = instruction->dstA.value_size;
			size_bits3 = 0; // FIXME. Need to derive this
			tmp = rule_add(self, entry_point, node, inst, 0, 3, value_id3, 0, 0, 0, 0, 0, size_bits3);
			ret = 0;
			break;

		default:
			debug_print(DEBUG_ANALYSE_TIP, 1, "build_tip_table failed for Inst:0x%x:0x%04x, OP 0x%x\n",
				entry_point, inst, instruction->opcode);
			exit(1);
			goto exit1;
		}
		if (inst == nodes[node].inst_end) {
			found = 1;
		}
		if (inst_log1->next_size > 0) {
			inst = inst_log1->next[0];
		} else {
			/* Exit here */
			found = 1;
		}
	} while (!found);
exit1:
	return ret;
}

#if 0
int tip_process_label(struct self_s *self, int entry_point, int label_index)
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	struct label_s *label;
	int n;

	label = &labels[label_redirect[label_index].redirect];
	if ((label->scope != 0) && (label->tip_size > 0) &&
		(label_redirect[label_index].redirect == label_index)) {
		for (n = 0; n < label->tip_size; n++) {
			if (label->tip[n].lab_pointer_first) {
				label->size_bits = label->tip[n].lab_size_first;
				label->pointer_type_size_bits = label->tip[n].lab_pointed_to_size;
				if (label->tip[n].lab_pointed_to_size != 64) {
					label->pointer_type = 2; /* INT */
				}
				label->lab_pointer += label->tip[n].lab_pointer_first;
			}
		}
	}
	return 0;
}
#endif

int dis64_copy_operand(struct self_s *self, int inst_from, int operand_from, int inst_to, int operand_to, int size)
{
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct operand_s operand;
	struct memory_s value;
	printf("inst_from = 0x%x, operand_from = 0x%x\n", inst_from, operand_from);

	if (operand_from == 1) {
		memcpy(&operand, &(inst_log_entry[inst_from].instruction.srcA), sizeof(struct operand_s));
		memcpy(&value, &(inst_log_entry[inst_from].value1), sizeof(struct memory_s));
	} else if (operand_from == 2) {
		memcpy(&operand, &(inst_log_entry[inst_from].instruction.srcB), sizeof(struct operand_s));
		memcpy(&value, &(inst_log_entry[inst_from].value2), sizeof(struct memory_s));
	} else if (operand_from == 3) {
		memcpy(&operand, &(inst_log_entry[inst_from].instruction.dstA), sizeof(struct operand_s));
		memcpy(&value, &(inst_log_entry[inst_from].value3), sizeof(struct memory_s));
	} else {
		printf("dis64_copy_operand: Unknown operand_from 0x%x. Out of range\n", operand_from);
		stack_trace();
		abort();
	}
	if (operand_to == 1) {
		memcpy(&(inst_log_entry[inst_to].instruction.srcA), &operand, sizeof(struct operand_s));
		memcpy(&(inst_log_entry[inst_to].value1), &value, sizeof(struct memory_s));
	} else if (operand_to == 2) {
		memcpy(&(inst_log_entry[inst_to].instruction.srcB), &operand, sizeof(struct operand_s));
		memcpy(&(inst_log_entry[inst_to].value2), &value, sizeof(struct memory_s));
	} else if (operand_to == 3) {
		memcpy(&(inst_log_entry[inst_to].instruction.dstA), &operand, sizeof(struct operand_s));
		memcpy(&(inst_log_entry[inst_to].value3), &value, sizeof(struct memory_s));
	} else {
		printf("dis64_copy_operand: Unknown operand_to 0x%x. Out of range\n", operand_to);
		stack_trace();
		abort();
	}

	return 0;
}

#if 0
/* This searches the tip list and discovers:
   If a label is used with different bit widths by different instructions, add a zext
   so that the label can be split into two, and thus not consist of multi-bit-size instructions.
 */
int tip_add_zext(struct self_s *self, int entry_point, int label_index)
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	struct label_s *label;
	struct label_s label_local;
	int n;
	int tmp;
	int variable_id;
	int variable_id_add_tip;
	int node;

	label = &labels[label_redirect[label_index].redirect];
	if ((label->scope != 0) && (label->tip_size > 1) &&
		(label_redirect[label_index].redirect == label_index)) {
		int size = label->tip[0].lab_size_first;
		int inst_new;
		int inst_modified;
		int operand_modified;
		for (n = 1; n < label->tip_size; n++) {
			if (label->tip[n].lab_size_first != size) {
				inst_modified = label->tip[n].inst_number;
				operand_modified = label->tip[n].operand;
				node = label->tip[n].node;
				if (inst_log_entry[inst_modified].instruction.opcode == RET) {
					return 0;
				}
				tmp = insert_nop_before(self, inst_modified, &inst_new);
				/* FIXME: Not support LOAD, STORE or MOV inst yet. */
				if (inst_log_entry[inst_modified].instruction.opcode == LOAD) {
					debug_print(DEBUG_ANALYSE_TIP, 1, "ZEXT/TRUNC before unhandled LOAD instruction\n");
					exit(1);
				}
				if (inst_log_entry[inst_modified].instruction.opcode == STORE) {
					debug_print(DEBUG_ANALYSE_TIP, 1, "ZEXT/TRUNC before unhandled STORE instruction\n");
					exit(1);
				}
				if (inst_log_entry[inst_modified].instruction.opcode == MOV) {
					debug_print(DEBUG_ANALYSE_TIP, 1, "ZEXT/TRUNC before unhandled MOV instruction\n");
					/* Need to first separate the label merge that the MOV instruction did,
					   Add the ZEXT/TRUNC.
					   Re-implement the new label merge that rhe MOV instruction should do.
					   NOTE: Maybe move the label merge to later?
					 */
					//exit(1);
				}
				if (label->tip[n].lab_size_first > size) {
					inst_log_entry[inst_new].instruction.opcode = ZEXT;
				} else {
					inst_log_entry[inst_new].instruction.opcode = TRUNC;
				}
				inst_log_entry[inst_new].instruction.flags = 0;

				debug_print(DEBUG_ANALYSE_TIP, 1, "label needed zext/trunc: size=0x%x, inst_new=0x%x. tip:0x%x node = 0x%x, inst = 0x%x, phi = 0x%x, operand = 0x%x, lap_pointer_first = 0x%x, lab_integer_first = 0x%x, lab_size_first = 0x%x\n",
				size,
				inst_new,
				label_index,
				label->tip[n].node,
				label->tip[n].inst_number,
				label->tip[n].phi_number,
				label->tip[n].operand,
				label->tip[n].lab_pointer_first,
				label->tip[n].lab_integer_first,
				label->tip[n].lab_size_first);
				tmp = dis64_copy_operand(self, inst_modified, operand_modified, inst_new, 1, size);
				tmp = dis64_copy_operand(self, inst_modified, operand_modified, inst_new, 3, size);
				inst_log_entry[inst_new].instruction.srcA.value_size = size;
				inst_log_entry[inst_new].instruction.dstA.index = REG_TMP3;
				inst_log_entry[inst_new].value3.value_id =
					external_entry_point->variable_id;
				if (operand_modified == 1) {
					inst_log_entry[inst_modified].instruction.srcA.index = REG_TMP3;
				} else if (operand_modified == 2) {
					inst_log_entry[inst_modified].instruction.srcB.index = REG_TMP3;
				} else if (operand_modified == 3) {
					inst_log_entry[inst_modified].instruction.dstA.index = REG_TMP3;
				} else {
					printf("operand out of range.\n");
					exit(1);
				}
				inst_log1 =  &inst_log_entry[inst_new];
				tmp  = assign_id_label_dst(self, entry_point, inst_new, inst_log1, &label_local);
				variable_id = external_entry_point->variable_id;
				variable_id_add_tip = variable_id;
				if (!tmp) {
					debug_print(DEBUG_ANALYSE_TIP, 1, "variable_id = %x\n", variable_id);
					if (variable_id >= 10000) {
						printf("ERROR: variable_id overrun 10000 limit. Trying to write to %d\n", variable_id);
						exit(1);
					}
					label_redirect[variable_id].redirect = variable_id;
					labels[variable_id].scope = label_local.scope;
					labels[variable_id].type = label_local.type;
					labels[variable_id].value = label_local.value;
					labels[variable_id].size_bits = label_local.size_bits;
					labels[variable_id].lab_pointer += label_local.lab_pointer;
					variable_id++;
					external_entry_point->variable_id = variable_id;
					debug_print(DEBUG_ANALYSE_TIP, 1, "variable_id increased to = %x\n", variable_id);
				} else {
					printf("ERROR: assign_id_label_dst() failed. entry_point = 0x%x, inst = 0x%x\n",
						entry_point, inst_new);
					exit(1);
				}
				if (operand_modified == 1) {
					inst_log_entry[inst_modified].value1.value_id = variable_id_add_tip;
				} else if (operand_modified == 2) {
					inst_log_entry[inst_modified].value2.value_id = variable_id_add_tip;
				} else if (operand_modified == 3) {
					inst_log_entry[inst_modified].value3.value_id = variable_id_add_tip;
				} else {
					printf("operand out of range.\n");
					exit(1);
				}
				/* Now update the tip table with the changes */
				/* Update the tip to point to the new inst.
				   Update the label on the new instruction to include a tip for the
				   new inst, the REG_TMP3 and its label.
				*/
				tmp = tip_add(self, entry_point, node, inst_new, 0, 1, variable_id_add_tip,
					label->tip[n].lab_pointer_first, 0, 0, label->tip[n].lab_size_first);
				tmp = tip_add(self, entry_point, node, inst_modified, 0, 1, variable_id_add_tip,
					label->tip[n].lab_pointer_first, 0, 0, label->tip[n].lab_size_first);
				label->tip[n].inst_number = inst_new;
				label->tip[n].operand = 1;
				label->tip[n].lab_size_first = size;
			}
		}
	}
	return 0;
}
#endif


#if 0
int tip_print_label(struct self_s *self, int entry_point, int label_index)
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[entry_point]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	struct label_s *label;
	int n;

	label = &labels[label_redirect[label_index].redirect];
	if ((label->scope != 0) && (label->tip_size > 0) &&
		(label_redirect[label_index].redirect == label_index)) {
		for (n = 0; n < label->tip_size; n++) {
			debug_print(DEBUG_ANALYSE_TIP, 1, "label tip:0x%x node = 0x%x, inst = 0x%x, phi = 0x%x, operand = 0x%x, pointer_first = 0x%x, pointed_to_size = 0x%x, integer_first = 0x%x, size_first = 0x%x\n",
			label_index,
			label->tip[n].node,
			label->tip[n].inst_number,
			label->tip[n].phi_number,
			label->tip[n].operand,
			label->tip[n].lab_pointer_first,
			label->tip[n].lab_pointed_to_size,
			label->tip[n].lab_integer_first,
			label->tip[n].lab_size_first);
		}
	}
	return 0;
}
#endif

int redirect_mov_reg_reg_labels(struct self_s *self, struct external_entry_point_s *external_entry_point, int node)
{
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	int m;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int variable_id = external_entry_point->variable_id;
	uint64_t stack_address;
	struct memory_s *memory;
	int value_id;
	int value_id3;

	int inst;
	struct label_s label;
	int found = 0;
	debug_print(DEBUG_MAIN, 1, "redirect_mov_reg_reg_labels() node 0x%x\n", node);

	inst = nodes[node].inst_start;
	do {
		inst_log1 =  &inst_log_entry[inst];
		instruction =  &inst_log1->instruction;
		switch (instruction->opcode) {
		case MOV:
			/* MOV reg,reg */
			if ((IND_DIRECT == instruction->srcA.indirect) &&
				(STORE_REG == instruction->srcA.store) &&
				(IND_DIRECT == instruction->dstA.indirect) &&
				(STORE_REG == instruction->dstA.store)) {

				value_id = inst_log1->value1.value_id;
				value_id3 = inst_log1->value3.value_id;
				/* Use the redirect as the source in case the source value_id has previously been redirected */
				label_redirect[value_id3].domain = label_redirect[value_id].domain;
				label_redirect[value_id3].index = label_redirect[value_id].index;
			/* MOV imm,reg */
			} else if ((IND_DIRECT == instruction->srcA.indirect) &&
				(STORE_DIRECT == instruction->srcA.store) &&
				(IND_DIRECT == instruction->dstA.indirect) &&
				(STORE_REG == instruction->dstA.store)) {

				value_id = inst_log1->value1.value_id;
				value_id3 = inst_log1->value3.value_id;
				/* Use the redirect as the source in case the source value_id has previously been redirected */
				label_redirect[value_id3].domain = label_redirect[value_id].domain;
				label_redirect[value_id3].index = label_redirect[value_id].index;
			} 
			break;
		default:
			break;
		}
		if (inst == nodes[node].inst_end) {
			found = 1;
		}
		if (inst_log1->next_size > 0) {
			inst = inst_log1->next[0];
		} else {
			/* Exit here */
			found = 1;
		}
	} while (!found);

	return 0;
}

uint64_t function_find_return_label(struct self_s *self, struct external_entry_point_s *external_entry_point, int node)
{
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	int m;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int variable_id = external_entry_point->variable_id;
	uint64_t stack_address;
	struct memory_s *memory;
	int value_id;
	int value_id3;
	uint64_t index = 0;
	int inst;
	struct label_s label;
	int found = 0;
	debug_print(DEBUG_MAIN, 1, " node 0x%x\n", node);

	inst = nodes[node].inst_start;
	do {
		inst_log1 =  &inst_log_entry[inst];
		instruction =  &inst_log1->instruction;
		switch (instruction->opcode) {
		case RET:
			value_id = inst_log1->value1.value_id;
			check_domain(&(label_redirect[value_id]));
			index = label_redirect[value_id].index;
			found = 1;
			break;
		default:
			break;
		}
		if (inst == nodes[node].inst_end) {
			found = 1;
		}
		if (inst_log1->next_size > 0) {
			inst = inst_log1->next[0];
		} else {
			/* Exit here */
			found = 1;
		}
	} while (!found);

	return index;
}

int change_add_to_gep1(struct self_s *self, struct external_entry_point_s *external_entry_point, int node)
{
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct tip2_s *tip2 = external_entry_point->tip2;
	int m;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int variable_id = external_entry_point->variable_id;
	uint64_t stack_address;
	struct memory_s *memory;
	int value_id1;
	int value_id2;
	int value_id3;

	int inst;
	struct label_s label;
	int found = 0;

	inst = nodes[node].inst_start;
	do {
		inst_log1 =  &inst_log_entry[inst];
		instruction =  &inst_log1->instruction;
		switch (instruction->opcode) {
		case ADD:
			debug_print(DEBUG_MAIN, 1, "change_add_to_gep1() node 0x%x, inst 0x%x\n", node, inst);
			check_domain(&(label_redirect[inst_log1->value1.value_id]));
			value_id1 = label_redirect[inst_log1->value1.value_id].index;
			check_domain(&(label_redirect[inst_log1->value2.value_id]));
			value_id2 = label_redirect[inst_log1->value2.value_id].index;
			check_domain(&(label_redirect[inst_log1->value3.value_id]));
			value_id3 = label_redirect[inst_log1->value3.value_id].index;
			if ((tip2[value_id1].pointer > 0) ||
				(tip2[value_id2].pointer > 0) ||
				(tip2[value_id3].pointer > 0)) {
				instruction->opcode = GEP1;
				debug_print(DEBUG_MAIN, 1, "change_add_to_gep1() node 0x%x, inst 0x%x opcode = 0x%x\n",
					node, inst, inst_log_entry[inst].instruction.opcode);
			}
			break;
		case SUB:
			debug_print(DEBUG_MAIN, 1, "change_sub_to_gep1() node 0x%x, inst 0x%x\n", node, inst);
			check_domain(&(label_redirect[inst_log1->value1.value_id]));
			value_id1 = label_redirect[inst_log1->value1.value_id].index;
			check_domain(&(label_redirect[inst_log1->value2.value_id]));
			value_id2 = label_redirect[inst_log1->value2.value_id].index;
			check_domain(&(label_redirect[inst_log1->value3.value_id]));
			value_id3 = label_redirect[inst_log1->value3.value_id].index;
			/* FIXME: P1 - P2 = I, not P3. */
			if ((tip2[value_id1].pointer > 0) ||
				(tip2[value_id2].pointer > 0) ||
				(tip2[value_id3].pointer > 0)) {
				instruction->opcode = GEP1;
				labels[value_id2].value = -labels[value_id2].value;
				instruction->srcB.index = -instruction->srcB.index;
			}
			break;
		default:
			break;
		}
		if (inst == nodes[node].inst_end) {
			found = 1;
		}
		if (inst_log1->next_size > 0) {
			inst = inst_log1->next[0];
		} else {
			/* Exit here */
			found = 1;
		}
	} while (!found);

	return 0;
}

#if 0
int discover_pointer_types(struct self_s *self, struct external_entry_point_s *external_entry_point, int node)
{
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	int m;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int variable_id = external_entry_point->variable_id;
	uint64_t stack_address;
	struct memory_s *memory;
	int value_id1;
	int value_id2;

	int inst;
	struct label_s label;
	int found = 0;
	debug_print(DEBUG_MAIN, 1, "discover_pointer_types() node 0x%x\n", node);

	inst = nodes[node].inst_start;
	do {
		inst_log1 =  &inst_log_entry[inst];
		instruction =  &inst_log1->instruction;
		switch (instruction->opcode) {
		case LOAD:
			switch (inst_log1->instruction.srcA.indirect) {
			case 1:  // Memory
				value_id1 = label_redirect[inst_log1->value1.value_id].redirect;
				labels[value_id1].pointer_type_size_bits = instruction->srcA.value_size;
				debug_print(DEBUG_MAIN, 1, "discover_pointer_types() label 0x%x pointer type size = 0x%x\n",
					value_id1, instruction->srcA.value_size);
				break;
			case 2:  // Stack
				value_id1 = label_redirect[inst_log1->value1.value_id].redirect;
				labels[value_id1].pointer_type_size_bits = instruction->srcA.value_size;
				debug_print(DEBUG_MAIN, 1, "discover_pointer_types() label 0x%x pointer type size = 0x%x\n",
					value_id1, instruction->srcA.value_size);
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
		if (inst == nodes[node].inst_end) {
			found = 1;
		}
		if (inst_log1->next_size > 0) {
			inst = inst_log1->next[0];
		} else {
			/* Exit here */
			found = 1;
		}
	} while (!found);

	return 0;
}
#endif


int substitute_inst(struct self_s *self, int inst, int new_inst)
{
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	inst_log_entry[new_inst].instruction.opcode =
		inst_log_entry[inst].instruction.opcode;
	inst_log_entry[new_inst].instruction.flags =
		inst_log_entry[inst].instruction.flags;
	inst_log_entry[new_inst].instruction.srcA.store =
		inst_log_entry[inst].instruction.srcA.store;
	inst_log_entry[new_inst].instruction.srcA.indirect =
		inst_log_entry[inst].instruction.srcA.indirect;
	inst_log_entry[new_inst].instruction.srcA.indirect_size =
		inst_log_entry[inst].instruction.srcA.indirect_size;
	inst_log_entry[new_inst].instruction.srcA.index =
		inst_log_entry[inst].instruction.srcA.index;
	inst_log_entry[new_inst].instruction.srcA.relocated =
		inst_log_entry[inst].instruction.srcA.relocated;
	inst_log_entry[new_inst].instruction.srcA.value_size =
		inst_log_entry[inst].instruction.srcA.value_size;
	inst_log_entry[new_inst].instruction.srcB.store =
		inst_log_entry[inst].instruction.srcB.store;
	inst_log_entry[new_inst].instruction.srcB.indirect =
		inst_log_entry[inst].instruction.srcB.indirect;
	inst_log_entry[new_inst].instruction.srcB.indirect_size =
		inst_log_entry[inst].instruction.srcB.indirect_size;
	inst_log_entry[new_inst].instruction.srcB.index =
		inst_log_entry[inst].instruction.srcB.index;
	inst_log_entry[new_inst].instruction.srcB.relocated =
		inst_log_entry[inst].instruction.srcB.relocated;
	inst_log_entry[new_inst].instruction.srcB.value_size =
		inst_log_entry[inst].instruction.srcB.value_size;
	inst_log_entry[new_inst].instruction.dstA.store =
		inst_log_entry[inst].instruction.dstA.store;
	inst_log_entry[new_inst].instruction.dstA.indirect =
		inst_log_entry[inst].instruction.dstA.indirect;
	inst_log_entry[new_inst].instruction.dstA.indirect_size =
		inst_log_entry[inst].instruction.dstA.indirect_size;
	inst_log_entry[new_inst].instruction.dstA.index =
		inst_log_entry[inst].instruction.dstA.index;
	inst_log_entry[new_inst].instruction.dstA.relocated =
		inst_log_entry[inst].instruction.dstA.relocated;
	inst_log_entry[new_inst].instruction.dstA.value_size =
		inst_log_entry[inst].instruction.dstA.value_size;
	return 0;
}


int build_flag_dependency_table(struct self_s *self)
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log1_flags;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct instruction_s *instruction;
	int n;
	int prev = 0;
	int found;
	int tmp;
	int new_inst;
	int inst_max = self->flag_dependency_size;

	for (n = 1; n < inst_max; n++) {
		self->flag_result_users[n] = 0;
	}

	for (n = 1; n < inst_max; n++) {
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		switch (instruction->opcode) {
		case RCR:
		case RCL:
		case ADC:
		case SBB:
		case IF:
			debug_print(DEBUG_MAIN, 1, "flag user inst 0x%x OP:0x%x\n", n, instruction->opcode);
			found = 0;
			tmp = 30; /* Limit the scan backwards */
			inst_log1_flags =  inst_log1;
			do {
				if (inst_log1_flags->prev > 0) {
					prev = inst_log1_flags->prev[0];
				} else {
					break;
				}
				tmp--;
				inst_log1_flags =  &inst_log_entry[prev];
				debug_print(DEBUG_MAIN, 1, "Previous opcode 0x%x\n", inst_log1_flags->instruction.opcode);
				debug_print(DEBUG_MAIN, 1, "Previous flags 0x%x\n", inst_log1_flags->instruction.flags);
				if (1 == inst_log1_flags->instruction.flags) {
					found = 1;
				}
				debug_print(DEBUG_MAIN, 1, "Previous flags instruction size 0x%x\n", inst_log1_flags->prev_size);
				tmp--;
			} while ((0 == found) && (0 < tmp) && (0 != prev));
			if (found == 0) {
				debug_print(DEBUG_MAIN, 1, "Previous flags instruction not found. found=%d, tmp=%d, prev=0x%x\n", found, tmp, prev);
				return 1;
			} else {
				debug_print(DEBUG_MAIN, 1, "Previous flags instruction found. found=%d, tmp=%d, prev=0x%x n=0x%x\n", found, tmp, prev, n);
				if (self->flag_result_users[prev] > 0) {
					if ((inst_log_entry[prev].instruction.opcode != CMP) &&
						(inst_log_entry[prev].instruction.opcode != TEST)) {
						debug_print(DEBUG_MAIN, 1, "TOO MANY FLAGGED NON CMP/TEST. Opcode = 0x%x, Node = 0x%x\n",
							inst_log_entry[prev].instruction.opcode,
							inst_log_entry[prev].node_member);
						exit(1);
					}
					if (inst_log_entry[prev].instruction.opcode == TEST) {
						debug_print(DEBUG_MAIN, 1, "FIXME: Too many TEST. Inst = 0x%x Opcode = 0x%x\n",
							prev,
							inst_log_entry[prev].instruction.opcode);
					}
					
					/* Use "before" because after will cause a race condition */
					tmp = insert_nop_before(self, prev, &new_inst);
					/* copy CMP/TEST into it */
					tmp = substitute_inst(self, prev, new_inst);
					self->flag_dependency[n] = new_inst;
					self->flag_dependency_opcode[n] = inst_log1_flags->instruction.opcode;
					self->flag_result_users[new_inst]++;
					if (new_inst > 0xe20) {
						debug_print(DEBUG_MAIN, 1, "ADDING NEW INST 0x%x, flagged = 0x%x, flag_dep_size = 0x%x\n",
							new_inst, self->flag_result_users[new_inst], self->flag_dependency_size);
					}
				} else {		
					self->flag_dependency[n] = prev;
					self->flag_dependency_opcode[n] = inst_log1_flags->instruction.opcode;
					self->flag_result_users[prev]++;
					if (prev > 0xe20) {
						debug_print(DEBUG_MAIN, 1, "ADDING FLAGGED 0x%x, flagged = 0x%x, flag_dep_size = 0x%x\n",
							prev, self->flag_result_users[prev], self->flag_dependency_size);
					}
				}
			}
			break;
		default:
			break;
		}
	}
	found = 0;
	for (n = 1; n < inst_max; n++) {
		if (self->flag_result_users[n] > 1) {
			debug_print(DEBUG_MAIN, 1, "Duplicate Previous flags instruction found. inst 0x%x:0x%x\n", n, self->flag_result_users[n]);
			found = 1;
		}
		if (self->flag_result_users[n] > 0) {
			debug_print(DEBUG_MAIN, 1, "FLAG RESULT USED. inst 0x%x:0x%x opcode=0x%x\n", n, self->flag_result_users[n], inst_log_entry[n].instruction.opcode);
		}

	}
	if (found) {
		printf("build_flag_dependency_table: Exiting\n");
		exit(1);
	}
	
	return 0;
}

int matcher_sbb(struct self_s *self, int inst, int *sbb_match, int *n1, int *n2, int *n3, int *flags_result_used)
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	int match = 0;
	int prev = self->flag_dependency[inst];
	int next1 = 0;
	int next2 = 0;
	int next3 = 0;
	int nexts_present = 0;
	int cmp_sbb_and_add = 0;
	int cmp_sbb_add = 0;
	int reg = 0;
	int reg_size = 0;
	int is_reg = 0;
	int ssb_same_reg = 0;
	int next1_same_reg = 0;
	int next2_same_reg = 0;
	int m;
	int max_log = inst_log;
	inst_log1 =  &inst_log_entry[inst];

	if (self->flag_result_users[inst] > 0) {
		for (m = 1; m < max_log; m++) {
			if (self->flag_dependency[m] == inst) {
				debug_print(DEBUG_MAIN, 1, "flag: SBB leaves users. inst 0x%x uses flag from inst 0x%x\n", m, inst);
			}
		}
		*flags_result_used = 1;
		debug_print(DEBUG_MAIN, 1, "flag: NOT HANDLED: SBB leaves users. inst ???? uses flag from inst 0x%x\n", inst);
	}
	if (inst_log1->next_size) {
		next1 = inst_log1->next[0];
	}
	if (inst_log_entry[next1].next_size) {
		next2 = inst_log_entry[next1].next[0];
	}
	if (inst_log_entry[next2].next_size) {
		next3 = inst_log_entry[next2].next[0];
	}
	if ((prev != 0) && (next1 != 0) && (next2 != 0)) {
		nexts_present = 1;
	}
	if ((nexts_present) &&
		(inst_log_entry[prev].instruction.opcode == CMP) && 
		(inst_log_entry[next1].instruction.opcode == rAND) && 
		(inst_log_entry[next2].instruction.opcode == ADD)) {
		cmp_sbb_and_add = 1;
	}
	if ((prev != 0) && (next1 != 0) &&
		(inst_log_entry[prev].instruction.opcode == CMP) && 
		(inst_log_entry[next1].instruction.opcode == ADD)) { 
		cmp_sbb_add = 1;
	}
	if ((inst_log1->instruction.dstA.store == STORE_REG) &&
		(inst_log1->instruction.dstA.indirect == IND_DIRECT)) {
		reg = inst_log1->instruction.dstA.index;
		reg_size = inst_log1->instruction.dstA.value_size;
		is_reg = 1;
	}
	if (inst_log1->instruction.srcA.index == 
		inst_log1->instruction.srcB.index) {
		ssb_same_reg = 1;
	}
	if ((inst_log_entry[next1].instruction.srcB.index == reg) &&
		(inst_log_entry[next1].instruction.dstA.index == reg)) {
		next1_same_reg = 1;
	}
	if ((inst_log_entry[next2].instruction.srcB.index == reg) &&
		(inst_log_entry[next2].instruction.dstA.index == reg)) {
		next2_same_reg = 1;
	}

	if ((*flags_result_used == 0) &&
		nexts_present &&
		cmp_sbb_and_add &&
		is_reg &&
		ssb_same_reg &&
		next1_same_reg &&
		next2_same_reg) {
		/* cmp_sbb_and_add to icmp_bc */
		match = 5;
	} else if ((*flags_result_used == 0) &&
		nexts_present &&
		cmp_sbb_add &&
		is_reg &&
		ssb_same_reg &&
		next1_same_reg &&
		next2_same_reg) {
		/* cmp_sbb_add to icmp_bc */
		match = 4;
	} else if ((*flags_result_used == 0) &&
		is_reg &&
		ssb_same_reg) {
		/* cmp_sbb_to_icmp_sex */
		match = 3;
	} else if (*flags_result_used == 0) {
		/* cmp_ssb_to_icmp_sex_add_sub */
		match = 2;
	} else {
		/* Not yet handled */
		match = 1;
	}
	*n1 = next1;
	*n2 = next2;
	*n3 = next3;
	*sbb_match = match;

	return 0;
}

int fix_flag_dependency_instructions(struct self_s *self)
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log1_flags;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct instruction_s *instruction;
	int m,n;
	int tmp;
	int prev;
	int next1;
	int next2;
	int next3;
	int sbb_match;
	int flags_result_used;
	int reg;
	int reg_size;
	int new_inst = 0;
	int64_t working_var1;
	int64_t working_var2;
	int64_t working_var3;
	int max_log;

	/* Use max_log and not inst_log in case inst_log changes when adding nop instructions */
	max_log = self->flag_dependency_size;
	debug_print(DEBUG_MAIN, 1, "flag: MAX_LOG = 0x%x\n", max_log);

	for (n = 1; n < max_log; n++) {
		if (!self->flag_dependency[n]) {
			/* Go round loop again */
			continue;
		}
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		prev = self->flag_dependency[n];
		next1 = 0;
		next2 = 0;
		next3 = 0;
		sbb_match = 0;
		debug_print(DEBUG_MAIN, 1, "flag user inst 0x%x OP:0x%x\n", n, instruction->opcode);
		switch (instruction->opcode) {
		case ADC:
			debug_print(DEBUG_MAIN, 1, "flag: ADC NOT HANDLED yet\n");
			exit(1);
			break;
		case SBB:
			tmp = matcher_sbb(self, n, &sbb_match, &next1, &next2, &next3, &flags_result_used);
			debug_print(DEBUG_MAIN, 1, "SBB: match 0x%x\n", sbb_match);
			if (self->flag_result_users[n] > 0) {
				for (m = 1; m < max_log; m++) {
					if (self->flag_dependency[m] == n) {
						debug_print(DEBUG_MAIN, 1, "flag: SBB leaves users. inst 0x%x uses flag from inst 0x%x\n", m, n);
					}
				}
				debug_print(DEBUG_MAIN, 1, "flag: NOT HANDLED: SBB leaves users. inst ???? uses flag from inst 0x%x\n", n);
				exit(1);
			}
			/* Match tests passed. Now do the substitution */
			switch (sbb_match) {
			case 5:
				working_var1 = inst_log_entry[next1].instruction.srcA.index;
				working_var2 = inst_log_entry[next2].instruction.srcA.index;
				working_var3 = working_var1 + working_var2;
				tmp = insert_nop_after(self, n, &new_inst);
				debug_print(DEBUG_MAIN, 1, "flag: working_var1 = 0x%"PRIx64", working_var2 = 0x%"PRIx64", working_var3 = 0x%"PRIx64"\n",
					working_var1,
					working_var2,
					working_var3);
				inst_log_entry[prev].instruction.opcode = ICMP;
				inst_log_entry[prev].instruction.flags = 0;
				inst_log_entry[prev].instruction.predicate = LESS;
				inst_log_entry[prev].instruction.dstA.index = REG_LESS;
				inst_log_entry[prev].instruction.dstA.store = STORE_REG;
				inst_log_entry[prev].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[prev].instruction.dstA.relocated = 0;
				inst_log_entry[prev].instruction.dstA.value_size = 1;
				inst_log_entry[prev].value3.value_scope =  2;
				instruction->opcode = BRANCH;
				instruction->srcA.index = REG_LESS;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				inst_log1->value3.value_scope =  2;
				
				debug_print(DEBUG_MAIN, 1, "flag: realloc: inst_log1->next_size = 0x%x, %p\n", inst_log1->next_size, inst_log1->next);
				inst_log1->next = realloc(inst_log1->next, 2 * sizeof(int));
				debug_print(DEBUG_MAIN, 1, "flag: realloc: inst_log1->next_size = 0x%x, %p\n", inst_log1->next_size, inst_log1->next);
				
				inst_log1->next[0] = next2;
				inst_log1->next[1] = new_inst;
				inst_log1->next_size = 2;
	
				inst_log_entry[new_inst].instruction.opcode = MOV;
				inst_log_entry[new_inst].instruction.flags = 0;
				inst_log_entry[new_inst].instruction.predicate = 0;
				inst_log_entry[new_inst].instruction.srcA.index = working_var3;
				inst_log_entry[new_inst].instruction.srcA.store = STORE_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.relocated = 0;
				inst_log_entry[new_inst].instruction.srcA.value_size = reg_size;
				inst_log_entry[new_inst].instruction.srcB.index = reg;
				inst_log_entry[new_inst].instruction.srcB.store = STORE_REG;
				inst_log_entry[new_inst].instruction.srcB.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcB.relocated = 0;
				inst_log_entry[new_inst].instruction.srcB.value_size = reg_size;
				inst_log_entry[new_inst].instruction.dstA.index = reg;
				inst_log_entry[new_inst].instruction.dstA.store = STORE_REG;
				inst_log_entry[new_inst].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.dstA.relocated = 0;
				inst_log_entry[new_inst].instruction.dstA.value_size = reg_size;
				inst_log_entry[new_inst].value3.value_scope =  2;

				inst_log_entry[next1].instruction.opcode = JMP;
				inst_log_entry[next1].instruction.flags = 0;
				inst_log_entry[next1].instruction.predicate = 0;
				inst_log_entry[next1].instruction.srcA.index = working_var2;
				inst_log_entry[next1].instruction.srcA.store = STORE_DIRECT;
				inst_log_entry[next1].instruction.srcA.indirect = IND_DIRECT;
				inst_log_entry[next1].instruction.srcA.relocated = 0;
				inst_log_entry[next1].instruction.srcA.value_size = reg_size;
				inst_log_entry[next1].instruction.srcB.index = reg;
				inst_log_entry[next1].instruction.srcB.store = STORE_REG;
				inst_log_entry[next1].instruction.srcB.indirect = IND_DIRECT;
				inst_log_entry[next1].instruction.srcB.relocated = 0;
				inst_log_entry[next1].instruction.srcB.value_size = reg_size;
				inst_log_entry[next1].instruction.dstA.index = reg;
				inst_log_entry[next1].instruction.dstA.store = STORE_REG;
				inst_log_entry[next1].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[next1].instruction.dstA.relocated = 0;
				inst_log_entry[next1].instruction.dstA.value_size = reg_size;
				inst_log_entry[next1].value3.value_scope =  2;
				inst_log_entry[next1].next[0] = next3;
				tmp = inst_log_entry[next3].prev_size;
				inst_log_entry[next3].prev = realloc(inst_log_entry[next3].prev, (tmp +  1) * sizeof(int));
				inst_log_entry[next3].prev[tmp] = next1;
				inst_log_entry[next3].prev_size++;

				inst_log_entry[next2].instruction.opcode = MOV;
				inst_log_entry[next2].instruction.flags = 0;
				inst_log_entry[next2].instruction.predicate = 0;
				inst_log_entry[next2].instruction.srcA.index = working_var2;
				inst_log_entry[next2].instruction.srcA.store = STORE_DIRECT;
				inst_log_entry[next2].instruction.srcA.indirect = IND_DIRECT;
				inst_log_entry[next2].instruction.srcA.relocated = 0;
				inst_log_entry[next2].instruction.srcA.value_size = reg_size;
				inst_log_entry[next2].instruction.srcB.index = reg;
				inst_log_entry[next2].instruction.srcB.store = STORE_REG;
				inst_log_entry[next2].instruction.srcB.indirect = IND_DIRECT;
				inst_log_entry[next2].instruction.srcB.relocated = 0;
				inst_log_entry[next2].instruction.srcB.value_size = reg_size;
				inst_log_entry[next2].instruction.dstA.index = reg;
				inst_log_entry[next2].instruction.dstA.store = STORE_REG;
				inst_log_entry[next2].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[next2].instruction.dstA.relocated = 0;
				inst_log_entry[next2].instruction.dstA.value_size = reg_size;
				inst_log_entry[next2].value3.value_scope =  2;
				debug_print(DEBUG_MAIN, 1, "flag: SBB 5 handled\n");
				break;
			case 3:
				inst_log_entry[prev].instruction.opcode = ICMP;
				inst_log_entry[prev].instruction.flags = 0;
				inst_log_entry[prev].instruction.predicate = BELOW;
				inst_log_entry[prev].instruction.dstA.index = REG_BELOW;
				inst_log_entry[prev].instruction.dstA.store = STORE_REG;
				inst_log_entry[prev].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[prev].instruction.dstA.relocated = 0;
				inst_log_entry[prev].instruction.dstA.value_size = 1;
				inst_log_entry[prev].value3.value_scope =  2;
				instruction->opcode = SEX;
				instruction->flags = 0;
				instruction->srcA.index = REG_BELOW;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				debug_print(DEBUG_MAIN, 1, "flag: SBB 3 handled\n");
				break;
			default:
				debug_print(DEBUG_MAIN, 1, "flag: SBB 0x%x NOT HANDLED\n", sbb_match);
				break;
			}
			
			//exit(1);
			break;
		case IF:
			debug_print(DEBUG_MAIN, 1, "flag IF inst 0x%x OP:0x%x\n", n, instruction->opcode);
			inst_log1_flags =  &inst_log_entry[self->flag_dependency[n]];
			if (inst_log1_flags->instruction.opcode != self->flag_dependency_opcode[n]) {
				return 1;
			}
			switch (inst_log1_flags->instruction.opcode) {
			case CMP:
				inst_log1_flags->instruction.opcode = ICMP;
				inst_log1_flags->instruction.flags = 0;
				inst_log1_flags->instruction.predicate = inst_log1->instruction.srcA.index;
				inst_log1_flags->instruction.dstA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				inst_log1_flags->instruction.dstA.store = STORE_REG;
				inst_log1_flags->instruction.dstA.indirect = IND_DIRECT;
				inst_log1_flags->instruction.dstA.relocated = 0;
				inst_log1_flags->instruction.dstA.value_size = 1;
				inst_log1_flags->value3.value_scope =  2;
				/* FIXME: fill in rest of instruction dstA and then its value3 */
				instruction->opcode = BRANCH;
				instruction->srcA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				inst_log1->value3.value_scope =  2;
				debug_print(DEBUG_MAIN, 1, "Pair of instructions adjusted. inst 0x%x:0x%x\n", n, self->flag_dependency[n]);
				break;
			case TEST:
				//if (inst_log1_flags->instruction.srcA.index != inst_log1_flags->instruction.srcB.index) {
				//	debug_print(DEBUG_MAIN, 1, "flag NOT HANDLED inst 0x%x TEST OP:0x%x\n", n, inst_log1_flags->instruction.opcode);
				//	exit (1);
				//}
				/* Change TEST,IF to AND,ICMP,BRANCH */
				tmp = insert_nop_after(self, self->flag_dependency[n], &new_inst);
				reg_size = inst_log1_flags->instruction.srcA.value_size;
				inst_log1_flags->instruction.opcode = rAND;
				inst_log1_flags->instruction.flags = 0;
				inst_log1_flags->instruction.dstA.index = REG_TMP1;
				inst_log1_flags->instruction.dstA.store = STORE_REG;
				inst_log1_flags->instruction.dstA.indirect = IND_DIRECT;
				inst_log1_flags->instruction.dstA.relocated = 0;
				inst_log1_flags->instruction.dstA.value_size = reg_size;

				inst_log_entry[new_inst].instruction.opcode = ICMP;
				inst_log_entry[new_inst].instruction.flags = 0;
				inst_log_entry[new_inst].instruction.predicate = inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.srcA.index = 0;
				inst_log_entry[new_inst].instruction.srcA.store = STORE_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.relocated = 0;
				inst_log_entry[new_inst].instruction.srcA.value_size = reg_size;
				inst_log_entry[new_inst].instruction.srcB.index = REG_TMP1;
				inst_log_entry[new_inst].instruction.srcB.store = STORE_REG;
				inst_log_entry[new_inst].instruction.srcB.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcB.relocated = 0;
				inst_log_entry[new_inst].instruction.srcB.value_size = reg_size;
				inst_log_entry[new_inst].instruction.dstA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.dstA.store = STORE_REG;
				inst_log_entry[new_inst].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.dstA.relocated = 0;
				inst_log_entry[new_inst].instruction.dstA.value_size = 1;
				inst_log_entry[new_inst].value3.value_scope =  2;

				/* FIXME: fill in rest of instruction dstA and then its value3 */
				instruction->opcode = BRANCH;
				instruction->srcA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				inst_log1->value3.value_scope =  2;
				debug_print(DEBUG_MAIN, 1, "Pair of instructions adjusted. inst 0x%x:0x%x\n", n, self->flag_dependency[n]);
				break;
			case rAND:
				tmp = insert_nop_after(self, self->flag_dependency[n], &new_inst);
				reg = inst_log1_flags->instruction.dstA.index;
				reg_size = inst_log1_flags->instruction.dstA.value_size;

				inst_log_entry[new_inst].instruction.opcode = ICMP;
				inst_log_entry[new_inst].instruction.flags = 0;
				inst_log_entry[new_inst].instruction.predicate = inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.srcA.index = 0;
				inst_log_entry[new_inst].instruction.srcA.store = STORE_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.relocated = 0;
				inst_log_entry[new_inst].instruction.srcA.value_size = reg_size;
				inst_log_entry[new_inst].instruction.srcB.index = reg;
				inst_log_entry[new_inst].instruction.srcB.store = STORE_REG;
				inst_log_entry[new_inst].instruction.srcB.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcB.relocated = 0;
				inst_log_entry[new_inst].instruction.srcB.value_size = reg_size;
				inst_log_entry[new_inst].instruction.dstA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.dstA.store = STORE_REG;
				inst_log_entry[new_inst].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.dstA.relocated = 0;
				inst_log_entry[new_inst].instruction.dstA.value_size = 1;
				inst_log_entry[new_inst].value3.value_scope =  2;

				/* FIXME: fill in rest of instruction dstA and then its value3 */
				instruction->opcode = BRANCH;
				instruction->srcA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				inst_log1->value3.value_scope =  2;
				debug_print(DEBUG_MAIN, 1, "Pair of instructions adjusted. inst 0x%x:0x%x\n", n, self->flag_dependency[n]);
				break;
			case SUB:
				tmp = insert_nop_before(self, self->flag_dependency[n], &new_inst);
				reg = inst_log1_flags->instruction.dstA.index;
				reg_size = inst_log1_flags->instruction.dstA.value_size;
				tmp = substitute_inst(self, self->flag_dependency[n], new_inst);

				inst_log_entry[new_inst].instruction.opcode = ICMP;
				inst_log_entry[new_inst].instruction.flags = 0;
				inst_log_entry[new_inst].instruction.predicate = inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.dstA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.dstA.store = STORE_REG;
				inst_log_entry[new_inst].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.dstA.relocated = 0;
				inst_log_entry[new_inst].instruction.dstA.value_size = 1;
				inst_log_entry[new_inst].value3.value_scope =  2;

				/* FIXME: fill in rest of instruction dstA and then its value3 */
				instruction->opcode = BRANCH;
				instruction->srcA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				inst_log1->value3.value_scope =  2;
				debug_print(DEBUG_MAIN, 1, "Pair of instructions adjusted. inst 0x%x:0x%x\n", n, self->flag_dependency[n]);
				break;
			case ADD:
				tmp = inst_log1->instruction.srcA.index;
				if ((tmp == EQUAL) || (tmp == NOT_EQUAL)) {
					int inst = self->flag_dependency[n];
					tmp = insert_nop_after(self, inst, &new_inst);
					reg = inst_log1_flags->instruction.dstA.index;
					reg_size = inst_log1_flags->instruction.dstA.value_size;

					inst_log_entry[new_inst].instruction.opcode = ICMP;
					inst_log_entry[new_inst].instruction.flags = 0;
					inst_log_entry[new_inst].instruction.predicate = inst_log1->instruction.srcA.index;
					inst_log_entry[new_inst].instruction.srcA.index = 0;
					inst_log_entry[new_inst].instruction.srcA.store = STORE_DIRECT;
					inst_log_entry[new_inst].instruction.srcA.indirect = IND_DIRECT;
					inst_log_entry[new_inst].instruction.srcA.relocated = 0;
					inst_log_entry[new_inst].instruction.srcA.value_size = reg_size;
					inst_log_entry[new_inst].instruction.srcB.store =
						inst_log_entry[inst].instruction.dstA.store;
					inst_log_entry[new_inst].instruction.srcB.indirect =
						inst_log_entry[inst].instruction.dstA.indirect;
					inst_log_entry[new_inst].instruction.srcB.indirect_size =
						inst_log_entry[inst].instruction.dstA.indirect_size;
					inst_log_entry[new_inst].instruction.srcB.index =
						inst_log_entry[inst].instruction.dstA.index;
					inst_log_entry[new_inst].instruction.srcB.relocated =
						inst_log_entry[inst].instruction.dstA.relocated;
					inst_log_entry[new_inst].instruction.srcB.value_size =
						inst_log_entry[inst].instruction.dstA.value_size;

					inst_log_entry[new_inst].instruction.dstA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
					inst_log_entry[new_inst].instruction.dstA.store = STORE_REG;
					inst_log_entry[new_inst].instruction.dstA.indirect = IND_DIRECT;
					inst_log_entry[new_inst].instruction.dstA.relocated = 0;
					inst_log_entry[new_inst].instruction.dstA.value_size = 1;
					inst_log_entry[new_inst].value3.value_scope =  2;

					/* FIXME: fill in rest of instruction dstA and then its value3 */
					instruction->opcode = BRANCH;
					instruction->srcA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
					instruction->srcA.store = STORE_REG;
					instruction->srcA.indirect = IND_DIRECT;
					instruction->srcA.relocated = 0;
					instruction->srcA.value_size = 1;
					inst_log1->value3.value_scope =  2;
					debug_print(DEBUG_MAIN, 1, "Pair of instructions adjusted. inst 0x%x:0x%x\n", n, self->flag_dependency[n]);
				} else {
					debug_print(DEBUG_MAIN, 1, "flag NOT HANDLED inst 0x%x OP:ADD:0x%x:PRED=0x%"PRIx64"\n",
						n,
						inst_log1_flags->instruction.opcode,
						inst_log1->instruction.srcA.index);
				}
				break;


			default:
				debug_print(DEBUG_MAIN, 1, "flag NOT HANDLED inst 0x%x OP:0x%x\n", n, inst_log1_flags->instruction.opcode);
				exit (1);
				break;
			}
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "flag: UNKNOWNN:0x%x NOT HANDLED yet. inst 0x%x:0x%x\n",
				instruction->opcode, n, self->flag_dependency[n]);
			exit(1);
			break;
		}
	}
	return 0;
}

int print_flag_dependency_table(struct self_s *self)
{
	int n;
	for (n = 1; n < self->flag_dependency_size; n++) {
		if (self->flag_dependency[n]) {
			debug_print(DEBUG_MAIN, 1, "FLAGS: Inst 0x%x linked to previous Inst 0x%x:0x%x\n", n, self->flag_dependency[n], self->flag_dependency_opcode[n]);
		}
	}
	return 0;
}	

int insert_nop_before(struct self_s *self, int inst, int *new_inst)
{
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct inst_log_entry_s *inst_log1 = &inst_log_entry[inst];
	struct inst_log_entry_s *inst_log1_previous;
	struct inst_log_entry_s *inst_log1_new;
	int l,m,n;
	int inst_new;

	inst_new = inst_log;
	inst_log1_new = &inst_log_entry[inst_new];
	inst_log++;
	self->flag_dependency = realloc(self->flag_dependency, (inst_log) * sizeof(int));
	self->flag_dependency[inst_log - 1] = 0;
	self->flag_dependency_opcode = realloc(self->flag_dependency_opcode, (inst_log) * sizeof(int));
	self->flag_dependency_opcode[inst_log - 1] = 0;
	self->flag_result_users = realloc(self->flag_result_users, (inst_log) * sizeof(int));
	self->flag_result_users[inst_log - 1] = 0;
	debug_print(DEBUG_MAIN, 1, "INFO: Insert nop before inst 0x%x: Old dep size = 0x%x, new dep size = 0x%"PRIx64"\n",
		inst, self->flag_dependency_size, inst_log);
	debug_print(DEBUG_MAIN, 1, "INFO: Setting flag_result_users[0x%"PRIx64"] = 0\n", inst_log - 1);
	self->flag_dependency_size = inst_log;

	inst_log1_new->instruction.opcode = NOP;
        inst_log1_new->instruction.flags = 0;
	if (inst_log1->prev_size) {
		inst_log1_new->prev = calloc(inst_log1->prev_size, sizeof(int));
		inst_log1_new->prev_size = inst_log1->prev_size;
		for (n = 0; n < inst_log1->prev_size; n++) {
			inst_log1_new->prev[n] = inst_log1->prev[n];
			if (inst_log1->prev[n] == 0) {
				debug_print(DEBUG_MAIN, 1, "ERROR: Insert nop before first instruction not yet supported. Case 0\n");
				/* Move the entry point. Should never get here */
				exit(1);
			}
			inst_log1_previous = &inst_log_entry[inst_log1->prev[n]];
			for (m = 0; m < inst_log1_previous->next_size; m++) {
				if (inst_log1_previous->next[m] == inst) {
					inst_log1_previous->next[m] = inst_new;
				}
			}
		}
	} else {
		for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
			if ((self->external_entry_points[l].valid != 0) &&
				(self->external_entry_points[l].type == 1) &&
				(self->external_entry_points[l].inst_log == inst)) {
					self->external_entry_points[l].inst_log = inst_new;
				debug_print(DEBUG_MAIN, 1, "fixing entry point[0x%x] from 0x%x to 0x%x\n",
					l, inst, inst_new);
			}
		}
	}
	inst_log1_new->next = calloc(1, sizeof(int));
	inst_log1_new->next_size = 1;
	inst_log1_new->next[0] = inst;
	if (0 == inst_log1->prev_size) {
		inst_log1->prev = calloc(1, sizeof(int));
	}
	inst_log1->prev_size = 1;
	inst_log1->prev[0] = inst_new;
	*new_inst = inst_new;

	return 0;
}

int insert_nop_after(struct self_s *self, int inst, int *new_inst)
{
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct inst_log_entry_s *inst_log1 = &inst_log_entry[inst];
	struct inst_log_entry_s *inst_log1_next;
	struct inst_log_entry_s *inst_log1_new;
	int m,n;
	int inst_new;

	inst_new = inst_log;
	if (inst_log1->next_size > 1) {
		debug_print(DEBUG_MAIN, 1, "insert_nop_after: FAILED Inst 0x%x\n", inst);
		return 1;
	}
	inst_log1_new = &inst_log_entry[inst_log];
	inst_log++;
	self->flag_dependency = realloc(self->flag_dependency, (inst_log) * sizeof(int));
	self->flag_dependency[inst_log - 1] = 0;
	self->flag_dependency_opcode = realloc(self->flag_dependency_opcode, (inst_log) * sizeof(int));
	self->flag_dependency_opcode[inst_log - 1] = 0;
	self->flag_result_users = realloc(self->flag_result_users, (inst_log) * sizeof(int));
	self->flag_result_users[inst_log - 1] = 0;
	debug_print(DEBUG_MAIN, 1, "INFO: Insert nop after: Old dep size = 0x%x, new dep size = 0x%"PRIx64"\n", self->flag_dependency_size, inst_log);
	self->flag_dependency_size = inst_log;

	inst_log1_new->instruction.opcode = NOP;
        inst_log1_new->instruction.flags = 0;
	if (inst_log1->next_size) {
		inst_log1_new->next = calloc(inst_log1->next_size, sizeof(int));
		inst_log1_new->next_size = inst_log1->next_size;
		for (n = 0; n < inst_log1->next_size; n++) {
			inst_log1_new->next[n] = inst_log1->next[n];
			inst_log1_next = &inst_log_entry[inst_log1->next[n]];
			for (m = 0; m < inst_log1_next->prev_size; m++) {
				if (inst_log1_next->prev[m] == inst) {
					inst_log1_next->prev[m] = inst_new;
				}
			}
		}
	}
	inst_log1_new->prev = calloc(1, sizeof(int));
	inst_log1_new->prev_size = 1;
	inst_log1_new->prev[0] = inst;
	inst_log1->next_size = 1;
	inst_log1->next[0] = inst_new;
	*new_inst = inst_new;

	return 0;
}

int create_function_node_members(struct self_s *self, struct external_entry_point_s *external_entry_point)
{
	int m, n;
	int global_nodes_size = self->nodes_size;
	struct control_flow_node_s *global_nodes = self->nodes;
	int member_nodes_size;
	int *member_nodes;
	int *node_list;
	int found = 0;
	int count = 1;
	int node;
	int next_node;
	int tmp;

	struct mid_node_s {
		int node;
		int valid;
	};
	struct mid_node_s *mid_node;

	
	node_list = calloc(global_nodes_size + 1, sizeof(int));
	mid_node = calloc(100, sizeof(struct mid_node_s));

	mid_node[0].node = external_entry_point->start_node;
	mid_node[0].valid = 1;

	do {
		for (n = 0; n < 100; n++) {
			if (mid_node[n].valid == 1) {
				node = mid_node[n].node;
				mid_node[n].valid = 0;
				break;
			}
		}
		if (n == 100) {
			/* finished */
			found = 1;
			break;
		}	
		if (node_list[node] == 0) {
			node_list[node] = count;
			count++;
		}
		for (n = 0; n < global_nodes[node].next_size; n++) {
			next_node = global_nodes[node].link_next[n].node;
			if (node_list[next_node] == 0) {
				for (m = 0; m < 100; m++) {
					if (mid_node[m].valid == 0) {
						mid_node[m].node = next_node;
						mid_node[m].valid = 1;
						break;
					}
				}
				if (m == 100) {
					printf("Failed in create_function_node_members(). No free mid_nodes.\n");
					exit(1);
				}
			}
		}
	} while (found == 0);
	member_nodes = calloc(count, sizeof(int));
	member_nodes_size = count;
	for (n = 1; n <= global_nodes_size; n++) {
		tmp = node_list[n];
		if (tmp != 0 && tmp < member_nodes_size) {
			member_nodes[tmp] = n;
		}
	}
	external_entry_point->member_nodes_size = member_nodes_size;
	external_entry_point->member_nodes = member_nodes;
	external_entry_point->nodes_size = member_nodes_size;
	external_entry_point->nodes = calloc(member_nodes_size, sizeof(struct control_flow_node_s));

	/* node 0 is intentionally not used */
	for (n = 1; n < member_nodes_size; n++) {
		memcpy(&(external_entry_point->nodes[n]), &(global_nodes[member_nodes[n]]), sizeof (struct control_flow_node_s));
		external_entry_point->nodes[n].prev_node = calloc(external_entry_point->nodes[n].prev_size, sizeof(int));
		memcpy(&(external_entry_point->nodes[n].prev_node), &(global_nodes[member_nodes[n]].prev_node), external_entry_point->nodes[n].prev_size * sizeof (int));
		for (m = 0; m < external_entry_point->nodes[n].prev_size; m++) {
			external_entry_point->nodes[n].prev_node[m] = node_list[external_entry_point->nodes[n].prev_node[m]];
		}
		external_entry_point->nodes[n].prev_link_index = calloc(external_entry_point->nodes[n].prev_size, sizeof(int));
		memcpy(&(external_entry_point->nodes[n].prev_link_index), &(global_nodes[member_nodes[n]].prev_link_index), external_entry_point->nodes[n].prev_size * sizeof (int));
		external_entry_point->nodes[n].link_next = calloc(external_entry_point->nodes[n].next_size, sizeof(struct node_link_s));
		memcpy(&(external_entry_point->nodes[n].link_next), &(global_nodes[member_nodes[n]].link_next), external_entry_point->nodes[n].next_size * sizeof (struct node_link_s));
		for (m = 0; m < external_entry_point->nodes[n].next_size; m++) {
			external_entry_point->nodes[n].link_next[m].node = node_list[external_entry_point->nodes[n].link_next[m].node];
		}
	}
	free(mid_node);
	free(node_list);
#if 0
	printf("function: %s\n", external_entry_point->name);
	for (n = 1; n < member_nodes_size; n++) {
		printf("Node=0x%x\n", member_nodes[n]);
	}
#endif

	return 0;
}

int assign_id_label_dst(struct self_s *self, int function, int inst, struct inst_log_entry_s *inst_log1, struct label_s *label)
{
	/* returns 0 for id and label set. 1 for error */
	int ret = 1;
	struct instruction_s *instruction =  &inst_log1->instruction;
	int variable_id = self->external_entry_points[function].variable_id;
	uint64_t stack_address;
	uint64_t data_address;
	int index;
	int tmp;
	struct memory_s *memory;

	debug_print(DEBUG_MAIN, 1, "label address2 = %p\n", label);
	debug_print(DEBUG_MAIN, 1, "opcode = 0x%x\n", instruction->opcode);
	debug_print(DEBUG_MAIN, 1, "value to log_to_label:entry_point = 0x%x, inst = 0x%x:%s, dstA:store 0x%x, indirect 0x%x, index 0x%"PRIx64", value_size 0x%x, relocated 0x%x, value3:value_scope 0x%x, value_id 0x%"PRIx64", indirect_offset_value 0x%"PRIx64"\n",
		function,
		inst,
		opcode_table[instruction->opcode],
		instruction->dstA.store,
		instruction->dstA.indirect,
		instruction->dstA.index,
		instruction->dstA.value_size,
		instruction->dstA.relocated,
		inst_log1->value3.value_scope,
		inst_log1->value3.value_id,
		inst_log1->value3.indirect_offset_value);

	switch (instruction->opcode) {
	case NOP:
		break;
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
	case ZEXT:
	case TRUNC:
	case BITCAST:
	case ICMP:
	case LOAD:
		switch (instruction->dstA.indirect) {
		case IND_DIRECT:
			debug_print(DEBUG_MAIN, 1, "assign_id_dst: IND_DIRECT\n");
			inst_log1->value3.value_id = variable_id;
			/* Override the EXE setting for now */
			if (inst_log1->value3.value_scope == 1) {
				inst_log1->value3.value_scope = 2;
			}
			memset(label, 0, sizeof(struct label_s));
			ret = log_to_label(instruction->dstA.store,
				instruction->dstA.indirect,
				instruction->dstA.index,
				instruction->dstA.value_size,
				instruction->dstA.relocated,
				inst_log1->value3.value_scope,
				inst_log1->value3.value_id,
				inst_log1->value3.indirect_offset_value,
				label);
			debug_print(DEBUG_MAIN, 1, "value1 scope 0x%x, value2 scope 0x%x, value3 scope 0x%x\n",
				inst_log1->value1.value_scope,
				inst_log1->value2.value_scope,
				inst_log1->value3.value_scope);
			if (ret) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x%x, value3 unknown label\n", inst);
				debug_print(DEBUG_MAIN, 1, "value1 scope 0x%x, value2 scope 0x%x, value3 scope 0x%x\n",
					inst_log1->value1.value_scope,
					inst_log1->value2.value_scope,
					inst_log1->value3.value_scope);
			}
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "Unknown instruction->dstA.indirect = 0x%x\n",
				instruction->dstA.indirect);
			break;
		}
		break;

	case STORE:
		switch (instruction->dstA.indirect) {
		case IND_DIRECT:
			debug_print(DEBUG_MAIN, 1, "assign_id_dst: Failed: IND_DIRECT STORE should not happen\n");
			break;

		case IND_MEM:
			debug_print(DEBUG_MAIN, 1, "assign_id_dst: IND_MEM\n");
			inst_log1->value3.value_id = 0;
			data_address = inst_log1->value3.indirect_init_value + inst_log1->value3.indirect_offset_value;
			debug_print(DEBUG_MAIN, 1, "assign_id: data_address = 0x%"PRIx64"\n", data_address);
			memory = search_store(
				self->external_entry_points[function].process_state.memory_data,
				data_address,
				inst_log1->instruction.dstA.indirect_size);
			if (memory) {
				if (memory->value_id) {
					inst_log1->value3.value_id = memory->value_id;
					ret = 0;
					break;
				} else {
					inst_log1->value3.value_id = variable_id;
					memory->value_id = variable_id;
					ret = log_to_label(instruction->dstA.store,
						instruction->dstA.indirect,
						instruction->dstA.index,
						instruction->dstA.value_size,
						instruction->dstA.relocated,
						inst_log1->value3.value_scope,
						inst_log1->value3.value_id,
						inst_log1->value3.indirect_offset_value,
						label);
					if (ret) {
						debug_print(DEBUG_MAIN, 1, "assign_id: IND_MEM log_to_label failed\n");
						exit(1);
					}
				}
			} else {
				debug_print(DEBUG_MAIN, 1, "FIXME: assign_id: memory not found for mem address\n");
				exit(1);
			}
			break;

		case IND_STACK:
			debug_print(DEBUG_MAIN, 1, "assign_id_dst: IND_STACK\n");
			stack_address = inst_log1->value3.indirect_init_value + inst_log1->value3.indirect_offset_value;
			debug_print(DEBUG_MAIN, 1, "assign_id: stack_address = 0x%"PRIx64"\n", stack_address);
			memory = search_store(
				self->external_entry_points[function].process_state.memory_stack,
				stack_address,
				inst_log1->instruction.dstA.indirect_size);
			if (memory) {
				if (memory->value_id) {
					inst_log1->value3.value_id = memory->value_id;
					ret = 0;
					break;
				} else {
					inst_log1->value3.value_id = variable_id;
					memory->value_id = variable_id;
					ret = log_to_label(instruction->dstA.store,
						instruction->dstA.indirect,
						instruction->dstA.index,
						instruction->dstA.value_size,
						instruction->dstA.relocated,
						inst_log1->value3.value_scope,
						inst_log1->value3.value_id,
						inst_log1->value3.indirect_offset_value,
						label);
					if (ret) {
						debug_print(DEBUG_MAIN, 1, "assign_id: IND_STACK log_to_label failed\n");
						exit(1);
					}
				}
			} else {
				debug_print(DEBUG_MAIN, 1, "FIXME: assign_id: memory not found for stack address\n");
				exit(1);
			}
			break;

		case IND_IO:
			debug_print(DEBUG_MAIN, 1, "IND_IO not yet handled\n");
			exit(1);
			break;

		default:
			debug_print(DEBUG_MAIN, 1, "Unknown instruction->dstA.indirect = 0x%x\n",
				instruction->dstA.indirect);
			exit(1);
			break;
		}
		break;

	/* Specially handled because value3 is not assigned and writen to a destination. */
	case TEST:
	case CMP:
		debug_print(DEBUG_MAIN, 1, "TEST, CMP have no DST\n");
		ret = 0;
		break;

	case CALL:
		debug_print(DEBUG_MAIN, 1, "SSA CALL inst_log 0x%x\n", inst);
		if (IND_DIRECT == instruction->dstA.indirect) {
			inst_log1->value3.value_id = variable_id;
		} else {
			debug_print(DEBUG_MAIN, 1, "ERROR: CALL with indirect dstA\n");
			exit(1);
		}
		debug_print(DEBUG_MAIN, 1, "value3.value_scope = 0x%x\n", inst_log1->value3.value_scope);
		memset(label, 0, sizeof(struct label_s));
		ret = log_to_label(instruction->dstA.store,
			instruction->dstA.indirect,
			instruction->dstA.index,
			instruction->dstA.value_size,
			instruction->dstA.relocated,
			inst_log1->value3.value_scope,
			inst_log1->value3.value_id,
			inst_log1->value3.indirect_offset_value,
			label);
		if (ret) {
			debug_print(DEBUG_MAIN, 1, "Inst:0x%x, value3 unknown label\n", inst);
		}
		break;
	case CALLM:
		debug_print(DEBUG_MAIN, 1, "SSA CALLM inst_log 0x%x\n", inst);
		if (IND_DIRECT == instruction->dstA.indirect) {
			inst_log1->value3.value_id = variable_id;
		} else {
			debug_print(DEBUG_MAIN, 1, "ERROR: CALLM with indirect dstA\n");
			exit(1);
		}
		debug_print(DEBUG_MAIN, 1, "value3.value_scope = 0x%x\n", inst_log1->value3.value_scope);
		memset(label, 0, sizeof(struct label_s));
		ret = log_to_label(instruction->dstA.store,
			instruction->dstA.indirect,
			instruction->dstA.index,
			instruction->dstA.value_size,
			instruction->dstA.relocated,
			inst_log1->value3.value_scope,
			inst_log1->value3.value_id,
			inst_log1->value3.indirect_offset_value,
			label);
		if (ret) {
			debug_print(DEBUG_MAIN, 1, "Inst:0x%x, value3 unknown label\n", inst);
		}
		break;
	case IF:
	case BRANCH:
	case RET:
	case JMP:
	case JMPT:
		debug_print(DEBUG_MAIN, 1, "IF, BRANCH, RET, JMP, JMPT have no DST\n");
		ret = 0;
		break;
	default:
		debug_print(DEBUG_MAIN, 1, "SSA1 failed for Inst:0x%x, OP 0x%x\n", inst, instruction->opcode);
		ret = 1;
		break;
	}
	return ret;
}

int fill_reg_dependency_table(struct self_s *self, struct external_entry_point_s *external_entry_point, int n)
{
	/* n is the requested node */
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	int nodes_size = external_entry_point->nodes_size;
	int m;
	int tmp;

	for (m = 0; m < MAX_REG; m++) {
		int value_id;
		if (1 == nodes[n].used_register[m].seen) {
			int node;
			int found = 0;
			debug_print(DEBUG_MAIN, 1, "Node 0x%x: Reg Used src:0x%x\n", n, m);
			tmp = find_reg_in_phi_list(self, nodes, nodes_size, n, m, &value_id);
			if (!tmp) {
				nodes[n].used_register[m].src_first_value_id = value_id;
				nodes[n].used_register[m].src_first_node = n;
				nodes[n].used_register[m].src_first_label = 1;
				debug_print(DEBUG_MAIN, 1, "Found reg 0x%x in phi. value_id = 0x%x\n", m, value_id);
				continue;
			}
			/* Start searching previous nodes for used_register and phi */
			node = n;
			debug_print(DEBUG_MAIN, 1, "Previous size 0x%x\n", nodes[node].prev_size);
			if (nodes[node].prev_size > 0) {
				debug_print(DEBUG_MAIN, 1, "Previous node 0x%x\n", nodes[node].prev_node[0]);
			}
			while ((nodes[node].prev_size > 0) && (nodes[node].prev_node[0] != 0)) {
				node = nodes[node].prev_node[0];
				debug_print(DEBUG_MAIN, 1, "Previous nodes 0x%x\n", node);
				if (nodes[node].used_register[m].dst) {
					struct inst_log_entry_s *inst_log1;
					struct instruction_s *instruction;
					struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
					inst_log1 =  &inst_log_entry[nodes[node].used_register[m].dst];
					instruction =  &inst_log1->instruction;
					/* FIXME: Handle indirect */
					/* Indirect should never happen for registers */
					if ((instruction->dstA.store == STORE_REG) &&
						(instruction->dstA.indirect == IND_DIRECT)) {
						tmp = inst_log1->value3.value_id;
					} else {
						printf("BAD DST\n");
						exit(1);
					}
					nodes[n].used_register[m].src_first_value_id = tmp;
					nodes[n].used_register[m].src_first_node = node;
					nodes[n].used_register[m].src_first_label = 2;
					debug_print(DEBUG_MAIN, 1, "Reg DST found 0x%x\n", nodes[node].used_register[m].dst);
					debug_print(DEBUG_MAIN, 1, "node 0x%x, m 0x%x\n", node, m);
					debug_print(DEBUG_MAIN, 1, "value_id = 0x%x, node = 0x%x, label = 0x%x\n",
						nodes[n].used_register[m].src_first_value_id,
						nodes[n].used_register[m].src_first_node,
						nodes[n].used_register[m].src_first_label);

					found = 1;
					break;
				}
				tmp = find_reg_in_phi_list(self, nodes, nodes_size, node, m, &value_id);
				if (!tmp) {
					nodes[n].used_register[m].src_first_value_id = value_id;
					nodes[n].used_register[m].src_first_node = node;
					nodes[n].used_register[m].src_first_label = 1;
					debug_print(DEBUG_MAIN, 1, "Found reg 0x%x in previous 0x%x phi. value_id = 0x%x\n", m, node, value_id);
					debug_print(DEBUG_MAIN, 1, "value_id = 0x%x, node = 0x%x, label = 0x%x\n",
						nodes[n].used_register[m].src_first_value_id,
						nodes[n].used_register[m].src_first_node,
						nodes[n].used_register[m].src_first_label);
					found = 1;
					break;
				}
			}
				

			if (!found) {
				/* All other searches failed, must be a param */
				/* Build the param to label pointer tables, and use it to not duplicate param labels. */
				tmp = external_entry_point->param_reg_label[m];
				if (0 == tmp) {
					nodes[n].used_register[m].src_first_value_id = external_entry_point->variable_id;
					nodes[n].used_register[m].src_first_node = 0;
					nodes[n].used_register[m].src_first_label = 3;
					external_entry_point->label_redirect[external_entry_point->variable_id].domain = 1;
					external_entry_point->label_redirect[external_entry_point->variable_id].index = external_entry_point->variable_id;
					external_entry_point->labels[external_entry_point->variable_id].scope = 2;
					external_entry_point->labels[external_entry_point->variable_id].type = 1;
					//external_entry_point->labels[external_entry_point->variable_id].lab_pointer = 0;
					external_entry_point->labels[external_entry_point->variable_id].value = m;
					//external_entry_point->labels[external_entry_point->variable_id].size_bits =  nodes[n].used_register[m].size;
					external_entry_point->param_reg_label[m] = external_entry_point->variable_id;
					debug_print(DEBUG_MAIN, 1, "Found reg 0x%x in param, label_id = 0x%x\n", m, external_entry_point->variable_id);
					debug_print(DEBUG_MAIN, 1, "value_id = 0x%x, node = 0x%x, label = 0x%x\n",
						nodes[n].used_register[m].src_first_value_id,
						nodes[n].used_register[m].src_first_node,
						nodes[n].used_register[m].src_first_label);
					external_entry_point->variable_id++;
				} else {
					nodes[n].used_register[m].src_first_value_id = tmp;
					nodes[n].used_register[m].src_first_node = 0;
					nodes[n].used_register[m].src_first_label = 3;
					debug_print(DEBUG_MAIN, 1, "Found duplicate reg 0x%x in param, label_id = 0x%x\n", m, tmp);
					debug_print(DEBUG_MAIN, 1, "value_id = 0x%x, node = 0x%x, label = 0x%x\n",
						nodes[n].used_register[m].src_first_value_id,
						nodes[n].used_register[m].src_first_node,
						nodes[n].used_register[m].src_first_label);
				}
			}
		}
	}
	return 0;
}

/* Dump the labels table */
int dump_labels_table(struct self_s *self, char *buffer)
{
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	int l;
	int n;
	int tmp;

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			for (n = 0x1; n < 0x500; n++) {
				struct label_s *label;
				struct tip2_s *tip2;
				uint64_t label_domain;
				uint64_t label_index;
				//check_domain(&(external_entry_points[l].label_redirect[n]));
				label_domain = external_entry_points[l].label_redirect[n].domain;
				label_index = external_entry_points[l].label_redirect[n].index;
				if (label_index && (1 == label_domain)) {
					label = &(external_entry_points[l].labels[label_index]);
					tip2 = &(external_entry_points[l].tip2[label_index]);
					if (label->scope) {
						tmp = label_to_string(label, buffer, 1023);
						debug_print(DEBUG_MAIN, 1, "Label 0x%x->0x%lx:0x%lx:%s/0x%lx,ps=0x%lx, lp=0x%lx, scope=0x%lx\n",
							n, label_domain, label_index,
							buffer,
							tip2->integer_size,
							/* FIXME:get correct pointer size */
							0L,
							//label->pointer_type_size_bits,
							tip2->pointer,
							label->scope);
					}
				} else {
				    if (label_domain) {
							debug_print(DEBUG_MAIN, 1, "Label 0x%x->0x%lx:0x%lx\n", n, label_domain, label_index);
					}
				}

			}
		}
	}
	return 0;
}

int call_params_to_locals(struct self_s *self, int entry_point, int node)
{
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	struct external_entry_point_s *external_entry_point = &(external_entry_points[entry_point]);
	struct external_entry_point_s *external_entry_point_callee;
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = external_entry_point->label_redirect;
	struct label_s *labels = external_entry_point->labels;
	struct label_s *labels_callee;
	int m;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	uint64_t stack_address;
	struct memory_s *memory;
	struct extension_call_s *call;
	int params_stack_size;

	int inst;
	struct label_s *label;
	int found = 0;
	int tmp;
	debug_print(DEBUG_MAIN, 1, "PARAMS: entry_point = 0x%x, node = 0x%x\n", entry_point, node);

	inst = nodes[node].inst_start;
	do {
		inst_log1 =  &inst_log_entry[inst];
		instruction =  &inst_log1->instruction;
		debug_print(DEBUG_MAIN, 1, "inst = 0x%x\n", inst);
		switch (instruction->opcode) {
		case CALL:
			switch (instruction->srcA.relocated) {
			case 1:
				debug_print(DEBUG_MAIN, 1, "relocated = %d\n", instruction->srcA.relocated);
				debug_print(DEBUG_MAIN, 1, "PRINTING INST CALL\n");
				tmp = print_inst(self, instruction, inst, labels);
				//if (instruction->srcA.relocated != 1) {
				//	break;
				//}
				debug_print(DEBUG_MAIN, 1, "not yet handled\n");
				exit(1);

				external_entry_point_callee = &external_entry_points[instruction->srcA.index];
				labels_callee = external_entry_point_callee->labels;
				call = inst_log1->extension;
				call->params_reg_size = external_entry_point_callee->params_reg_ordered_size;
				/* FIXME: use struct in sizeof bit here */
				call->params_reg = calloc(call->params_reg_size, sizeof(int *));
				if (!call) {
					debug_print(DEBUG_MAIN, 1, "ERROR: PARAM failed for inst:0x%x, CALL. Out of memory\n", inst);
					return 1;
				}
				debug_print(DEBUG_MAIN, 1, "PARAM:call size=%x\n", call->params_reg_size);
				for (m = 0; m < call->params_reg_size; m++) {
					label = &labels_callee[external_entry_point_callee->params_reg_ordered[m]];
					/* param_regXXX */
					if ((2 == label->scope) &&
						(1 == label->type)) {
						call->params_reg[m] = call->reg_tracker[label->value];
						debug_print(DEBUG_MAIN, 1, "PARAM: param_reg 0x%lx --> call_params 0x%x\n", label->value, call->params_reg[m]);
						if (!(call->reg_tracker[label->value])) {
							printf("ERROR:%s:%d invalid param at node 0x%x, inst 0x%x\n", __FUNCTION__, __LINE__, node, inst);
							exit(1);
						}
					}
				}
				params_stack_size = 0;
				for (m = 0; m < external_entry_point_callee->params_size; m++) {
					label = &labels_callee[external_entry_point_callee->params[m]];
					/* param_stackXXX */
					if ((2 == label->scope) &&
						(2 == label->type)) {
						params_stack_size++;
						/* SP value held in value2 */
						debug_print(DEBUG_MAIN, 1, "PARAM: Searching for SP(0x%"PRIx64":0x%"PRIx64") + label->value(0x%"PRIx64") - 8\n", inst_log1->value2.init_value, inst_log1->value2.offset_value, label->value);
					}
				}
				call->params_stack = calloc(params_stack_size, sizeof(uint64_t));
				call->params_stack_size = params_stack_size;
				params_stack_size = 0;
				for (m = 0; m < external_entry_point_callee->params_size; m++) {
					label = &labels_callee[external_entry_point_callee->params[m]];
					/* param_regXXX */
					if ((2 == label->scope) &&
						(2 == label->type)) {
						/* param_stackXXX */
						/* SP value held in value2 */
						call->params_stack[params_stack_size] = inst_log1->value2.offset_value + label->value - 8;
						debug_print(DEBUG_MAIN, 1, "PARAM: Found SP(0x%"PRIx64":0x%"PRIx64") + label->value(0x%"PRIx64") - 8, params_stack = 0x%lx\n", inst_log1->value2.init_value, inst_log1->value2.offset_value, label->value, call->params_stack[params_stack_size]);
						params_stack_size++;
					}
				}
				break;
			case 2:
				debug_print(DEBUG_MAIN, 1, "relocated = %d\n", instruction->srcA.relocated);
				debug_print(DEBUG_MAIN, 1, "PRINTING INST CALL\n");
				tmp = print_inst(self, instruction, inst, labels);
				//if (instruction->srcA.relocated != 1) {
				//	break;
				//}
				debug_print(DEBUG_MAIN, 1, "not yet handled\n");
				exit(1);
				break;
			case 3:
				debug_print(DEBUG_MAIN, 1, "relocated = %d\n", instruction->srcA.relocated);
				debug_print(DEBUG_MAIN, 1, "not yet handled\n");
				exit(1);
				break;
			default:
				debug_print(DEBUG_MAIN, 1, "relocated = %d\n", instruction->srcA.relocated);
				debug_print(DEBUG_MAIN, 1, "not yet handled\n");
				exit(1);
				break;
			}

		default:
			break;
		}
		if (inst == nodes[node].inst_end) {
			found = 1;
		}
		if (inst_log1->next_size > 0) {
			inst = inst_log1->next[0];
		} else {
			/* Exit here */
			found = 1;
		}
	} while (!found);

	return 0;
}

int find_function_simple_params_reg(struct self_s *self, int entry_point)
{
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	struct control_flow_node_s *nodes = external_entry_points[entry_point].nodes;
	int nodes_size = external_entry_points[entry_point].nodes_size;
	int node;
	int n, n2, n3;
	int m;
	int found;
	int tmp;
	int *array1;
	int *array2;
	int *nodes_todo;
	int size = 0;
	nodes_todo = calloc(nodes_size, sizeof(int));
	array1 = calloc(MAX_REG, sizeof(int));
	array2 = calloc(MAX_REG, sizeof(int));

	// Fill array1[] with likely candidated for params.
	for (node = 1; node < nodes_size; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		for (n = 0; n < MAX_REG; n++) {
			if (1 == nodes[node].used_register[n].seen) {
				debug_print(DEBUG_MAIN, 1, "entry_point 0x%x, node 0x%x:node_used_reg 0x%x:seen=0x%x\n",
					entry_point,
					node,
					n,
					nodes[node].used_register[n].seen);
				array1[n] = 1;
			}
		}
	}
	for (n = 0; n < MAX_REG; n++) {
		if (1 == array1[n]) {
			debug_print(DEBUG_MAIN, 1, "processing reg 0x%x\n", n);
			nodes_todo[0] = 1;
			found = 0;
			while (0 == found) {
				node = 0;
				for (m = 0; m < nodes_size; m++) {
					if (nodes_todo[m]) {
						node = nodes_todo[m];
						nodes_todo[m] = 0;
						break;
					}
				}
				debug_print(DEBUG_MAIN, 1, "found0 node = %d\n", node);
				if (0 == node) {
					// finished this reg
					found = 1;
					continue;
				}
				if (1 == nodes[node].used_register[n].seen) {
					array2[n] = 1;
					found = 1;
					debug_print(DEBUG_MAIN, 1, "found1 simple_params_reg 0x%x\n", n);
					break;
				} else if (2 == nodes[node].used_register[n].seen) {
					found = 1;
					debug_print(DEBUG_MAIN, 1, "found2 simple_params_reg 0x%x\n", n);
					continue;
				} else {
					for (n2 = 0; n2 < nodes[node].next_size; n2++) {
						// add_nodes_todo
						for (n3 = 0; n3 < nodes_size; n3++) {
							if (0 == nodes_todo[n3]) {
								break;
							}
						}
						nodes_todo[n3] = nodes[node].link_next[n2].node;
						debug_print(DEBUG_MAIN, 1, "add_nodes_todo: %d = %d\n", n3, nodes[node].link_next[n2].node);
					}
				}
			} ; // while 
		}
	}
	for (n = 0; n < MAX_REG; n++) {
		if (array2[n]) {
			debug_print(DEBUG_MAIN, 1, "simple_params_reg 0x%x\n", n);
		}
	}
	size = 0;
	for (n = 0; n < reg_params_order_size; n++) {
		if (array2[reg_params_order[n]]) {
			size = n + 1;
		}
	}
	debug_print(DEBUG_MAIN, 1, "size = %d\n", size);
	external_entry_points[entry_point].simple_params_reg = calloc(size, sizeof(int));
	for (n = 0; n < size; n++) {
		external_entry_points[entry_point].simple_params_reg[n] = reg_params_order[n];
	}
	external_entry_points[entry_point].simple_params_reg_size = size;

	free(nodes_todo);
	free(array1);
	free(array2);
	return 0;
}

int fill_in_call_params(struct self_s *self, int entry_point)
{
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	struct external_entry_point_s *external_entry_point = &(external_entry_points[entry_point]);
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	int found = 0;
	int count = 0;
	int n;
	int inst;
	for(n = 1; n < external_entry_point->nodes_size; n++) {
		if ((nodes[n].valid)) {
			inst = nodes[n].inst_start;
			found = 0;
			do {
				count++;
				inst_log1 =  &inst_log_entry[inst];
				instruction =  &inst_log1->instruction;
				switch (instruction->opcode) {
				case CALL:
					debug_print(DEBUG_MAIN, 1, "CALL found: node = 0x%x, inst = 0x%x\n", n, inst);
					break;
				default:
					break;
				}
				if (inst == nodes[n].inst_end) {
					found = 1;
					break;
				}
				if (inst_log1->next_size > 0) {
					inst = inst_log1->next[0];
				} else {
					/* Exit here */
					found = 1;
					break;
				}
			} while (!found && (count < 20000)); // FIXME: What should the safety limit be?
		}
	}
	return 0;
}

