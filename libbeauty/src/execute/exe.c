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
 *
 *
 * 11-9-2004 Initial work.
 *   Copyright (C) 2004 James Courtier-Dutton James@superbug.co.uk
 * 10-11-2007 Updates.
 *   Copyright (C) 2007 James Courtier-Dutton James@superbug.co.uk
 * 10-10-2009 Updates.
 *   Copyright (C) 2007 James Courtier-Dutton James@superbug.co.uk
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

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <rev.h>


uint64_t read_data(struct self_s *self, uint64_t offset, int size_bits) {
	uint64_t tmp, tmp2, tmp3, limit;
	int n;
	/* Convert bits to bytes. Round up. Make sure 1 bit turns into 1 byte */
	int size = (size_bits + 7) >> 3;

	tmp = 0;
	debug_print(DEBUG_EXE, 1, "read_data:offset = 0x%"PRIx64", size = %d\n", offset, size);
	limit = offset + size - 1;
	if (limit <= self->data_size) {
		for (n = (size - 1); n >= 0; n--) {
			tmp2 = (tmp << 8);
			tmp3 = self->data[n + offset];
			debug_print(DEBUG_EXE, 1, "read_data:data = 0x%"PRIx64"\n", tmp3);
			tmp = tmp2 | tmp3;
		}
	} else {
		debug_print(DEBUG_EXE, 1, "read_data: offset out of range\n");
		tmp = 0;
	}
	debug_print(DEBUG_EXE, 1, "read_data:return = 0x%"PRIx64"\n", tmp);
	
	return tmp;
}

uint64_t read_section_content(struct self_s *self, uint64_t section_index, uint64_t offset, int size_bits) {
	uint64_t tmp, tmp2, tmp3, limit;
	int n;
	/* Convert bits to bytes. Round up. Make sure 1 bit turns into 1 byte */
	int size = (size_bits + 7) >> 3;

	tmp = 0;
	debug_print(DEBUG_EXE, 1, "read_data:section_index = 0x%lx, offset = 0x%"PRIx64", size = %d\n",
			section_index, offset, size);
	limit = offset + size - 1;
	if (limit <= self->sections[section_index].content_size) {
		for (n = (size - 1); n >= 0; n--) {
			tmp2 = (tmp << 8);
			tmp3 = self->sections[section_index].content[n + offset];
			debug_print(DEBUG_EXE, 1, "read_data:data = 0x%"PRIx64"\n", tmp3);
			tmp = tmp2 | tmp3;
		}
	} else {
		debug_print(DEBUG_EXE, 1, "read_data: offset out of range\n");
		tmp = 0;
	}
	debug_print(DEBUG_EXE, 1, "read_data:return = 0x%"PRIx64"\n", tmp);

	return tmp;
}
	
	
struct memory_s *search_store(
	struct memory_s *memory, uint64_t memory_size, uint64_t index, int size_bits)
{
	int n = 0;
	uint64_t start = index;
	//uint64_t end = index + size;
	uint64_t memory_start;
	//uint64_t memory_end;
	struct memory_s *result = NULL;
	/* Convert bits to bytes. Round up. Make sure 1 bit turns into 1 byte */
	int size = (size_bits + 7) >> 3;

	debug_print(DEBUG_EXE, 1, "memory=%p, memory_size=0x%lx, index=%"PRIx64", size=%d\n",
			memory, memory_size, index, size);
	if (!memory || 0 == memory_size) {
		debug_print(DEBUG_EXE, 1, "memory NULL. exiting\n");
		exit(1);
	}
	while (memory[n].valid == 1) {
		memory_start = memory[n].start_address;
		debug_print(DEBUG_EXE, 1, "looping 0x%x:start_address = 0x%"PRIx64"\n", n, memory_start);
		//memory_end = memory[n].start_address + memory[n].length;
		/* FIXME: for now ignore size */
/*		if ((start >= memory_start) &&
			(end <= memory_end)) {
*/
		if (start == memory_start) {
			result = &memory[n];
			debug_print(DEBUG_EXE, 1, "Found entry %d in table %p, %p\n", n, memory, result);
			break;
		}
		n++;
		if ( n >= memory_size) {
			break;
		}
	}
	return result;
}

struct memory_s *add_new_store(
	struct memory_s *memory, uint64_t memory_size, uint64_t index, int size_bits)
{
	int n = 0;
	uint64_t start = index;
	//uint64_t end = index + size;
	uint64_t memory_start;
	//uint64_t memory_end;
	struct memory_s *result = NULL;
	/* Convert bits to bytes. Round up. Make sure 1 bit turns into 1 byte */
	int size = (size_bits + 7) >> 3;

	debug_print(DEBUG_EXE, 1, "add_new_store: memory=%p, index=0x%"PRIx64", size=%d\n", memory, index, size);
	while (memory[n].valid == 1) {
		memory_start = memory[n].start_address;
		debug_print(DEBUG_EXE, 1, "looping 0x%x:start_address = 0x%"PRIx64"\n", n, memory_start);
		//memory_end = memory[n].start_address + memory[n].length;
		/* FIXME: for now ignore size */
/*		if ((start >= memory_start) &&
			(end <= memory_end)) {
*/
		if (start == memory_start) {
			result = NULL;
			/* Store already existed, so exit */
			goto exit_add_new_store;
		}
		n++;
		if ( n >= memory_size) {
			goto exit_add_new_store;
		}

	}
	result = &memory[n];
	debug_print(DEBUG_EXE, 1, "Found empty entry %d in table %p, %p\n", n, memory, result);
	result->relocated = 0;
	result->relocated_section_id = 0;
	result->relocated_section_index = 0;
	result->relocated_index = 0;
	result->section_id = 0;
	result->section_index = 0;
	result->start_address = index;
	result->length = size;
	/* unknown */
	result->init_value_type = 0;
	result->init_value = 0;
	result->offset_value = 0;
	/* unknown */
	result->value_type = 0;
	/* not set yet. */
	result->ref_memory = 0;
	/* not set yet. */
	result->ref_log = 0;
	/* unknown */
	result->value_scope = 0;
	/* Each time a new value is assigned, this value_id increases */
	result->value_id = 1;
	/* 1 - Entry Used */
	result->valid = 1;
exit_add_new_store:
	return result;
}

int print_store(struct memory_s *memory) {
	int n = 0;
	uint64_t memory_start;
	while (memory[n].valid == 1) {
		memory_start = memory[n].start_address;
		debug_print(DEBUG_EXE, 1, "looping print 0x%x: start_address = 0x%"PRIx64"\n", n, memory_start);
		n++;
	}
	debug_print(DEBUG_EXE, 1, "looping print 0x%x: finished\n", n);
	return 0;
}

static int source_equals_dest(struct operand_s *srcA, struct operand_s *dstA)
{
	int ret;
	/* Exclude value in comparison for XOR */
	if ((srcA->store == dstA->store) &&
		(srcA->indirect == dstA->indirect) &&
		(srcA->indirect_size == dstA->indirect_size) &&
		(srcA->index == dstA->index) &&
		(srcA->value_size == dstA->value_size)) {
		ret = 1;
	} else {
		ret = 0;
	}
	return ret;
}

static int log_section_access(struct self_s *self, uint64_t section_index,
			uint64_t access_type,
			uint64_t index,
			uint64_t size, // size in octets
			uint64_t data_type)
{
	struct section_s *section;
	uint64_t sections_size = self->sections_size;
	if (section_index >= sections_size) {
		debug_print(DEBUG_EXE, 1, "section_index too big. exiting\n");
		exit(1);
	}
	if (0 == section_index) {
		debug_print(DEBUG_EXE, 1, "section_index is 0. Invalid. exiting\n");
		exit(1);
	}
	section = &(self->sections[section_index]);
	if (section->memory_log_capacity == 0) {
		section->memory_log = calloc( 10, sizeof(struct memory_log_s));
		section->memory_log_capacity = 10;
	}
	else if (section->memory_log_capacity <= section->memory_log_size) {
		section->memory_log = realloc(
				section->memory_log,
				sizeof(struct memory_log_s) * (section->memory_log_capacity + 10));
		section->memory_log_capacity += 10;
	}
	section->memory_log[section->memory_log_size].action = access_type;
	section->memory_log[section->memory_log_size].address = index;
	section->memory_log[section->memory_log_size].length = size;
	section->memory_log[section->memory_log_size].type = data_type;
	section->memory_log[section->memory_log_size].octets = malloc(size);
	debug_print(DEBUG_EXE, 1, "memory_log_capacity = 0x%lx, size = 0x%lx\n",
			section->memory_log_capacity,
			section->memory_log_size);
	debug_print(DEBUG_EXE, 1, "log append: section_index=0x%lx, action=0x%lx, index = 0x%lx, size = 0x%lx, type = 0x%lx\n",
			section_index,
			access_type,
			index,
			size,
			data_type);
	if (index > section->content_size) {
		debug_print(DEBUG_EXE, 1, "index too big. Exiting\n");
		exit(1);
	}
	debug_print(DEBUG_EXE, 1, "log append: memory_log_size=0x%lx, content_size=0x%lx\n",
				section->memory_log_size,
				section->content_size);

	memcpy(section->memory_log[section->memory_log_size].octets, &(section->content[index]), size);
	if (data_type == 1) {
		debug_print(DEBUG_EXE, 1, "log append1: octets = %s\n", section->memory_log[section->memory_log_size].octets);
	}
	if (data_type == 2) {
		debug_print(DEBUG_EXE, 1, "log append2: octets = %s\n", section->memory_log[section->memory_log_size].octets);
	}
	section->memory_log_size++;
	return 0;
}

int search_relocation_table(struct self_s *self, uint64_t section_index,
		uint64_t offset, uint64_t size, uint64_t *reloc_index)
{
	int n;
	struct reloc_s *reloc = self->sections[section_index].reloc_entry;
	debug_print(DEBUG_INPUT_DIS, 1, "params: section_index=0x%lx, offset = 0x%lx, size=0x%lx\n",
		section_index,
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

static int get_value_RTL_instruction(
	struct self_s *self,
	struct process_state_s *process_state,
	struct operand_s *source,
	struct memory_s *destination,
	int info_id )
{
	struct memory_s *value = NULL;
	struct memory_s *value_data = NULL;
	struct memory_s *value_stack = NULL;
	uint64_t data_index;
	int tmp;
	char *info = NULL;
	//struct memory_s *memory_text;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;
	//int *memory_used;

	//memory_text = process_state->memory_text;
	memory_stack = process_state->memory_stack;
	memory_reg = process_state->memory_reg;
	memory_data = process_state->memory_data;
	//memory_used = process_state->memory_used;

	if (info_id == 0) info = "srcA";
	if (info_id == 1) info = "srcB";
	debug_print(DEBUG_EXE, 1, "get_value_RTL_instruction:%p, %p, %i:%s\n", source, destination, info_id, info);
	switch (source->indirect) {
	case IND_DIRECT:
		/* Not indirect */
		debug_print(DEBUG_EXE, 1, "%s-direct\n", info);
		switch (source->store) {
		case STORE_DIRECT:
			/* i - immediate */
			debug_print(DEBUG_EXE, 1, "%s-immediate\n", info);
			debug_print(DEBUG_EXE, 1, "%s-relocated=0x%x\n", info, source->relocated);
			debug_print(DEBUG_EXE, 1, "relocated_section_id:0x%x relocated_section_index:0x%x + 0x%x\n",
					source->relocated_section_id,
					source->relocated_section_index,
					source->relocated_index);
			switch (source->relocated) {
			case 0:
				destination->relocated = 0;
				destination->relocated_section_id = 0;
				destination->relocated_section_index = 0;
				destination->relocated_index = 0;
				destination->section_id = 0;
				destination->section_index = 0;
				destination->start_address = 0;
				destination->length = source->value_size;

				/* known */
				destination->init_value_type = 1;
				destination->init_value = source->index;
				destination->offset_value = 0;
				break;
			case 1:
				/* TODO: Handle other cases */
				log_section_access(self, source->relocated_section_index, 4, source->relocated_index, 0, 0);
				destination->section_id = source->relocated_section_id;
				destination->section_index = source->relocated_section_index;
				destination->start_address = 0;
				destination->length = source->value_size;
				/* known */
				destination->init_value_type = 1;
				destination->init_value = source->relocated_index;
				destination->offset_value = 0;
				break;
			case 2:
				destination->relocated = source->relocated;
				destination->relocated_section_id = source->relocated_section_id;
				destination->relocated_section_index = source->relocated_section_index;
				destination->relocated_index = source->relocated_index;
				destination->section_id = source->relocated_section_id;
				destination->section_index = source->relocated_section_index;
				destination->start_address = 0;
				destination->length = source->value_size;
				/* known */
				destination->init_value_type = 1;
				destination->init_value = source->index;
				destination->offset_value = 0;
				break;
			case 3:
				destination->relocated = source->relocated;
				destination->relocated_section_id = source->relocated_section_id;
				destination->relocated_section_index = source->relocated_section_index;
				destination->relocated_index = source->relocated_index;
				destination->section_id = source->relocated_section_id;
				destination->section_index = source->relocated_section_index;
				destination->start_address = 0;
				destination->length = source->value_size;
				/* known */
				destination->init_value_type = 1;
				destination->init_value = source->index;
				destination->offset_value = 0;
				break;
			default:
				debug_print(DEBUG_EXE, 1, "exiting, relocated 0x%x not yet handled\n",
						source->relocated);
				exit(1);
				break;
			}
			debug_print(DEBUG_EXE, 1, "index=%"PRIx64", size=%d\n",
					source->index,
					source->value_size);
			/* unknown */
			destination->value_type = 0;
			/* not set yet. */
			destination->ref_memory = 0;
			/* not set yet. */
			destination->ref_log = 0;
			/* unknown */
			/* FIXME: Do we need a special value for this. E.g. for CONSTANT */
			destination->value_scope = 4; /* CONSTANT */
			/* 1 - Entry Used */
			destination->value_id = 0;
			destination->valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				destination->init_value,
				destination->offset_value,
				destination->init_value +
					 destination->offset_value);
			break;
		case STORE_REG:
			/* r - register */
			debug_print(DEBUG_EXE, 1, "%s-register\n", info);
			debug_print(DEBUG_EXE, 1, "index=%"PRIx64", size=%d\n",
					source->index,
					source->value_size);
			value = search_store(memory_reg,
					process_state->memory_reg_size,
					source->index,
					source->value_size);
			debug_print(DEBUG_EXE, 1, "GET:EXE value=%p\n", value);
			if (value) {
				debug_print(DEBUG_EXE, 1, "value_id = 0x%"PRIx64"\n", value->value_id);
				debug_print(DEBUG_EXE, 1, "init_value = 0x%"PRIx64", offset_value = 0x%"PRIx64", start_address = 0x%"PRIx64", length = 0x%x\n",
					value->init_value, value->offset_value,
					value->start_address, value->length);
			}
			/* FIXME what to do in NULL */
			if (!value) {
				value = add_new_store(memory_reg,
						process_state->memory_reg_size,
						source->index,
						source->value_size);
				value->value_id = 0;
				value->value_scope = 1;
				if (1 == info_id) {
					value->value_scope = 2;
				}
			}
			if (!value) {
				debug_print(DEBUG_EXE, 1, "GET CASE0:STORE_REG ERROR!\n");
				return 1;
				break;
			}
			destination->relocated = value->relocated;
			destination->relocated_section_id = value->relocated_section_id;
			destination->relocated_section_index = value->relocated_section_index;
			destination->section_id = value->section_id;
			destination->section_index = value->section_index;
			destination->start_address = value->start_address;
			destination->length = value->length;
			destination->init_value_type = value->init_value_type;
			destination->init_value = value->init_value;
			destination->offset_value = value->offset_value;
			destination->value_type = value->value_type;
			destination->ref_memory =
				value->ref_memory;
			destination->ref_log =
				value->ref_log;
			destination->value_scope = value->value_scope;
			/* local counter */
			destination->value_id = value->value_id;
			/* 1 - Entry Used */
			destination->valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				destination->init_value,
				destination->offset_value,
				destination->init_value +
					destination->offset_value);
			debug_print(DEBUG_EXE, 1, "relocated_section_id:0x%x relocated_section_index:0x%x + 0x%x\n",
					value->relocated_section_id,
					value->relocated_section_index,
					value->relocated_index);
			debug_print(DEBUG_EXE, 1, "section_id:0x%x section_index:0x%x\n",
					value->section_id,
					value->section_index);
			break;
		default:
			/* Should not get here */
			debug_print(DEBUG_EXE, 1, "FAILED\n");
			return 1;
		}
		break;
	case IND_MEM:
		/* m - memory */
		debug_print(DEBUG_EXE, 1, "%s-indirect\n", info);
		debug_print(DEBUG_EXE, 1, "%s-memory\n", info);
		debug_print(DEBUG_EXE, 1, "index=%"PRIx64", indirect_size=%d, value_size=%d\n",
				source->index,
				source->indirect_size,
				source->value_size);
		debug_print(DEBUG_EXE, 1, "%s-relocated=0x%x\n", info, source->relocated);
		debug_print(DEBUG_EXE, 1, "relocated_section_id:0x%x relocated_section_index:0x%x + 0x%x\n",
				source->relocated_section_id,
				source->relocated_section_index,
				source->relocated_index);
#if 0
		debug_print(DEBUG_EXE, 1, "section_id:0x%x section_index:0x%x\n",
				source->section_id,
				source->section_index);
#endif
		switch (source->store) {
		case STORE_DIRECT:
			data_index = source->index;
			break;
		case STORE_REG:
			value = search_store(memory_reg,
					process_state->memory_reg_size,
					source->index,
					source->indirect_size);
			debug_print(DEBUG_EXE, 1, "EXE value=%p\n", value);
			/* FIXME what to do in NULL */
			if (!value) {
				value = add_new_store(memory_reg,
						process_state->memory_reg_size,
						source->index,
						source->indirect_size);
				value->value_id = 0;
			}
			if (!value) {
				debug_print(DEBUG_EXE, 1, "GET CASE2:STORE_REG ERROR!\n");
				return 1;
				break;
			}
			debug_print(DEBUG_EXE, 1, "relocated=0x%x\n", value->relocated);
			debug_print(DEBUG_EXE, 1, "relocated_section_id:0x%x relocated_section_index:0x%x + 0x%x\n",
					value->relocated_section_id,
					value->relocated_section_index,
					value->relocated_index);
			debug_print(DEBUG_EXE, 1, "section_id:0x%x section_index:0x%x\n",
					value->section_id,
					value->section_index);
			data_index = value->init_value + value->offset_value;
			log_section_access(self, value->section_index, 1,
					data_index, source->value_size >> 3, 3);
			destination->value_id = value->value_id;
			break;
		default:
			/* Should not get here */
			debug_print(DEBUG_EXE, 1, "FAILED\n");
			return 1;
			break;
		}
		value_data = search_store(self->sections[value->section_index].memory,
				self->sections[value->section_index].memory_size,
				data_index,
				source->value_size);
		debug_print(DEBUG_EXE, 1, "EXE2 value_data=%p, %p\n", value_data, &value_data);
		if (!value_data) {
			uint64_t reloc_index = 0;
			value_data = add_new_store(self->sections[value->section_index].memory,
				self->sections[value->section_index].memory_size,
				data_index,
				source->value_size);
			debug_print(DEBUG_EXE, 1, "section data_index=0x%lx, size(bits)=0x%x, reloc_size = 0x%lx\n",
					data_index,
					source->value_size,
					self->sections[value->section_index].reloc_size);
			tmp = search_relocation_table(self, value->section_index,
					data_index, source->value_size / 8, &reloc_index);
			debug_print(DEBUG_EXE, 1, "tmp = %d, reloc_index = 0x%lu\n", tmp, reloc_index);
			if (tmp) {
				value_data->init_value = read_section_content(
						self, value->section_index, data_index, source->value_size);
				//debug_print(DEBUG_EXE, 1, "adding new data from content table. TODO. Exiting\n");
				//exit(1);
			} else {
				struct reloc_s *reloc_table_entry;
				reloc_table_entry = &(self->sections[value->section_index].reloc_entry[reloc_index]);
				debug_print(DEBUG_EXE, 1, "relocate found index=0x%lx, type=0x%x, offset=0x%lx, size=0x%lx, section_id=0x%lx, section_index=0x%lx,name=%s, value_int = 0x%lx, value_uint = 0x%lx, addend = 0x%lx\n",
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

				value_data->relocated_section_id = reloc_table_entry->section_id;
				value_data->relocated_section_index = reloc_table_entry->section_index;
				value_data->relocated_index = reloc_index;
				value_data->section_id = reloc_table_entry->section_id;
				value_data->section_index = reloc_table_entry->section_index;
				switch(reloc_table_entry->type) {
				case 0xffff:
					value_data->init_value = reloc_table_entry->addend;

					debug_print(DEBUG_EXE, 1, "section_name:%s at 0x%x\n",
							reloc_table_entry->name,
							reloc_table_entry->addend);
					break;

				case 0x1:
					value_data->init_value = reloc_table_entry->value_uint;
					debug_print(DEBUG_EXE, 1, "section_name:%s at 0x%x\n",
							reloc_table_entry->name,
							reloc_table_entry->value_uint);
					break;

				default:
					debug_print(DEBUG_EXE, 1, "type 0x%lx not handled\n", reloc_table_entry->type);
					exit(1);
				}

				//debug_print(DEBUG_EXE, 1, "adding new data from reloc table. TODO. Exiting\n");
				//exit(1);
			}
			/* Handle data in different sections.
			 * Handle relocations in data sections.
			 */
			//exit(1);
			//value_data->init_value = read_data(self, data_index, 32);
			debug_print(DEBUG_EXE, 1, "EXE3 value_data=%p, %p\n", value_data, &value_data);
			debug_print(DEBUG_EXE, 1, "EXE3 value_data->init_value=%"PRIx64"\n", value_data->init_value);
			/* Data */
			value_data->value_scope = 3;
			/* Param number */
			value_data->value_id = 0;
		}
		debug_print(DEBUG_EXE, 1, "variable on data:0x%"PRIx64"\n",
			data_index);
		if (!value_data) {
			debug_print(DEBUG_EXE, 1, "GET CASE2:STORE_REG2 ERROR!\n");
			return 1;
			break;
		}
		destination->relocated = value_data->relocated;
		destination->relocated_section_id = value_data->relocated_section_id;
		destination->relocated_section_index = value_data->relocated_section_index;
		destination->section_id = value_data->section_id;
		destination->section_index = value_data->section_index;
		destination->start_address = value_data->start_address;
		destination->length = value_data->length;
		destination->init_value_type = value_data->init_value_type;
		destination->init_value = value_data->init_value;
		destination->offset_value = value_data->offset_value;
		destination->indirect_init_value = value->init_value;
		destination->indirect_offset_value = value->offset_value;
		destination->value_type = value_data->value_type;
		destination->ref_memory =
			value_data->ref_memory;
		destination->ref_log =
			value_data->ref_log;
		destination->value_scope = value_data->value_scope;
		/* counter */
		destination->value_id = value_data->value_id;
		debug_print(DEBUG_EXE, 1, "%s: scope=%d, id=%"PRIu64"\n",
			info,
			destination->value_scope,
			destination->value_id);
		/* 1 - Entry Used */
		destination->valid = 1;
		debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
			destination->init_value,
			destination->offset_value,
			destination->init_value +
				destination->offset_value);
		break;
	case IND_STACK:
		/* s - stack */
		debug_print(DEBUG_EXE, 1, "%s-indirect\n", info);
		debug_print(DEBUG_EXE, 1, "%s-stack\n", info);
		debug_print(DEBUG_EXE, 1, "index=%"PRIx64", indirect_size=%d, value_size=%d\n",
				source->index,
				source->indirect_size,
				source->value_size);
		value = search_store(memory_reg,
				process_state->memory_reg_size,
				source->index,
				source->indirect_size);
		debug_print(DEBUG_EXE, 1, "EXE value=%p\n", value);
		/* FIXME what to do in NULL */
		if (!value) {
			value = add_new_store(memory_reg,
					process_state->memory_reg_size,
					source->index,
					source->indirect_size);
			if (value) value->value_id = 0;
		}
		if (!value) {
			debug_print(DEBUG_EXE, 1, "GET CASE2:STORE_REG ERROR!\n");
			return 1;
			break;
		}
		value_stack = search_store(memory_stack,
				process_state->memory_stack_size,
				value->init_value +
					value->offset_value,
					source->value_size);
		debug_print(DEBUG_EXE, 1, "EXE2 value_stack=%p, %p\n", value_stack, &value_stack);
		if (!value_stack) {
			value_stack = add_new_store(memory_stack,
				process_state->memory_stack_size,
				value->init_value +
					value->offset_value,
					source->value_size);
			debug_print(DEBUG_EXE, 1, "EXE3 value_stack=%p, %p\n", value_stack, &value_stack);
			/* Only do this init on new stores */
			/* FIXME: 0x10000 should be a global variable */
			/* because it should match the ESP entry value */
			if ((value->init_value +
				value->offset_value) > 0x10000) {
				debug_print(DEBUG_EXE, 1, "PARAM\n");
				/* Param */
				value_stack->value_scope = 1;
				/* Param number */
				value_stack->value_id = 0;
			} else {
				debug_print(DEBUG_EXE, 1, "LOCAL\n");
				/* Local */
				value_stack->value_scope = 2;
				/* Local number */
				value_stack->value_id = 0;
			}
/* Section ends */
		}
		debug_print(DEBUG_EXE, 1, "variable on stack:0x%"PRIx64"\n",
			value->init_value + value->offset_value);
		if (!value_stack) {
			debug_print(DEBUG_EXE, 1, "GET CASE2:STORE_REG2 ERROR!\n");
			return 1;
			break;
		}
		destination->relocated = value_stack->relocated;
		destination->relocated_section_id = value_stack->relocated_section_id;
		destination->relocated_section_index = value_stack->relocated_section_index;
		destination->section_id = value_stack->section_id;
		destination->section_index = value_stack->section_index;
		destination->start_address = 0;
		destination->length = value_stack->length;
		destination->init_value_type = value_stack->init_value_type;
		destination->init_value = value_stack->init_value;
		destination->offset_value = value_stack->offset_value;
		destination->indirect_init_value = value->init_value;
		destination->indirect_offset_value = value->offset_value;
		destination->value_type = value_stack->value_type;
		destination->ref_memory =
			value_stack->ref_memory;
		destination->ref_log =
			value_stack->ref_log;
		destination->value_scope = value_stack->value_scope;
		/* counter */
		destination->value_id = value_stack->value_id;
		debug_print(DEBUG_EXE, 1, "%s: scope=%d, id=%"PRIu64"\n",
			info,
			destination->value_scope,
			destination->value_id);
		/* 1 - Entry Used */
		destination->valid = 1;
		debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
			destination->init_value,
			destination->offset_value,
			destination->init_value +
				destination->offset_value);
		break;
	default:
		/* Should not get here */
		debug_print(DEBUG_EXE, 1, "FAILED\n");
		return 1;
	}
	print_store(memory_reg);
	print_store(memory_stack);
	return 0;
}

static int put_value_RTL_instruction( 
	struct self_s *self,
	struct process_state_s *process_state,
	struct inst_log_entry_s *inst)
{
	struct instruction_s *instruction;
	struct memory_s *value;
//	struct memory_s *value_mem;
	struct memory_s *value_data;
	struct memory_s *value_stack;
	uint64_t data_index;
	//struct memory_s *memory_text;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;
	//int *memory_used;
	int result = 1;

	//memory_text = process_state->memory_text;
	memory_stack = process_state->memory_stack;
	memory_reg = process_state->memory_reg;
	memory_data = process_state->memory_data;
	//memory_used = process_state->memory_used;

	/* Put result in dstA */
	instruction = &inst->instruction;
	switch (instruction->dstA.indirect) {
	case IND_DIRECT:
		/* Not indirect */
		debug_print(DEBUG_EXE, 1, "dstA-direct\n");
		switch (instruction->dstA.store) {
		case STORE_DIRECT:
			/* i - immediate */
			debug_print(DEBUG_EXE, 1, "dstA-immediate-THIS SHOULD NEVER HAPPEN!\n");
			result = 1;
			goto exit_put_value;
			break;
		case STORE_REG:
			/* r - register */
			debug_print(DEBUG_EXE, 1, "dstA-register saving result\n");
			value = search_store(memory_reg,
					process_state->memory_reg_size,
					instruction->dstA.index,
					instruction->dstA.value_size);
			debug_print(DEBUG_EXE, 1, "EXE value=%p\n", value);
			if (value) {
				debug_print(DEBUG_EXE, 1, "init_value = 0x%"PRIx64", offset_value = 0x%"PRIx64", start_address = 0x%"PRIx64", length = 0x%x\n",
					value->init_value, value->offset_value,
					value->start_address, value->length);
			}
			/* FIXME what to do in NULL */
			if (!value) {
				debug_print(DEBUG_EXE, 1, "Reg 0x%lx not found, Adding new store\n", instruction->dstA.index);
				value = add_new_store(memory_reg,
						process_state->memory_reg_size,
						instruction->dstA.index,
						instruction->dstA.value_size);
			}
			if (!value) {
				debug_print(DEBUG_EXE, 1, "PUT CASE0:STORE_REG ERROR!\n");
				result = 1;
				goto exit_put_value;
				break;
			}
			/* eip changing */
			/* Make the constant 0x24 configurable
			 * depending on CPU type.
			 */
			debug_print(DEBUG_EXE, 1, "STORE_REG: index=0x%"PRIx64", start_address=0x%"PRIx64"\n",
				instruction->dstA.index, value->start_address);
			if (value->start_address != instruction->dstA.index) {
				debug_print(DEBUG_EXE, 1, "STORE failure\n");
				result = 1;
				goto exit_put_value;
				break;
			}
			if (value->start_address == 0x24) {
				debug_print(DEBUG_EXE, 1, "A JUMP or RET has occured\n");
			}

			/* FIXME: these should always be the same */
			/* value->length = inst->value3.length; */
			debug_print(DEBUG_EXE, 1, "STORING: value3.start_address 0x%"PRIx64" into value->start_address 0x%"PRIx64"\n",
				inst->value3.start_address, value->start_address);
			if (value->start_address != inst->value3.start_address) {
				debug_print(DEBUG_EXE, 1, "STORE failure2\n");
				result = 1;
				exit(1);
				goto exit_put_value;
				break;
			}
			
			value->relocated = inst->value3.relocated;
			value->relocated_section_id = inst->value3.relocated_section_id;
			value->relocated_section_index = inst->value3.relocated_section_index;
			value->relocated_index = inst->value3.relocated_index;
			value->section_id = inst->value3.section_id;
			value->section_index = inst->value3.section_index;

			value->start_address = inst->value3.start_address;
			value->init_value_type = inst->value3.init_value_type;
			value->init_value = inst->value3.init_value;
			value->offset_value = inst->value3.offset_value;
			value->value_type = inst->value3.value_type;
			value->ref_memory =
				inst->value3.ref_memory;
			value->ref_log =
				inst->value3.ref_log;
			value->value_scope = inst->value3.value_scope;
			/* 1 - Ids */
			value->value_id = inst->value3.value_id;
			debug_print(DEBUG_EXE, 1, "Saving to reg value_id of 0x%"PRIx64"\n", value->value_id);
			/* 1 - Entry Used */
			value->valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				value->init_value,
				value->offset_value,
				value->init_value + value->offset_value);
			debug_print(DEBUG_EXE, 1, "relocated=0x%x\n", value->relocated);
			debug_print(DEBUG_EXE, 1, "relocated_section_id:0x%x relocated_section_index:0x%x + 0x%x\n",
					value->relocated_section_id,
					value->relocated_section_index,
					value->relocated_index);
			debug_print(DEBUG_EXE, 1, "section_id:0x%x section_index:0x%x\n",
					value->section_id,
					value->section_index);
			result = 0;
			break;
		default:
			/* Should not get here */
			debug_print(DEBUG_EXE, 1, "FAILED\n");
			result = 1;
			goto exit_put_value;
		}
		break;
	case IND_MEM:
		/* m - memory */
		/* FIXME TODO */
		debug_print(DEBUG_EXE, 1, "dstA-indirect-NOT\n");
		debug_print(DEBUG_EXE, 1, "dstA-memory-NOT\n");
		debug_print(DEBUG_EXE, 1, "index=%"PRIx64", value_size=%d\n",
				instruction->dstA.index,
				instruction->dstA.value_size);
		switch (instruction->dstA.store) {
		case STORE_DIRECT:
			data_index = instruction->dstA.index;
			result = 0;
			break;
		case STORE_REG:
			value = search_store(memory_reg,
					process_state->memory_reg_size,
					instruction->dstA.index,
					instruction->dstA.indirect_size);
			debug_print(DEBUG_EXE, 1, "EXE value=%p\n", value);
			/* FIXME what to do in NULL */
			if (!value) {
				value = add_new_store(memory_reg,
						process_state->memory_reg_size,
						instruction->dstA.index,
						instruction->dstA.indirect_size);
				value->value_id = 0;
			}
			if (!value) {
				debug_print(DEBUG_EXE, 1, "GET CASE2:STORE_REG ERROR!\n");
				result = 1;
				goto exit_put_value;
				break;
			}
			if (value->start_address != instruction->dstA.index) {
				debug_print(DEBUG_EXE, 1, "STORE failure\n");
				result = 1;
				goto exit_put_value;
				break;
			}
			data_index = value->init_value + value->offset_value;
			result = 0;
			break;
		default:
			/* Should not get here */
			debug_print(DEBUG_EXE, 1, "FAILED\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		value_data = search_store(memory_data,
				process_state->memory_data_size,
				data_index,
				instruction->dstA.value_size);
		debug_print(DEBUG_EXE, 1, "EXE2 value_data=%p\n", value_data);
		if (!value_data) {
			value_data = add_new_store(memory_data,
				process_state->memory_data_size,
				data_index,
				instruction->dstA.value_size);
		}
		if (!value_data) {
			debug_print(DEBUG_EXE, 1, "PUT CASE2:STORE_REG2 ERROR!\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		if (value_data->start_address != data_index) {
			debug_print(DEBUG_EXE, 1, "STORE DATA failure\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		/* FIXME: these should always be the same */
		/* value_data->length = inst->value3.length; */
		value_data->init_value_type = inst->value3.init_value_type;
		value_data->init_value = inst->value3.init_value;
		value_data->offset_value = inst->value3.offset_value;
		value_data->value_type = inst->value3.value_type;
		value_data->ref_memory =
			inst->value3.ref_memory;
		value_data->ref_log =
			inst->value3.ref_log;
		value_data->value_scope = inst->value3.value_scope;
		/* 1 - Ids */
		value_data->value_id = inst->value3.value_id;
		debug_print(DEBUG_EXE, 1, "PUT: scope=%d, id=%"PRIu64"\n",
			value_data->value_scope,
			value_data->value_id);
		/* 1 - Entry Used */
		value_data->valid = 1;
		debug_print(DEBUG_EXE, 1, "value_data=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
			value_data->init_value,
			value_data->offset_value,
			value_data->init_value + value_data->offset_value);
		debug_print(DEBUG_EXE, 1, "relocated=0x%x\n", value_data->relocated);
		debug_print(DEBUG_EXE, 1, "relocated_section_id:0x%x relocated_section_index:0x%x + 0x%x\n",
				value_data->relocated_section_id,
				value_data->relocated_section_index,
				value_data->relocated_index);
		debug_print(DEBUG_EXE, 1, "section_id:0x%x section_index:0x%x\n",
				value_data->section_id,
				value_data->section_index);
		result = 0;
		break;
	case IND_STACK:
		/* s - stack */
		debug_print(DEBUG_EXE, 1, "dstA-indirect\n");
		debug_print(DEBUG_EXE, 1, "dstA-stack saving result\n");
		debug_print(DEBUG_EXE, 1, "index=%"PRIx64", indirect_size=%d\n",
				instruction->dstA.index,
				instruction->dstA.indirect_size);
		value = search_store(memory_reg,
				process_state->memory_reg_size,
				instruction->dstA.index,
				instruction->dstA.indirect_size);
		debug_print(DEBUG_EXE, 1, "dstA reg 0x%"PRIx64" value = 0x%"PRIx64" + 0x%"PRIx64"\n", instruction->dstA.index, value->init_value, value->offset_value);
		/* FIXME what to do in NULL */
		if (!value) {
			value = add_new_store(memory_reg,
					process_state->memory_reg_size,
					instruction->dstA.index,
					instruction->dstA.indirect_size);
		}
		if (!value) {
			debug_print(DEBUG_EXE, 1, "PUT CASE2:STORE_REG ERROR!\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		if (value->start_address != instruction->dstA.index) {
			debug_print(DEBUG_EXE, 1, "STORE failure\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		value_stack = search_store(memory_stack,
				process_state->memory_stack_size,
				value->init_value +
					value->offset_value,
				instruction->dstA.value_size);
		debug_print(DEBUG_EXE, 1, "EXE2 value_stack=%p\n", value_stack);
		if (!value_stack) {
			value_stack = add_new_store(memory_stack,
				process_state->memory_stack_size,
				value->init_value +
					value->offset_value,
				instruction->dstA.value_size);
		}
		if (!value_stack) {
			debug_print(DEBUG_EXE, 1, "PUT CASE2:STORE_REG2 ERROR!\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		/* FIXME: these should always be the same */
		/* value_stack->length = inst->value3.length; */
		value_stack->init_value_type = inst->value3.init_value_type;
		value_stack->init_value = inst->value3.init_value;
		value_stack->offset_value = inst->value3.offset_value;
		value_stack->value_type = inst->value3.value_type;
		value_stack->ref_memory =
			inst->value3.ref_memory;
		value_stack->ref_log =
			inst->value3.ref_log;
		value_stack->value_scope = inst->value3.value_scope;
		/* 1 - Ids */
		value_stack->value_id = inst->value3.value_id;
		debug_print(DEBUG_EXE, 1, "PUT: scope=%d, id=%"PRIu64"\n",
			value_stack->value_scope,
			value_stack->value_id);
		/* 1 - Entry Used */
		value_stack->valid = 1;
		debug_print(DEBUG_EXE, 1, "value_stack=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
			value_stack->init_value,
			value_stack->offset_value,
			value_stack->init_value + value_stack->offset_value);
		debug_print(DEBUG_EXE, 1, "relocated=0x%x\n", value_stack->relocated);
		debug_print(DEBUG_EXE, 1, "relocated_section_id:0x%x relocated_section_index:0x%x + 0x%x\n",
				value_stack->relocated_section_id,
				value_stack->relocated_section_index,
				value_stack->relocated_index);
		debug_print(DEBUG_EXE, 1, "section_id:0x%x section_index:0x%x\n",
				value_stack->section_id,
				value_stack->section_index);

		result = 0;
		break;
	default:
		/* Should not get here */
		debug_print(DEBUG_EXE, 1, "FAILED\n");
		result = 1;
		goto exit_put_value;
	}

exit_put_value:
	print_store(memory_reg);
	print_store(memory_stack);
	return result;
}

int process_hints(struct self_s *self,
		struct process_state_s *process_state,
		struct extension_call_s *call,
		int hint_size,
		int *hint_array)
{
	int n;
	int tmp;
	int reg;
	int hint;
	uint64_t offset;
	uint64_t length;
	int found;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;
	struct memory_s *value = NULL;
	//int *memory_used;

	//memory_text = process_state->memory_text;
	memory_stack = process_state->memory_stack;
	memory_reg = process_state->memory_reg;
	memory_data = process_state->memory_data;
	//memory_used = process_state->memory_used;
	int params_reg_size = call->params_reg_size;
	int *params_reg = call->params_reg;


	for (n = 0; n < hint_size; n++) {
		hint = hint_array[n];
		reg = params_reg[n];
		debug_print(DEBUG_EXE, 1, "Hint[%d] = 0x%x, Reg[%d] = 0x%x\n", n, hint_array[n], n, reg);
		value = search_store(memory_reg,
				process_state->memory_reg_size,
				reg,
				64);
		if (!value) {
			debug_print(DEBUG_EXE, 1, "value not found. exiting\n");
			exit(1);
		}
		debug_print(DEBUG_EXE, 1, "value.relocated = 0x%lx\n", value->relocated);
		debug_print(DEBUG_EXE, 1, "value.relocated_section_id = 0x%lx\n", value->relocated_section_id);
		debug_print(DEBUG_EXE, 1, "value.relocated_section_index = 0x%lx\n", value->relocated_section_index);
		debug_print(DEBUG_EXE, 1, "value.relocated_index = 0x%lx\n", value->relocated_index);
		debug_print(DEBUG_EXE, 1, "value.section_id = 0x%lx\n", value->section_id);
		debug_print(DEBUG_EXE, 1, "value.section_index = 0x%lx\n", value->section_index);
		switch (hint) {
		case 1: /* string-zero */
			length = 0;
			found = 0;
			for(offset = value->init_value + value->offset_value;
				offset < self->sections[value->section_index].content_size; offset++) {
				length++;
				if (self->sections[value->section_index].content[offset] == 0) {
					found = 1;
					break;
				}
			}
			if (found) {
				debug_print(DEBUG_EXE, 1, "string1 offset=0x%lx length=0x%lx\n",
						value->init_value + value->offset_value,
						length);
				log_section_access(self, value->section_index, 1, value->init_value + value->offset_value, length, 1);
			}
			break;

		case 2: /* format-string-zero */
			length = 0;
			found = 0;
			for(offset = value->init_value + value->offset_value;
				offset < self->sections[value->section_index].content_size; offset++) {
				length++;
				if (self->sections[value->section_index].content[offset] == 0) {
					found = 1;
					break;
				}
			}
			if (found) {
				debug_print(DEBUG_EXE, 1, "string2 offset=0x%lx length=0x%lx\n",
						value->init_value + value->offset_value,
						length);
				tmp = format_count_params(length, &(self->sections[value->section_index].content[value->init_value + value->offset_value]));
				debug_print(DEBUG_EXE, 1, "string2a param count=0x%x reg_param_size=0x%x\n",
						tmp, params_reg_size);
				call->params_reg_size = call->params_reg_size + tmp;
				call->params_reg = realloc(call->params_reg, call->params_reg_size * sizeof(int));
				for(n = 0; n < call->params_reg_size; n++) {
					call->params_reg[n] = self->external_function_reg_order[n];
				}
				debug_print(DEBUG_EXE, 1, "string2b param count=0x%x reg_param_size=0x%x\n",
						tmp, call->params_reg_size);
				log_section_access(self, value->section_index, 1, value->init_value + value->offset_value, length, 2);
			} else {
				debug_print(DEBUG_EXE, 1, "format string not found\n");
				exit(1);
			}
			break;

		default:
			debug_print(DEBUG_EXE, 1, "Unknown hint type - exiting\n");
			exit(1);
		}

	}
	return 0;
}



int execute_instruction(struct self_s *self, struct process_state_s *process_state, struct inst_log_entry_s *inst)
{
	struct instruction_s *instruction;
	struct memory_s *value;
	//struct memory_s *memory_text;
	//struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	//struct memory_s *memory_data;
	//int *memory_used;
	struct operand_s operand;
	int16_t tmp16s;
	int32_t tmp32s;
	int64_t tmp64s;
	uint16_t tmp16u;
	uint32_t tmp32u;
	uint64_t tmp64u;
	int tmp;
	int n;
	struct extension_call_s *call;
	struct external_function_s *external_function;
	char *function_name;
	int hint_size;
	int *hint_array;
	uint64_t eip;
	int fields_size = 0;

	//memory_text = process_state->memory_text;
	//memory_stack = process_state->memory_stack;
	memory_reg = process_state->memory_reg;
	//memory_data = process_state->memory_data;
	//memory_used = process_state->memory_used;
	int ret = 0;
	eip = memory_reg[2].offset_value;

	instruction = &inst->instruction;

	print_inst_short(self, instruction);
	switch (instruction->opcode) {
	case NOP:
		break;
	case CMP:
	case TEST:
		if ((instruction->srcA.value_size == 0) ||
			(instruction->srcB.value_size == 0)) {
			debug_print(DEBUG_EXE, 1, "ERROR: value_size == 0\n");
			exit(1);
		}
		break;
	case MOV:
	case NEG:
	case NOT:
	case TRUNC:
        case ZEXT:
		if ((instruction->srcA.value_size == 0) ||
			(instruction->dstA.value_size == 0)) {
			debug_print(DEBUG_EXE, 1, "ERROR: value_size == 0\n");
			exit(1);
		}
		break;
	case ADC:
	case ADD:
	case MUL:
	case IMUL:
	case SBB:
	case SUB:
	case rAND:
	case OR:
	case XOR:
	case SHL:
	case SHR:
	case SAL:
	case SAR:
		if ((instruction->srcA.value_size == 0) ||
			(instruction->srcB.value_size == 0) ||
			(instruction->dstA.value_size == 0)) {
			debug_print(DEBUG_EXE, 1, "ERROR: value_size == 0\n");
			exit(1);
		}
		break;
	case LOAD:
	case STORE:
	case JMPT:
	case JMP:
	case CALL:
	case CALLM:
	case IF:
	case SEX:
	case BITCAST:
		break;
	default:
		debug_print(DEBUG_EXE, 1, "ERROR: Unchecked value_size\n");
		exit(1);
		break;
	}

	switch (instruction->opcode) {
	case NOP:
		/* Get value of srcA */
		//ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of dstA */
		//ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "NOP\n");
		//put_value_RTL_instruction(self, process_state, inst);
		break;
	case CMP:
		/* Currently, do the same as NOP */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "CMP\n");
		//debug_print(DEBUG_EXE, 1, "value1 = 0x%x, value2 = 0x%x\n", inst->value1, inst->value2);
		debug_print(DEBUG_EXE, 1, "value_scope1=0x%"PRIx32", value_scope2=0x%"PRIx32"\n",
			inst->value1.value_scope,
			inst->value2.value_scope);
		debug_print(DEBUG_EXE, 1, "value_type1=0x%"PRIx32", value_type2=0x%"PRIx32"\n",
			inst->value1.value_type,
			inst->value2.value_type);
		debug_print(DEBUG_EXE, 1, "value_id1=0x%"PRIx64", value_id2=0x%"PRIx64"\n",
			inst->value1.value_id,
			inst->value2.value_id);
		/* A CMP does not save any values */
		//put_value_RTL_instruction(self, inst);
		break;
	case MOV:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0);
		debug_print(DEBUG_EXE, 1, "MOVvalue.relocated = 0x%lx\n", inst->value1.relocated);
		debug_print(DEBUG_EXE, 1, "MOVvalue.relocated_section_id = 0x%lx\n", inst->value1.relocated_section_id);
		debug_print(DEBUG_EXE, 1, "MOVvalue.relocated_section_index = 0x%lx\n", inst->value1.relocated_section_index);
		debug_print(DEBUG_EXE, 1, "MOVvalue.relocated_index = 0x%lx\n", inst->value1.relocated_index);
		debug_print(DEBUG_EXE, 1, "MOVvalue.section_id = 0x%lx\n", inst->value1.section_id);
		debug_print(DEBUG_EXE, 1, "MOVvalue.section_index = 0x%lx\n", inst->value1.section_index);

		/* Create result */
		debug_print(DEBUG_EXE, 1, "MOV\n");
		debug_print(DEBUG_EXE, 1, "MOV dest length = %d %d\n", inst->value1.length, inst->value3.length);
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.relocated = inst->value1.relocated;
		inst->value3.relocated_section_id = inst->value1.relocated_section_id;
		inst->value3.relocated_section_index = inst->value1.relocated_section_index;
		inst->value3.relocated_index = inst->value1.relocated_index;
		inst->value3.section_id = inst->value1.section_id;
		inst->value3.section_index = inst->value1.section_index;

		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			debug_print(DEBUG_EXE, 1, "ERROR: MOV set to dstA.indirect\n");
			exit(1);
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		/* FIXME Maybe Exception is the MOV instruction */
		debug_print(DEBUG_EXE, 1, "MOV EXE value_scope: 1 = 0x%x, 3 = 0x%x\n",
			inst->value1.value_scope, inst->value3.value_scope);
		inst->value3.value_scope = inst->value1.value_scope;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		if ((inst->value3.value_scope == 1) &&
			(STORE_REG == instruction->dstA.store) &&
			(1 == inst->value1.value_scope) &&
			(0 == instruction->dstA.indirect)) {
			inst->value3.value_scope = 2;
		}
		/* MOV imm to local */
		if ((inst->value3.value_scope == 0) &&
			(STORE_DIRECT == instruction->srcA.store) &&
			(0 == instruction->dstA.indirect)) {
			inst->value3.value_scope = 2;
		}
		if (inst->value3.value_scope == 0) {
			debug_print(DEBUG_EXE, 1, "ERROR: MOV value_scope == 0, BAD\n");
			exit(1);
		}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value2 values */
		//inst->value3.value_id = inst->value2.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		debug_print(DEBUG_EXE, 1, "pMOVvalue.relocated = 0x%lx\n", inst->value3.relocated);
		debug_print(DEBUG_EXE, 1, "pMOVvalue.relocated_section_id = 0x%lx\n", inst->value3.relocated_section_id);
		debug_print(DEBUG_EXE, 1, "pMOVvalue.relocated_section_index = 0x%lx\n", inst->value3.relocated_section_index);
		debug_print(DEBUG_EXE, 1, "pMOVvalue.relocated_index = 0x%lx\n", inst->value3.relocated_index);
		debug_print(DEBUG_EXE, 1, "pMOVvalue.section_id = 0x%lx\n", inst->value3.section_id);
		debug_print(DEBUG_EXE, 1, "pMOVvalue.section_index = 0x%lx\n", inst->value3.section_index);

		put_value_RTL_instruction(self, process_state, inst);
		break;
	case LOAD:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0);
		/* srcB is only needed in assigning labels to src. */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 0);
		/* Create result */
		debug_print(DEBUG_EXE, 1, "LOAD\n");
		debug_print(DEBUG_EXE, 1, "LOAD dest length = %d %d\n", inst->value1.length, inst->value3.length);
		inst->value3.relocated = inst->value1.relocated;
		inst->value3.relocated_section_id = inst->value1.relocated_section_id;
		inst->value3.relocated_section_index = inst->value1.relocated_section_index;
		inst->value3.relocated_index = inst->value1.relocated_index;
		inst->value3.section_id = inst->value1.section_id;
		inst->value3.section_index = inst->value1.section_index;
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			debug_print(DEBUG_EXE, 1, "ERROR: LOAD set to dstA.indirect\n");
			exit(1);
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		inst->value3.value_scope = 2;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		//if ((inst->value3.value_scope == 1) &&
		//	(STORE_REG == instruction->dstA.store) &&
		//	(1 == inst->value1.value_scope) &&
		//	(0 == instruction->dstA.indirect)) {
		//	inst->value3.value_scope = 2;
		//}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value2 values */
		//inst->value3.value_id = inst->value2.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case STORE:
		/* STORE is a special case where the indirect REG of IMM in the dstA is a direct REG or IMM in srcB */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "STORE\n");
		debug_print(DEBUG_EXE, 1, "STORE dest length = %d %d\n", inst->value1.length, inst->value3.length);
		inst->value3.start_address = inst->value2.start_address;
		inst->value3.length = inst->value2.length;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value2.init_value;
			inst->value3.indirect_offset_value =
				inst->value2.offset_value;
			inst->value3.value_id =
				inst->value2.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		if (instruction->dstA.indirect == IND_STACK) {
			inst->value3.value_scope = 2;
		} else if (instruction->dstA.indirect == IND_MEM) {
			inst->value3.value_scope = 3;
		}

		
		//inst->value3.value_scope = 3;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		//if ((inst->value3.value_scope == 1) &&
		//	(STORE_REG == instruction->dstA.store) &&
		//	(1 == inst->value1.value_scope) &&
		//	(0 == instruction->dstA.indirect)) {
		//	inst->value3.value_scope = 2;
		//}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value2 values */
		//inst->value3.value_id = inst->value2.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;

	case SEX:
		debug_print(DEBUG_EXE, 1, "SEX dest length = %d %d\n", inst->value1.length, inst->value3.length);
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SEX\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		/* Special case for SEX instruction. */
		/* FIXME: Stored value in reg store should be size modified */
		value = search_store(process_state->memory_reg,
				process_state->memory_reg_size,
				instruction->dstA.index,
				instruction->dstA.value_size);
		if (value) {
			/* Only update it if is is found */
			value->length = instruction->dstA.value_size;
		}
		debug_print(DEBUG_EXE, 1, "SEX dest length = %d %d\n", inst->value1.length, inst->value3.length);
		inst->value3.init_value_type = inst->value1.init_value_type;
		if (64 == inst->value3.length) {
			tmp32s = inst->value1.init_value;
			tmp64s = tmp32s;
			tmp64u = tmp64s;
		} else if (32 == inst->value3.length) {
			tmp16s = inst->value1.init_value;
			tmp32s = tmp16s;
			tmp64u = tmp32s;
		} else {
			debug_print(DEBUG_EXE, 1, "SEX length failure\n");
			return 1;
		}
		inst->value3.init_value = tmp64u;
		if (64 == inst->value3.length) {
			tmp32s = inst->value1.offset_value;
			tmp64s = tmp32s;
			tmp64u = tmp64s;
		} else if (32 == inst->value3.length) {
			tmp16s = inst->value1.offset_value;
			tmp32s = tmp16s;
			tmp64u = tmp32s;
		} else {
			debug_print(DEBUG_EXE, 1, "SEX length failure\n");
			return 1;
		}
		inst->value3.offset_value = tmp64u;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.relocated = inst->value1.relocated;
		inst->value3.relocated_section_id = inst->value1.relocated_section_id;
		inst->value3.relocated_section_index = inst->value1.relocated_section_index;
		inst->value3.relocated_index = inst->value1.relocated_index;
		inst->value3.section_id = inst->value1.section_id;
		inst->value3.section_index = inst->value1.section_index;

		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		/* FIXME Maybe Exception is the MOV instruction */
		inst->value3.value_scope = inst->value1.value_scope;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		if ((inst->value3.value_scope == 1) &&
			(STORE_REG == instruction->dstA.store) &&
			(1 == inst->value1.value_scope) &&
			(0 == instruction->dstA.indirect)) {
			inst->value3.value_scope = 2;
		}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value2 values */
		//inst->value3.value_id = inst->value2.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;

	case ZEXT:
		debug_print(DEBUG_EXE, 1, "ZEXT dest length = %d %d\n", inst->value1.length, inst->value3.length);
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "ZEXT\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		/* Special case for ZEXT instruction. */
		/* FIXME: Stored value in reg store should be size modified */
		value = search_store(process_state->memory_reg,
				process_state->memory_reg_size,
				instruction->dstA.index,
				instruction->dstA.value_size);
		if (value) {
			/* Only update it if is is found */
			value->length = instruction->dstA.value_size;
		}
		debug_print(DEBUG_EXE, 1, "ZEXT dest length = %d %d\n", inst->value1.length, inst->value3.length);
		inst->value3.init_value_type = inst->value1.init_value_type;
		if (64 == inst->value3.length) {
			tmp32u = inst->value1.init_value;
			tmp64u = tmp32u;
		} else if (32 == inst->value3.length) {
			tmp16u = inst->value1.init_value;
			tmp32u = tmp16u;
			tmp64u = tmp32u;
		} else {
			debug_print(DEBUG_EXE, 1, "ZEXT length failure\n");
			return 1;
		}
		inst->value3.init_value = tmp64u;
		if (64 == inst->value3.length) {
			tmp32u = inst->value1.offset_value;
			tmp64u = tmp32u;
		} else if (32 == inst->value3.length) {
			tmp16u = inst->value1.offset_value;
			tmp32u = tmp16u;
			tmp64u = tmp32u;
		} else {
			debug_print(DEBUG_EXE, 1, "ZEXT length failure\n");
			return 1;
		}
		inst->value3.offset_value = tmp64u;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.relocated = inst->value1.relocated;
		inst->value3.relocated_section_id = inst->value1.relocated_section_id;
		inst->value3.relocated_section_index = inst->value1.relocated_section_index;
		inst->value3.relocated_index = inst->value1.relocated_index;
		inst->value3.section_id = inst->value1.section_id;
		inst->value3.section_index = inst->value1.section_index;

		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		/* FIXME Maybe Exception is the MOV instruction */
		inst->value3.value_scope = inst->value1.value_scope;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		if ((inst->value3.value_scope == 1) &&
			(STORE_REG == instruction->dstA.store) &&
			(1 == inst->value1.value_scope) &&
			(0 == instruction->dstA.indirect)) {
			inst->value3.value_scope = 2;
		}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value2 values */
		//inst->value3.value_id = inst->value2.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;

	case ADD:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "ADD\n");
		debug_print(DEBUG_EXE, 1, "ADD dest length = %d %d %d\n", inst->value1.length, inst->value2.length, inst->value3.length);
		/* If the instruction is a RIP + Relocated, turn it into a MOVABS. */
		debug_print(DEBUG_EXE, 1, "ADD 0x%x 0x%x 0x%x    0x%x 0x%x 0x%x\n",
				instruction->srcA.indirect == IND_DIRECT,
				instruction->srcA.store == STORE_REG,
				instruction->srcA.index == 0x48,
				instruction->srcB.indirect == IND_DIRECT,
				instruction->srcB.store == STORE_DIRECT,
				instruction->srcB.relocated);

		if ((instruction->srcA.indirect == IND_DIRECT) &&
				(instruction->srcA.store == STORE_REG) &&
				(instruction->srcA.index == 0x48) &&
				(instruction->srcB.indirect == IND_DIRECT) &&
				(instruction->srcB.store == STORE_DIRECT) &&
								(instruction->srcB.relocated)) {
/* Convert to a MOV instruction */
			instruction->opcode = MOV;
			instruction->srcA.store = instruction->srcB.store;
			instruction->srcA.relocated = instruction->srcB.relocated;
			instruction->srcA.relocated_section_id = instruction->srcB.relocated_section_id;
			instruction->srcA.relocated_section_index = instruction->srcB.relocated_section_index;
			instruction->srcA.relocated_external_function = instruction->srcB.relocated_external_function;
			instruction->srcA.relocated_index = instruction->srcB.relocated_index;
			instruction->srcA.indirect = instruction->srcB.indirect;
			instruction->srcA.indirect_size = instruction->srcB.indirect_size;
			instruction->srcA.index = instruction->srcB.index;
			instruction->srcA.value = instruction->srcB.value;
			instruction->srcA.value_size = instruction->srcB.value_size;

			inst->value1.start_address = inst->value2.start_address;
			inst->value1.length = inst->value2.length;
			inst->value1.relocated = inst->value2.relocated;
			inst->value1.relocated_section_id = inst->value2.relocated_section_id;
			inst->value1.relocated_section_index = inst->value2.relocated_section_index;
			inst->value1.relocated_index = inst->value2.relocated_index;
			inst->value1.section_id = inst->value2.section_id;
			inst->value1.section_index = inst->value2.section_index;
			inst->value1.init_value_type = inst->value2.init_value_type;
			inst->value1.init_value = inst->value2.init_value;
			inst->value1.offset_value = inst->value2.offset_value;
			inst->value1.value_type = inst->value2.value_type;
			inst->value1.ref_memory = inst->value2.ref_memory;
			inst->value1.ref_log = inst->value2.ref_log;
			inst->value1.value_scope = inst->value2.value_scope;
			inst->value1.value_id = 0;

			inst->value3.start_address = instruction->dstA.index;
			inst->value3.length = instruction->dstA.value_size;
			//inst->value3.length = inst->value1.length;
			inst->value3.relocated = inst->value2.relocated;
			inst->value3.relocated_section_id = inst->value2.relocated_section_id;
			inst->value3.relocated_section_index = inst->value2.relocated_section_index;
			inst->value3.relocated_index = inst->value2.relocated_index;
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;

			inst->value3.init_value_type = inst->value2.init_value_type;
			inst->value3.init_value = inst->value2.init_value;
			inst->value3.offset_value = inst->value2.offset_value;
			inst->value3.value_type = inst->value2.value_type;
			if (inst->instruction.dstA.indirect) {
				debug_print(DEBUG_EXE, 1, "ERROR: MOV set to dstA.indirect\n");
				exit(1);
			}
			inst->value3.ref_memory =
				inst->value2.ref_memory;
			inst->value3.ref_log =
				inst->value2.ref_log;
			/* Note: value_scope stays from the dst, not the src. */
			/* FIXME Maybe Exception is the MOV instruction */
			debug_print(DEBUG_EXE, 1, "ADD relocated EXE value_scope: 2 = 0x%x, 3 = 0x%x\n",
				inst->value2.value_scope, inst->value3.value_scope);
			inst->value3.value_scope = inst->value2.value_scope;
			/* MOV param to local */
			/* When the destination is a param_reg,
			 * Change it to a local_reg */
			if ((inst->value3.value_scope == 1) &&
				(STORE_REG == instruction->dstA.store) &&
				(1 == inst->value2.value_scope) &&
				(0 == instruction->dstA.indirect)) {
				inst->value3.value_scope = 2;
			}
			/* MOV imm to local */
			if ((inst->value3.value_scope == 0) &&
				(STORE_DIRECT == instruction->srcB.store) &&
				(0 == instruction->dstA.indirect)) {
				inst->value3.value_scope = 2;
			}
			if (inst->value3.value_scope == 0) {
				debug_print(DEBUG_EXE, 1, "ERROR: MOV value_scope == 0, BAD\n");
				exit(1);
			}
			/* Counter */
			//if (inst->value3.value_scope == 2) {
				/* Only value_id preserves the value2 values */
			//inst->value3.value_id = inst->value2.value_id;
			inst->value3.value_id = 0;
			inst->value2.value_id = 0;
			//}
			/* 1 - Entry Used */
			inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
					inst->value3.init_value,
					inst->value3.offset_value,
					inst->value3.init_value +
						inst->value3.offset_value);
			debug_print(DEBUG_EXE, 1, "pMOVvalue.relocated = 0x%lx\n", inst->value3.relocated);
			debug_print(DEBUG_EXE, 1, "pMOVvalue.relocated_section_id = 0x%lx\n", inst->value3.relocated_section_id);
			debug_print(DEBUG_EXE, 1, "pMOVvalue.relocated_section_index = 0x%lx\n", inst->value3.relocated_section_index);
			debug_print(DEBUG_EXE, 1, "pMOVvalue.relocated_index = 0x%lx\n", inst->value3.relocated_index);
			debug_print(DEBUG_EXE, 1, "pMOVvalue.section_id = 0x%lx\n", inst->value3.section_id);
			debug_print(DEBUG_EXE, 1, "pMOVvalue.section_index = 0x%lx\n", inst->value3.section_index);
		} else {
			if (inst->value1.section_id) {
				inst->value3.section_id = inst->value1.section_id;
				inst->value3.section_index = inst->value1.section_index;
			}
			if (inst->value2.section_id) {
				inst->value3.section_id = inst->value2.section_id;
				inst->value3.section_index = inst->value2.section_index;
			}
			inst->value3.start_address = instruction->dstA.index;
			inst->value3.length = instruction->dstA.value_size;
			//inst->value3.length = inst->value1.length;
			inst->value3.init_value_type = inst->value1.init_value_type;
			inst->value3.init_value = inst->value1.init_value;
			inst->value3.offset_value =
					inst->value1.offset_value + inst->value2.init_value;
			inst->value3.value_type = inst->value1.value_type;
			if (inst->instruction.dstA.indirect) {
				inst->value3.indirect_init_value =
						inst->value1.indirect_init_value;
				inst->value3.indirect_offset_value =
						inst->value1.indirect_offset_value;
				inst->value3.value_id =
						inst->value1.value_id;
			}
			inst->value3.ref_memory =
					inst->value1.ref_memory;
			inst->value3.ref_log =
					inst->value1.ref_log;
			inst->value3.value_scope = inst->value1.value_scope;
			if (inst->value3.value_scope == 0) {
				debug_print(DEBUG_EXE, 1, "ERROR: value_scope == 0, BAD\n");
				exit(1);
			}
			/* Counter */
			inst->value3.value_id = inst->value1.value_id;
			/* 1 - Entry Used */
			inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
					inst->value3.init_value,
					inst->value3.offset_value,
					inst->value3.init_value +
					inst->value3.offset_value);
		}
		put_value_RTL_instruction(self, process_state, inst);
#if 0
		if (instruction->srcA.relocated) {
			debug_print(DEBUG_EXE, 1, "ADD srcA relocated. exiting\n");
			exit(1);
		}
		if (instruction->srcB.relocated) {
			debug_print(DEBUG_EXE, 1, "ADD srcB relocated. exiting\n");
			exit(1);
		}
#endif
		break;
	case ADC:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "ADC\n");
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case MUL:  /* Unsigned mul */
	case IMUL: /* FIXME: Handled signed case */
		/* If the MUL is has an immediate value, it will be in srcA, so that type info from srcB */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of dstA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "MUL or IMUL\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		/* IF srcA is a IMM, use value2 types, else use value1 types. */
		if ((instruction->srcA.store == STORE_DIRECT) &&
			(instruction->srcA.indirect == IND_DIRECT)) {
			inst->value3.init_value_type = inst->value2.init_value_type;
			inst->value3.init_value = inst->value2.init_value;
			inst->value3.offset_value =
				((inst->value1.offset_value + inst->value1.init_value) 
				* (inst->value2.offset_value + inst->value2.init_value))
				 - inst->value1.init_value;
			inst->value3.value_type = inst->value2.value_type;
			inst->value3.ref_memory =
				inst->value2.ref_memory;
			inst->value3.ref_log =
				inst->value2.ref_log;
			inst->value3.value_scope = inst->value2.value_scope;
			/* Counter */
			inst->value3.value_id = inst->value2.value_id;
		} else {
			inst->value3.init_value_type = inst->value1.init_value_type;
			inst->value3.init_value = inst->value1.init_value;
			inst->value3.offset_value =
				((inst->value1.offset_value + inst->value1.init_value) 
				* (inst->value2.offset_value + inst->value2.init_value))
				 - inst->value1.init_value;
			inst->value3.value_type = inst->value1.value_type;
			inst->value3.ref_memory =
				inst->value1.ref_memory;
			inst->value3.ref_log =
				inst->value1.ref_log;
			inst->value3.value_scope = inst->value1.value_scope;
			/* Counter */
			inst->value3.value_id = inst->value1.value_id;
		}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SUB:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SUB\n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value -
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SBB:
		/* FIXME: Add support for the Carry bit */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SUB\n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value -
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case TEST:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "TEST \n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value2.init_value) &
			inst->value1.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		/* Fixme handle saving flags */
		//put_value_RTL_instruction(self, process_state, inst);
		break;
	case rAND:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "AND \n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) &
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case OR:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "OR \n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) |
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case XOR:
		/* If XOR against itself, this is a special case of making a dst value out of a src value,
		    but not really using the src value. 
		    So, the source value cannot be considered a PARAM
		    If tmp == 0, set scope to PARAM in get_value_RTL_intruction.
		    If tmp == 1, set scope to LOCAL in get_value_RTL_intruction.
		    TODO: Change output .c code from "local1 ^= local1;" to "local1 = 0;"
		 */
		tmp = source_equals_dest(&(instruction->srcA), &(instruction->srcB));
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), tmp); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "XOR\n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) ^
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case NEG:
		/* Get value of srcA */
		/* Could be replaced with a SUB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "NOT\n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = 0 - (inst->value1.offset_value +
			inst->value1.init_value);
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case NOT:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "NOT\n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = !(inst->value1.offset_value +
			inst->value1.init_value);
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SHL:
		/* This is an UNSIGNED operation */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SHL\n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) <<
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SHR:
		/* This is an UNSIGNED operation */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SHR\n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) >>
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SAL:
		/* This is an UNSIGNED operation */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SAL\n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		/* FIXME: This is currently doing unsigned SHL instead of SAL */
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) <<
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SAR:
		/* This is an UNSIGNED operation */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SAR\n");
		if (inst->value1.section_id) {
			inst->value3.section_id = inst->value1.section_id;
			inst->value3.section_index = inst->value1.section_index;
		}
		if (inst->value2.section_id) {
			inst->value3.section_id = inst->value2.section_id;
			inst->value3.section_index = inst->value2.section_index;
		}
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		/* FIXME: This is currently doing unsigned SHR instead of SAR */
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) >>
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case IF:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->dstA), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "IF\n");
		/* Create absolute JMP value in value3 */
		value = search_store(memory_reg,
				process_state->memory_reg_size,
				REG_IP,
				4);
		inst->value3.start_address = value->start_address;
		inst->value3.length = value->length;
		inst->value3.init_value_type = value->init_value_type;
		inst->value3.init_value = value->init_value;
		inst->value3.offset_value = value->offset_value +
			inst->value2.init_value;
		inst->value3.value_type = value->value_type;
		inst->value3.ref_memory =
			value->ref_memory;
		inst->value3.ref_log =
			value->ref_log;
		inst->value3.value_scope = value->value_scope;
		/* Counter */
		inst->value3.value_id = value->value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
		/* No put_RTL_value is done for an IF */
		break;
	case JMPT:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->dstA), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "JMPT\n");
		debug_print(DEBUG_EXE, 1, "JMPT dest length = %d %d %d\n", inst->value1.length, inst->value2.length, inst->value3.length);
		inst->value3.start_address = inst->value1.start_address;
		inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		/* FIXME Maybe Exception is the MOV instruction */
		inst->value3.value_scope = inst->value1.value_scope;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		if ((inst->value3.value_scope == 1) &&
			(STORE_REG == instruction->dstA.store) &&
			(1 == inst->value1.value_scope) &&
			(0 == instruction->dstA.indirect)) {
			inst->value3.value_scope = 2;
		}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value1 values */
		//inst->value3.value_id = inst->value1.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		// put_value_RTL_instruction(self, process_state, inst);
		break;
	case JMP:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of dstA */
		//ret = get_value_RTL_instruction(self,  &(instruction->dstA), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "JMP\n");
		/* Create absolute JMP value in value3 */
		value = search_store(memory_reg,
				process_state->memory_reg_size,
				REG_IP,
				4);
		debug_print(DEBUG_EXE, 1, "JMP 0x%"PRIx64"+%"PRId64"\n",
			value->offset_value, inst->value1.init_value);
		inst->value3.start_address = value->start_address;
		inst->value3.length = value->length;
		inst->value3.init_value_type = value->init_value_type;
		inst->value3.init_value = value->init_value;
		inst->value3.offset_value = value->offset_value +
			inst->value1.init_value;
		inst->value3.value_type = value->value_type;
		inst->value3.ref_memory =
			value->ref_memory;
		inst->value3.ref_log =
			value->ref_log;
		inst->value3.value_scope = value->value_scope;
		/* Counter */
		inst->value3.value_id = value->value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
		/* update EIP */
		value->offset_value = inst->value3.offset_value;
		break;
	case CALL:
		/* FIXME */
		/* On entry:
		 * srcA = relative offset which is value 1.
		 * srcB = ESP.
		 * dstA is destination EAX register which is value 2.
		 * with associated value1 and value2 
		 * On exit we have need:
		 * relative value coverted to ABS value.
		 * value1 = value1.  // Value 1 is useful for function pointer calls. 
		 * value2 = ESP
		 * value3 = value3
		 */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0);
		//ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1);
		//value = search_store(memory_reg,
		//		REG_IP,
		//		4);
		//debug_print(DEBUG_EXE, 1, "EXE CALL 0x%"PRIx64"+%"PRIx64"\n",
		//	value->offset_value, inst->value1.init_value);
		///* Make init_value +  offset_value = abs value */
		//inst->value1.offset_value = inst->value1.init_value;
		//inst->value1.init_value = value->offset_value;
		switch (instruction->srcA.relocated) {
			case 2:
				/* Do nothing for case 2, because we have already done this at decode time */
#if 0
				/* Link the call destination to a valid external_entry_point if possible */
				for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
					struct external_entry_point_s *external_entry_points = self->external_entry_points;
					if ((external_entry_points[n].valid != 0) &&
						(external_entry_points[n].type == 1) &&
						(external_entry_points[n].value == instruction->srcA.relocated_index)) {
							//debug_print(DEBUG_OUTPUT, 1, "found external relocated 0x%x\n", n);
							instruction->srcA.index = n;
							instruction->srcA.relocated = 1;
							break;
					}
				}
#endif
				break;
			case 0:
				/* Link the call destination to a valid external_entry_point if possible */
				if (instruction->srcA.indirect == IND_DIRECT) {
					debug_print(DEBUG_EXE, 1, "CALL: SCANNING eip = 0x%lx, init_value = 0x%lx, offset_value = 0x%lx\n",
						eip,
						inst->value1.init_value,
						inst->value1.offset_value);
					for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
						struct external_entry_point_s *external_entry_points = self->external_entry_points;
						uint64_t call_offset = eip + inst->value1.init_value + inst->value1.offset_value;
						if ((external_entry_points[n].valid != 0) &&
							(external_entry_points[n].type == 1) &&
							(external_entry_points[n].value == call_offset)) {
							debug_print(DEBUG_EXE, 1, "found call_offset entry_point = 0x%x\n", n);
							instruction->srcA.index = n;
							instruction->srcA.relocated = 1;
							print_inst(self, instruction, 0x80000000, NULL);
							break;
						}
						if ((external_entry_points[n].valid != 0) &&
							(external_entry_points[n].type == 2) &&
							(external_entry_points[n].value == call_offset)) {
							debug_print(DEBUG_EXE, 1, "found call_offset entry_point = 0x%x\n", n);
							instruction->srcA.index = n;
							instruction->srcA.relocated = 1;
							print_inst(self, instruction, 0x20000000, NULL);
							break;
						}
					}
				}
				break;
			case 3:
				debug_print(DEBUG_EXE, 1, "CALL:External: relocated = 0x%x\n", instruction->srcA.relocated);
				if (!inst->extension) {
					inst->extension = calloc(1, sizeof(struct extension_call_s));
				} else {
					debug_print(DEBUG_EXE, 1, "extension already allocated. Why? Exiting\n");
					exit(1);
				}
				call = inst->extension;
				tmp = input_external_function_get_size(self, instruction->srcA.relocated_external_function, &fields_size);
				if (tmp) {
					debug_print(DEBUG_EXE, 1, "external function not found. exiting\n");
					exit(1);
				}
				call->params_reg_size = fields_size;
				call->params_reg = calloc(fields_size, sizeof(int));
				for(n = 0; n < fields_size; n++) {
					call->params_reg[n] = self->external_function_reg_order[n];
				}
				debug_print(DEBUG_EXE, 1, "call->params_reg_size = %d\n", call->params_reg_size);
				debug_print(DEBUG_EXE, 1, "TODO Need to add support for param hints. Exiting\n");
				tmp = input_external_function_get_name(self, instruction->srcA.relocated_external_function, &function_name);
				debug_print(DEBUG_EXE, 1, "Function Name %p:%s\n", function_name, function_name);
				tmp = input_find_hints(self, function_name, &hint_size, &hint_array);
				debug_print(DEBUG_EXE, 1, "Hint size = 0x%x\n", hint_size);
				for (n = 0; n < hint_size; n++) {
					debug_print(DEBUG_EXE, 1, "Hint[%d] = 0x%x\n", n, hint_array[n]);
				}
				tmp = process_hints(self, process_state, call, hint_size, hint_array);
				debug_print(DEBUG_EXE, 1, "call->params_reg_size = %d\n", call->params_reg_size);

				break;
				/* FIXME: First expand printf format string to create a new specific printf
				 */
			default:
				debug_print(DEBUG_EXE, 1, "CALL:unknown: relocated = 0x%x\n", instruction->srcA.relocated);
				debug_print(DEBUG_EXE, 1, "Not implemented yet\n");
				exit(1);
				break;
		}
#if 1 
		/* FIXME: Currently this is a NOP. Need length to come from entry_point */
		/* Get value of dstA */
		inst->value3.start_address = instruction->dstA.index;
		/* FIXME: get length from entry_point */
		inst->value3.length = instruction->dstA.value_size;
		inst->value3.init_value_type = 0;
		inst->value3.init_value = 0;
		inst->value3.offset_value = 0;
		//inst->value3.value_type = inst->value1.value_type;
		inst->value3.value_type = 0;
		inst->value3.indirect_init_value = 0;
		inst->value3.indirect_offset_value = 0;
		inst->value3.ref_memory = 0;
		inst->value3.ref_log = 0;
		inst->value3.value_scope = 2;
		/* Counter */
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		/* 1 - Entry Used */
		inst->value1.valid = 1;
		inst->value3.valid = 1;
		put_value_RTL_instruction(self, process_state, inst);
#endif
		break;

	case CALLM:
		debug_print(DEBUG_OUTPUT, 1, "FIXME: CALLM not yet exe\n");
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
#if 1 
		/* FIXME: Currently this is a NOP. Need length to come from entry_point */
		/* Get value of dstA */
		inst->value3.start_address = instruction->dstA.index;
		/* FIXME: get length from entry_point */
		inst->value3.length = instruction->dstA.value_size;
		inst->value3.init_value_type = 0;
		inst->value3.init_value = 0;
		inst->value3.offset_value = 0;
		//inst->value3.value_type = inst->value1.value_type;
		inst->value3.value_type = 0;
		inst->value3.indirect_init_value = 0;
		inst->value3.indirect_offset_value = 0;
		inst->value3.ref_memory = 0;
		inst->value3.ref_log = 0;
		inst->value3.value_scope = 2;
		/* Counter */
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		/* 1 - Entry Used */
		inst->value1.valid = 1;
		inst->value3.valid = 1;
		put_value_RTL_instruction(self, process_state, inst);
#endif
		break;

	case TRUNC:
		/* Get value of srcA */
		//ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of dstA */
		//ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "TRUNC\n");
		//put_value_RTL_instruction(self, process_state, inst);
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Create result */
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		/* Special case for SEX instruction. */
		/* FIXME: Stored value in reg store should be size modified */
		value = search_store(process_state->memory_reg,
				process_state->memory_reg_size,
				instruction->dstA.index,
				instruction->dstA.value_size);
		if (value) {
			/* Only update it if is is found */
			value->length = instruction->dstA.value_size;
		}
		debug_print(DEBUG_EXE, 1, "TRUNC dest length = %d %d\n", inst->value1.length, inst->value3.length);
		inst->value3.init_value_type = inst->value1.init_value_type;
		if (64 == inst->value3.length) {
			tmp64u = inst->value1.init_value;
			tmp64u = tmp64u & 0xffffffffffffffff;
		} else if (32 == inst->value3.length) {
			tmp64u = inst->value1.init_value;
			tmp64u = tmp64u & 0xffffffff;
		} else {
			debug_print(DEBUG_EXE, 1, "TRUNC length failure\n");
			return 1;
		}
		inst->value3.init_value = tmp64u;
		if (64 == inst->value3.length) {
			tmp64u = inst->value1.offset_value;
			tmp64u = tmp64u & 0xffffffffffffffff;
		} else if (32 == inst->value3.length) {
			tmp64u = inst->value1.offset_value;
			tmp64u = tmp64u & 0xffffffff;
		} else {
			debug_print(DEBUG_EXE, 1, "TRUNC length failure\n");
			return 1;
		}
		inst->value3.offset_value = tmp64u;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		/* FIXME Maybe Exception is the MOV instruction */
		inst->value3.value_scope = inst->value1.value_scope;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		if ((inst->value3.value_scope == 1) &&
			(STORE_REG == instruction->dstA.store) &&
			(1 == inst->value1.value_scope) &&
			(0 == instruction->dstA.indirect)) {
			inst->value3.value_scope = 2;
		}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value2 values */
		//inst->value3.value_id = inst->value2.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;

	case BITCAST:
		debug_print(DEBUG_EXE, 1, "BITCAST\n");
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Create result */
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		/* FIXME: Stored value in reg store should be size modified */
		value = search_store(process_state->memory_reg,
				process_state->memory_reg_size,
				instruction->dstA.index,
				instruction->dstA.value_size);
		if (value) {
			/* Only update it if is is found */
			value->length = instruction->dstA.value_size;
		}
		debug_print(DEBUG_EXE, 1, "BITCAST dest length = %d %d\n", inst->value1.length, inst->value3.length);
		inst->value3.relocated = 0;
		inst->value3.relocated_section_id = 0;
		inst->value3.relocated_section_index = 0;
		inst->value3.section_id = inst->value1.section_id;
		inst->value3.section_index = inst->value1.section_index;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.value_id =
				inst->value1.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		/* FIXME Maybe Exception is the MOV instruction */
		inst->value3.value_scope = inst->value1.value_scope;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		if ((inst->value3.value_scope == 1) &&
			(STORE_REG == instruction->dstA.store) &&
			(1 == inst->value1.value_scope) &&
			(0 == instruction->dstA.indirect)) {
			inst->value3.value_scope = 2;
		}
		/* Counter */
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;

	default:
		debug_print(DEBUG_EXE, 1, "Unhandled EXE intruction 0x%x\n", instruction->opcode);
		ret = 1;
		break;
	}
	switch (instruction->opcode) {
	case NOP:
	case CMP:
		break;
	default: 
		if (inst->value3.value_scope == 0) {
			debug_print(DEBUG_EXE, 1, "ERROR: value_scope == 0, BAD\n");
			exit(1);
		}
		break;
	}
	return ret;
}

