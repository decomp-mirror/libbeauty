/* Test creation of a .bc file for LLVM IR*/

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <global_struct.h>

#include <input.h>
#include <output.h>
#include <debug_llvm.h>

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>

#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/MathExtras.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Bitcode/BitcodeWriter.h>



#define STORE_DIRECT 0

using namespace llvm;


static cl::opt<bool>
	DebugPM("debug-pass-manager", cl::Hidden,
		cl::desc("Print pass management debugging information"));

struct declaration_s {
	std::vector<Type*>FuncTy_0_args;
	FunctionType *FT;
	Function *F;
	IRBuilder<> *builder;
};

		CmpInst::Predicate predicate_to_llvm_table[] =  {
			ICmpInst::FCMP_FALSE,  /// None
			ICmpInst::FCMP_FALSE,  /// FLAG_OVERFLOW
			ICmpInst::FCMP_FALSE,  /// FLAG_NOT_OVERFLOW
			ICmpInst::ICMP_ULT,  ///< unsigned less than. FLAG_BELOW
			ICmpInst::ICMP_UGE,  ///< unsigned greater or equal. FLAG_NOT_BELOW
			ICmpInst::ICMP_EQ,  ///< equal. FLAG_EQUAL
			ICmpInst::ICMP_NE,  ///< not equal. FLAG_NOT_EQUAL
			ICmpInst::ICMP_ULE,  ///< unsigned less or equal. FLAG_BELOW_EQUAL
			ICmpInst::ICMP_UGT,  ///< unsigned greater than. FLAG_ABOVE
			ICmpInst::FCMP_FALSE, /// FLAG_SIGNED
			ICmpInst::FCMP_FALSE, /// FLAG_NOT_SIGNED
			ICmpInst::FCMP_FALSE, /// FLAG_PARITY
			ICmpInst::FCMP_FALSE, /// FLAG_NOT_PARITY
			ICmpInst::ICMP_SLT,  ///< signed less than
			ICmpInst::ICMP_SGE,  ///< signed greater or equal
			ICmpInst::ICMP_SLE,  ///< signed less or equal
			ICmpInst::ICMP_SGT,  ///< signed greater than. 
		};

class LLVM_ir_export
{
	public:
		int find_function_member_node(struct self_s *self, struct external_entry_point_s *external_entry_point, int node_to_find, int *member_node);
		int add_instruction(struct self_s *self, Module *mod, struct declaration_s *declaration, Value **value, BasicBlock **bb, int node, int external_entry, int inst);
		int add_node_instructions(struct self_s *self, Module *mod, struct declaration_s *declaration, Value **value, BasicBlock **bb, int node, int external_entry);
		int fill_value(struct self_s *self, Value **value, int value_id, int external_entry);
		int output(struct self_s *self);


	private:
		LLVMContext Context;
};

int LLVM_ir_export::find_function_member_node(struct self_s *self, struct external_entry_point_s *external_entry_point, int node_to_find, int *member_node)
{
	int found = 1;
	int n;

	*member_node = 0;
	for (n = 0; n < external_entry_point->member_nodes_size; n++) {
		if (node_to_find == external_entry_point->member_nodes[n]) {
			found = 0;
			*member_node = n;
			break;
		}
	}
	return found;
}

int sprint_value(raw_string_ostream &OS1, Value *valueA)
{
	valueA->print(OS1);
	OS1 << "\n";
	OS1.flush();
	return 0;
}

int sprint_srcA_srcB(raw_string_ostream &OS1, Value *srcA, Value *srcB)
{
	if (!srcA) {
		debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: srcA NULL\n");
		exit(1);
	}
	if (!srcB) {
		debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: srcB NULL\n");
		exit(1);
	}
	OS1 << "srcA: ";
	srcA->print(OS1);
	OS1 << "\n";
	OS1 << "srcB: ";
	srcB->print(OS1);
	OS1 << "\n";
	OS1 << "srcA_type = ";
	srcA->getType()->print(OS1);
	OS1 << "\n";
	OS1 << "srcB_type = ";
	srcB->getType()->print(OS1);
	OS1.flush();
	return 0;
}

int check_domain(struct label_redirect_s *label_redirect)
{
	if (label_redirect->domain != 1) {
		debug_print(DEBUG_OUTPUT_LLVM, 1, "Check Domain failed. %lu\n", label_redirect->domain);
		assert(0);
		exit(1);
	}
	return 0;
}

Type *import_alien_type(struct self_s *self, Module *mod, Type *type_alien) {

	Type * ReturnTy;
	if (type_alien->isIntegerTy()) {
		ReturnTy = IntegerType::get(mod->getContext(), type_alien->getScalarSizeInBits());
		return ReturnTy;
	} else if (type_alien->isPointerTy()) {
		Type * type_alien2 = type_alien->getPointerElementType();
		if (type_alien2->isIntegerTy()) {
				ReturnTy = PointerType::get(
						IntegerType::get(mod->getContext(),
								type_alien2->getScalarSizeInBits()),
						0); // Address space zero
				llvm::outs() << *type_alien << "\n";
				llvm::outs() << *type_alien2 << "\n";
				llvm::outs() << *ReturnTy << "\n";
				return ReturnTy;
		}
//				ReturnTy = IntegerType::get(mod->getContext(), type_alien->getScalarSizeInBits());
		debug_print(DEBUG_OUTPUT_LLVM, 1, "Return/Param pointer type not handled yet\n");
		llvm::outs() << *type_alien << "\n";
		llvm::outs() << type_alien2->isAggregateType() << " - Aggregate\n";
		llvm::outs() << type_alien2->isArrayTy() << " - Array\n";
		llvm::outs() << type_alien2->isDoubleTy() << " - Double\n";
		llvm::outs() << type_alien2->isFloatTy() << " - Float\n";
		llvm::outs() << type_alien2->isIntegerTy() << " - Integer\n";
		llvm::outs() << type_alien2->isFunctionTy() << " - Function\n";
		llvm::outs() << type_alien2->isFunctionTy() << " - Function\n";
		llvm::outs() << type_alien2->isPointerTy() << " - Pointer\n";
		llvm::outs() << type_alien2->isStructTy() << " - Struct\n";
		llvm::outs() << type_alien2->isVectorTy() << " - Vector\n";
		llvm::outs() << type_alien2->isVoidTy() << " - Void\n";

		exit(1);
	} else {
		debug_print(DEBUG_OUTPUT_LLVM, 1, "Return/Param type not handled yet\n");
		llvm::outs() << *type_alien << "\n";
		llvm::outs() << type_alien->isAggregateType() << " - Aggregate\n";
		llvm::outs() << type_alien->isArrayTy() << " - Array\n";
		llvm::outs() << type_alien->isDoubleTy() << " - Double\n";
		llvm::outs() << type_alien->isFloatTy() << " - Float\n";
		llvm::outs() << type_alien->isIntegerTy() << " - Integer\n";
		llvm::outs() << type_alien->isFunctionTy() << " - Function\n";
		llvm::outs() << type_alien->isFunctionTy() << " - Function\n";
		llvm::outs() << type_alien->isPointerTy() << " - Pointer\n";
		llvm::outs() << type_alien->isStructTy() << " - Struct\n";
		llvm::outs() << type_alien->isVectorTy() << " - Vector\n";
		llvm::outs() << type_alien->isVoidTy() << " - Void\n";

		exit(1);
	}
	return ReturnTy;
}



int LLVM_ir_export::add_instruction(struct self_s *self, Module *mod, struct declaration_s *declaration, Value **value, BasicBlock **bb, int node, int external_entry, int inst)
{
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct inst_log_entry_s *inst_log1 = &inst_log_entry[inst];
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[external_entry]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;;
	Value *srcA;
	Value *srcB;
	Value *dstA;
	Value *value_tmp;
	uint64_t size_bits;
	uint64_t srcA_size;
	uint64_t srcB_size;
	uint64_t lab_pointer;
	int value_id;
	int value_id_dst;
	struct label_s *label;
	int param_stack = 0;
	int tmp;
	char buffer[1024];
	int node_true;
	int node_false;
	int result = 0;
	int n;
	std::string Buf1;
	raw_string_ostream OS1(Buf1);

	IRBuilder<> *builder = declaration[external_entry].builder;
	builder->SetInsertPoint(bb[node]);

	switch (inst_log1->instruction.opcode) {
	case 1:  // MOV
		/* 2 forms, 1) MOV REG,REG and 2) MOV IMM,REG
		 * (1) is a NOP in LLVM IR, (2) is a fill value but no OP.
		 */
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:MOV\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx, value_id3 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value3.value_id,
			external_entry_point->label_redirect[inst_log1->value3.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value3.value_id].index);
		if (inst_log1->instruction.srcA.store == 0) {  /* IMM */
			tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
			value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
			if (!value[value_id]) {
				tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
				if (tmp) {
					debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. dstA value_id = 0x%x\n", value_id);
					exit(1);
				}
			}
			sprint_value(OS1, value[value_id]);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
			Buf1.clear();
		}
		break;
	case 2:  // ADD
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:ADD\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx, value_id2 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value2.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value2.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcB = value[value_id];

		debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA = %p, srcB = %p\n", srcA, srcB);
		sprint_srcA_srcB(OS1, srcA, srcB);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();

		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		dstA = builder->CreateAdd(srcA, srcB, buffer);
		value[inst_log1->value3.value_id] = dstA;
		sprint_value(OS1, dstA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		break;
	case 4:  // SUB
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:SUB\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx, value_id2 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value2.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		if (external_entry_point->labels[value_id].tip2) {
			size_bits = external_entry_point->tip2[external_entry_point->labels[value_id].tip2].integer_size;
		} else {
			size_bits = 8;
		}
		srcA_size = size_bits;
		debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA: scope=0x%lx, type=0x%lx value=0x%lx size_bits=0x%lx lab_pointer=0x%lx name=%s\n",
			external_entry_point->labels[value_id].scope,
			external_entry_point->labels[value_id].type,
			external_entry_point->labels[value_id].value,
			external_entry_point->tip2[external_entry_point->labels[value_id].tip2].integer_size,
			external_entry_point->tip2[external_entry_point->labels[value_id].tip2].pointer,
			external_entry_point->labels[value_id].name);

		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value2.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcB = value[value_id];
		if (external_entry_point->labels[value_id].tip2) {
			size_bits = external_entry_point->tip2[external_entry_point->labels[value_id].tip2].integer_size;
		} else {
			size_bits = 8;
		}
		srcB_size = size_bits;
		debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA: scope=0x%lx, type=0x%lx value=0x%lx size_bits=0x%lx lab_pointer=0x%lx name=%s\n",
			external_entry_point->labels[value_id].scope,
			external_entry_point->labels[value_id].type,
			external_entry_point->labels[value_id].value,
			external_entry_point->tip2[external_entry_point->labels[value_id].tip2].integer_size,
			external_entry_point->tip2[external_entry_point->labels[value_id].tip2].pointer,
			external_entry_point->labels[value_id].name);

		debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA = %p, srcB = %p\n", srcA, srcB);

		sprint_srcA_srcB(OS1, srcA, srcB);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();

		debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA_size = 0x%lx, srcB_size = 0x%lx\n", srcA_size, srcB_size);
		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		dstA = builder->CreateSub(srcA, srcB, buffer);
		value[inst_log1->value3.value_id] = dstA;
		sprint_value(OS1, dstA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		break;
	case 7:  // XOR
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:XOR\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx, value_id2 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value2.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value2.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcB = value[value_id];

		debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA = %p, srcB = %p\n", srcA, srcB);
		sprint_srcA_srcB(OS1, srcA, srcB);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();

		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		dstA = builder->CreateXor(srcA, srcB, buffer);
		value[inst_log1->value3.value_id] = dstA;
		sprint_value(OS1, dstA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		break;
	case 0xd:  // MUL
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:MUL\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx, value_id2 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value2.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value2.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcB = value[value_id];
		debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA = %p, srcB = %p\n", srcA, srcB);

		sprint_srcA_srcB(OS1, srcA, srcB);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();

		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		dstA = builder->CreateMul(srcA, srcB, buffer);
		value[inst_log1->value3.value_id] = dstA;
		sprint_value(OS1, dstA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		break;
	case 0xe:  // IMUL
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:IMUL\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx, value_id2 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value2.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value2.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcB = value[value_id];
		debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA = %p, srcB = %p\n", srcA, srcB);

		sprint_srcA_srcB(OS1, srcA, srcB);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();

		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		// FIXME: Get IMUL different from MUL
		dstA = builder->CreateMul(srcA, srcB, buffer);
		value[inst_log1->value3.value_id] = dstA;
		sprint_value(OS1, dstA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		break;
	case 0x11:  // JMP
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:JMP node_end = 0x%x\n", inst, inst_log1->instruction.opcode, inst_log1->node_end);
		if (inst_log1->node_end) {
			node_true = nodes[node].link_next[0].node;
			//dstA = BranchInst::Create(bb[node_true], bb[node]);
			dstA = builder->CreateBr(bb[node_true]);
			sprint_value(OS1, dstA);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
			Buf1.clear();
			result = 1;
		}
		break;
	case 0x12:  // CALL
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:CALL\n", inst, inst_log1->instruction.opcode);
		switch (inst_log1->instruction.srcA.relocated) {
		case 1:
		case 2: {
			struct extension_call_s *call_info = static_cast<struct extension_call_s *> (inst_log1->extension);
			std::vector<Value*> vector_params;
			int function_to_call = 0;
			function_to_call = inst_log1->instruction.srcA.index;

			debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: params_size = 0x%x:0x%x\n", inst, call_info->params_reg_size, declaration[function_to_call].FT->getNumParams());
			for (n = 0; n < call_info->params_reg_size; n++) {
				tmp = check_domain(&(external_entry_point->label_redirect[call_info->params_reg[n]]));
				value_id = external_entry_point->label_redirect[call_info->params_reg[n]].index;
				debug_print(DEBUG_OUTPUT_LLVM, 1, "call_info_params = 0x%x->0x%x, %p\n", call_info->params_reg[n], value_id, value[value_id]);
				if (!value_id) {
					debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: invalid call_info_param\n");
					exit(1);
				}
				vector_params.push_back(value[value_id]);
			}
			PointerType* PointerTy_1 = PointerType::get(IntegerType::get(mod->getContext(), 8), 0);
			ConstantPointerNull* const_ptr_5 = ConstantPointerNull::get(PointerTy_1);
			vector_params.push_back(const_ptr_5); /* EIP */
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: args_size = 0x%lx\n", inst, vector_params.size());
			tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "AX = 0x%lx:0x%lx %s\n",
						inst_log1->value3.value_id,
						external_entry_point->label_redirect[inst_log1->value3.value_id].index,
						buffer);
			declaration[function_to_call].F->print(OS1);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
			Buf1.clear();
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: declaration dump done.\n", inst);
			for(auto i : vector_params) {
				debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: dumping vector_params %p\n", inst, i);
				if (i) {
					i->print(OS1);
					debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
					Buf1.clear();
				}
			}
			CallInst* call_inst = builder->CreateCall(declaration[function_to_call].F, vector_params, buffer);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: call_inst %p\n", inst, call_inst);

			call_inst->setCallingConv(CallingConv::C);
			call_inst->setTailCall(false);
			dstA = call_inst;
			value[inst_log1->value3.value_id] = dstA;
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: dstA %p\n", inst, dstA);
			dstA->getType()->print(OS1);
			sprint_value(OS1, dstA);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
			Buf1.clear();
			//debug_print(DEBUG_OUTPUT_LLVM, 1, "exit(1)\n");
			//exit(1);
			break;
			}
		case 3: { // For external call()
			int function = inst_log1->instruction.srcA.relocated_external_function;
			LLVM_input_header *input_header = (LLVM_input_header*)self->input_header;
			char *function_name;

			struct extension_call_s *call_info = static_cast<struct extension_call_s *> (inst_log1->extension);
			std::vector<Value*> vector_params;
			for (n = 0; n < call_info->params_reg_size; n++) {
				//int reg_value = call_info->reg_tracker[call_info->params_reg[n]]; 
				//value_id = external_entry_point->label_redirect[reg_value].index;
				tmp = check_domain(&(external_entry_point->label_redirect[call_info->params_reg[n]]));
				value_id = external_entry_point->label_redirect[call_info->params_reg[n]].index;
				debug_print(DEBUG_OUTPUT_LLVM, 1, "call_info_params = 0x%x->0x%x, %p\n", call_info->params_reg[n], value_id, value[value_id]);
				if (!value_id) {
					debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: invalid call_info_param\n");
					exit(1);
				} else {
					outs() << *value[value_id] << " - value_id\n";
				}
				vector_params.push_back(value[value_id]);
			}
			/* Import the function declaration from an alien module */
			auto CalleeTy_alien = input_header->get_function_type(function);
			auto ReturnTy_alien = CalleeTy_alien->getReturnType();
			Type *ReturnTy = import_alien_type(self, mod, ReturnTy_alien);

			std::vector<Type*>FuncTy_puts_args;
			int number_of_params = CalleeTy_alien->getFunctionNumParams();
			for (n = 0; n < number_of_params; n++) {
				Type *param_alien = CalleeTy_alien->getFunctionParamType(n);
				Type *param = import_alien_type(self, mod, param_alien);
				FuncTy_puts_args.push_back(param);
			}
			auto CalleeTy = FunctionType::get(
					ReturnTy,
					FuncTy_puts_args,
					CalleeTy_alien->isVarArg());

			StringRef name = input_header->get_function_name(self, function);
			function_name = strndup(name.data(), 1024);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "function_name = %p:%s\n", function_name, function_name);
			llvm::outs() << function_name << " - function_name\n";

			auto Callee =
				Function::Create(CalleeTy, Function::ExternalLinkage, function_name, mod);

			llvm::outs() << *Callee << " - Callee\n";
			llvm::outs() << &(*Callee->getParent()) << " - Callee-parent\n";
			llvm::outs() << mod << " - mod\n";

			tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "AX = 0x%lx:0x%lx %s\n",
						inst_log1->value3.value_id,
						external_entry_point->label_redirect[inst_log1->value3.value_id].index,
						buffer);

			CallInst* call_inst = builder->CreateCall(Callee, vector_params, buffer);
			call_inst->setCallingConv(CallingConv::C);
			call_inst->setTailCall(false);
			dstA = call_inst;
			value[inst_log1->value3.value_id] = dstA;
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: dstA %p\n", inst, dstA);
			sprint_value(OS1, dstA);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
			Buf1.clear();
			//debug_print(DEBUG_OUTPUT_LLVM, 1, "Relocated 3 Not yet handled\n");
			//exit(1);
			break;
			}
		default: {
			debug_print(DEBUG_OUTPUT_LLVM, 1, "Relocated %d Not yet handled\n", inst_log1->instruction.srcA.relocated);
			exit(1);
			break;
			}
		}
		break;
	case 0x1e:  // RET
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:RET\n", inst, inst_log1->instruction.opcode);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL\n");
				result = 2;
				exit(1);
				break;
			}
		}
		srcA = value[value_id];
		sprint_value(OS1, srcA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();
		dstA = builder->CreateRet(srcA);
		sprint_value(OS1, dstA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		result = 1;
		break;
	case 0x1f:  // SEX
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:SEX\n", inst, inst_log1->instruction.opcode);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx, value_id3 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value3.value_id,
			external_entry_point->label_redirect[inst_log1->value3.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value3.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		sprint_value(OS1, srcA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value3.value_id]));
		value_id_dst = external_entry_point->label_redirect[inst_log1->value3.value_id].index;
		label = &external_entry_point->labels[value_id_dst];
		tmp = label_to_string(label, buffer, 1023);
		if (external_entry_point->labels[value_id_dst].tip2) {
			size_bits = external_entry_point->tip2[external_entry_point->labels[value_id_dst].tip2].integer_size;
		} else {
			size_bits = 0;
		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "label->tip2: size_bits = 0x%lx\n", size_bits);
		dstA = builder->CreateSExt(srcA, IntegerType::get(mod->getContext(), size_bits), buffer);
		value[value_id_dst] = dstA;
		sprint_value(OS1, dstA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		break;
	case 0x23:  // ICMP
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:ICMP\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "ICMP predicate = 0x%x\n", inst_log1->instruction.predicate);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx, value_id2 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value2.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				tmp = label_to_string(&external_entry_point->labels[value_id], buffer, 1023);
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x:%s\n", value_id, buffer);
				exit(1);
			}
		}
		srcA = value[value_id];
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value2.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				tmp = label_to_string(&external_entry_point->labels[value_id], buffer, 1023);
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcB value_id = 0x%x:%s\n", value_id, buffer);
				exit(1);
			}
		}
		srcB = value[value_id];

		debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA = %p, srcB = %p\n", srcA, srcB);
		sprint_srcA_srcB(OS1, srcA, srcB);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();

		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		dstA = builder->CreateICmp(predicate_to_llvm_table[inst_log1->instruction.predicate], srcA, srcB, buffer);
		value[inst_log1->value3.value_id] = dstA;
		sprint_value(OS1, dstA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		break;
	case 0x24:  // BRANCH
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:BRANCH\n", inst, inst_log1->instruction.opcode);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				tmp = label_to_string(&external_entry_point->labels[value_id], buffer, 1023);
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x:%s\n", value_id, buffer);
				exit(1);
			}
		}
		srcA = value[value_id];
		sprint_value(OS1, srcA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();
		//BranchInst::Create(label_7, label_9, int1_11, label_6);
		node_true = nodes[node].link_next[0].node;
		node_false = nodes[node].link_next[1].node;
		dstA = builder->CreateCondBr(srcA, bb[node_true], bb[node_false]);
		sprint_value(OS1, dstA);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		result = 1;
		break;
	case 0x25:  // LOAD
		LoadInst* dstA_load;
		param_stack = 0;
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:LOAD\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		switch (inst_log1->instruction.srcA.indirect) {
		case 1:  // Memory
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LOAD Memory: value_id1 = 0x%lx->0x%lx:0x%lx, value_id2 = 0x%lx->0x%lx:0x%lx value_id3 = 0x%lx->0x%lx:0x%lx\n",
				inst_log1->value1.value_id,
				external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
				external_entry_point->label_redirect[inst_log1->value1.value_id].index,
				inst_log1->value2.value_id,
				external_entry_point->label_redirect[inst_log1->value2.value_id].domain,
				external_entry_point->label_redirect[inst_log1->value2.value_id].index,
				inst_log1->value3.value_id,
				external_entry_point->label_redirect[inst_log1->value3.value_id].domain,
				external_entry_point->label_redirect[inst_log1->value3.value_id].index);
			/*
			value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
			if (!value[value_id]) {
				tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
				if (tmp) {
					debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
					exit(1);
				}
			}
			srcA = value[value_id];
			*/
			tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value2.value_id]));
			value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].index;
			if (!value[value_id]) {
				debug_print(DEBUG_OUTPUT_LLVM, 1, "fill_value: value_id = 0x%x\n", value_id);
				tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
				if (tmp) {
					debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
					exit(1);
				}
			}
			srcB = value[value_id];

			srcB->print(OS1);
			OS1.flush();
			debug_print(DEBUG_OUTPUT_LLVM, 1, "srcB: %s\n", Buf1.c_str());
			Buf1.clear();
			/*
			debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA = %p, srcB = %p\n", srcA, srcB);
			sprint_srcA_srcB(OS1, srcA, srcB);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
			Buf1.clear();
			*/

			tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value3.value_id]));
			value_id_dst = external_entry_point->label_redirect[inst_log1->value3.value_id].index;
			label = &external_entry_point->labels[value_id_dst];
			tmp = label_to_string(label, buffer, 1023);
			if (external_entry_point->labels[value_id_dst].tip2) {
				size_bits = external_entry_point->tip2[external_entry_point->labels[value_id_dst].tip2].integer_size;
			} else {
				size_bits = 8;
			}
			debug_print(DEBUG_OUTPUT_LLVM, 1, "CreateLoad: size_bits = 0x%lx 0x%lx\n", size_bits, size_bits >> 3);
			dstA = builder->CreateAlignedLoad(srcB, size_bits >> 3, buffer);
			//dstA_load = new LoadInst(srcA, buffer, false, bb[node]);
			//dstA_load->setAlignment(label->size_bits >> 3);
			//dstA = dstA_load;

			dstA->print(OS1);
			OS1.flush();
			debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
			Buf1.clear();

			if (value_id_dst) {
				value[value_id_dst] = dstA;
			} else {
				debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: FIXME: Invalid value_id\n", inst);
			}
			break;
		case 2:  // Stack
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LOAD Stack: value_id1 = 0x%lx->0x%lx:0x%lx, value_id2 = 0x%lx->0x%lx:0x%lx value_id3 = 0x%lx->0x%lx:0x%lx\n",
				inst_log1->value1.value_id,
				external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
				external_entry_point->label_redirect[inst_log1->value1.value_id].index,
				inst_log1->value2.value_id,
				external_entry_point->label_redirect[inst_log1->value2.value_id].domain,
				external_entry_point->label_redirect[inst_log1->value2.value_id].index,
				inst_log1->value3.value_id,
				external_entry_point->label_redirect[inst_log1->value3.value_id].domain,
				external_entry_point->label_redirect[inst_log1->value3.value_id].index);

			tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
			value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
			if (!value[value_id]) {
				tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
				if (tmp) {
					debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
					exit(1);
				}
			}
			srcA = value[value_id];
			label = &(external_entry_point->labels[value_id]);
			if ((2 == label->scope) &&
				(2 == label->type)) {
				param_stack = 1;
			}

			tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value2.value_id]));
			value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].index;
			if (!value[value_id]) {
				tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
				if (tmp) {
					debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
					exit(1);
				}
			}
			srcB = value[value_id];

			debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA = %p, srcB = %p\n", srcA, srcB);
			sprint_srcA_srcB(OS1, srcA, srcB);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "SRC:\n%s\n", Buf1.c_str());
			Buf1.clear();

			tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value3.value_id]));
			value_id_dst = external_entry_point->label_redirect[inst_log1->value3.value_id].index;
			label = &external_entry_point->labels[value_id_dst];
			tmp = label_to_string(label, buffer, 1023);
			if (external_entry_point->labels[value_id_dst].tip2) {
				size_bits = external_entry_point->tip2[external_entry_point->labels[value_id_dst].tip2].integer_size;
			} else {
				size_bits = 8;
			}
			debug_print(DEBUG_OUTPUT_LLVM, 1, "DST: size_bits = 0x%lx\n", size_bits);

			if (param_stack) {
				// FIXME: is srcA is a param_stack... make this a NOP 
				dstA = srcA;
			} else {
				dstA = builder->CreateAlignedLoad(srcA, size_bits >> 3, buffer);
			}

			dstA->print(OS1);
			OS1.flush();
			debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
			Buf1.clear();

			if (value_id_dst) {
				value[value_id_dst] = dstA;
			} else {
				debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: FIXME: Invalid value_id\n", inst);
			}
			break;
		default:
			debug_print(DEBUG_OUTPUT_LLVM, 1, "FIXME: LOAD Indirect = 0x%x not yet handled\n", inst_log1->instruction.srcA.indirect);
			break;
		}
		break;
	case 0x26:  // STORE
		{
		Value* srcB_store;
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:STORE\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "STORE: value_id1 = 0x%lx->0x%lx:0x%lx, value_id2 = 0x%lx->0x%lx:0x%lx value_id3 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value2.value_id].index,
			inst_log1->value3.value_id,
			external_entry_point->label_redirect[inst_log1->value3.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value3.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (value_id) {
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: srcA value_id 0x%x\n", inst, value_id);
			if (!value[value_id]) {
				tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
				if (tmp) {
					debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
					exit(1);
				}
			}
			srcA = value[value_id];
		} else {
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: FIXME: Invalid srcA value_id\n", inst);
			break;
		}
		/* Note: The srcB here should be value3 as it is a STORE instruction */
		/*       But it depends on whether the value3 is a constant or a calculated pointer */
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value3.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value3.value_id].index;
		if (value_id) {
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: dstA value_id 0x%x\n", inst, value_id);
			if (!value[value_id]) {
				tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
				if (tmp) {
					debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. dstA value_id = 0x%x\n", value_id);
					exit(1);
				}
			}
			srcB = value[value_id];
		} else {
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: FIXME: Invalid dstA value_id\n", inst);
			break;
		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA = %p, dstA = %p\n", srcA, srcB);
		sprint_srcA_srcB(OS1, srcA, srcB);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();
		Type* srcA_type = srcA->getType();
		Type* srcB_type = srcB->getType();
		uint32_t srcA_width = 99;
		uint32_t srcB_width = 99;
		if (srcA_type->isIntegerTy()) {
			srcA_width = cast<IntegerType>(srcA_type)->getBitWidth();
		}
		if (srcA_type->isPointerTy()) {
			PointerType *PTy = cast<PointerType>(srcA_type);
			Type *Type1 = PTy->getElementType();
			if (Type1->isIntegerTy()) {
				srcA_width = cast<IntegerType>(Type1)->getBitWidth();
			}
		}
		if (srcB_type->isIntegerTy()) {
			srcB_width = cast<IntegerType>(srcB_type)->getBitWidth();
		}
		if (srcB_type->isPointerTy()) {
			PointerType *PTy = cast<PointerType>(srcB_type);
			Type *Type1 = PTy->getElementType();
			if (Type1->isIntegerTy()) {
				srcB_width = cast<IntegerType>(Type1)->getBitWidth();
			} else if (Type1->isPointerTy()) {
				PointerType *PTy = cast<PointerType>(srcB_type);
				Type *Type1 = PTy->getElementType();
				if (Type1->isIntegerTy()) {
					srcB_width = cast<IntegerType>(Type1)->getBitWidth();
				}
			}
		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: srcA_width = %d, srcB_width = %d\n", inst, srcA_width, srcB_width);
		//srcA_type->dump();
		srcA_type->print(llvm::errs());
		//srcB_type->dump();
		srcB_type->print(llvm::errs());
		//std::cout << srcB->getName());
		// If they are == a normal store will not work.
		if ((srcA_type != srcB_type) &&
			(srcA_type->isPointerTy()) &&
			(srcB_type->isPointerTy())) {
			PointerType *srcB_ptr = PointerType::get(srcA_type, 0);
			srcB_store = builder->CreateBitCast(srcB, srcB_ptr);
		} else {
			srcB_store = srcB;
		}

		// FIXME: JCD: Need to cast the stored to be the type of the srcA
		//dstA = new StoreInst(srcA, srcB, false, bb[node]);
		dstA = builder->CreateStore(srcA, srcB_store);
		OS1 << "dstA: ";
		dstA->print(OS1);
		OS1 << "\n";
		OS1.flush();
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		}
		break;
	case 0x2F:  // GEP1
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:GEP1\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "GEP: value_id1 = 0x%lx->0x%lx:0x%lx, value_id2 = 0x%lx->0x%lx:0x%lx value_id3 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value2.value_id].index,
			inst_log1->value3.value_id,
			external_entry_point->label_redirect[inst_log1->value3.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value3.value_id].index);
// Constant Definitions
//  ConstantInt* const_int64_1 = ConstantInt::get(C, APInt(64, StringRef("10"), 10));
//  // PointerType* const_ptr_int64_1 = PointerType::get(ConstantInt::get(C, APInt(64, StringRef("10"), 10)));
//   Value* const_ptr_int64_1 = ConstantExpr::getIntToPtr(
//                        const_int64_1 , PointerTy_1);
//
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			debug_print(DEBUG_OUTPUT_LLVM, 1, "fill_value: value_id = 0x%x\n", value_id);
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];

		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value2.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].index;
		if (!value[value_id]) {
			debug_print(DEBUG_OUTPUT_LLVM, 1, "fill_value: value_id = 0x%x\n", value_id);
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcB = value[value_id];

		label = &external_entry_point->labels[value_id];
		if (external_entry_point->labels[value_id].tip2) {
			lab_pointer = external_entry_point->tip2[external_entry_point->labels[value_id].tip2].pointer;
		} else {
			lab_pointer = 0;
		}
		if (lab_pointer) {
			/* Swap srcA and srcB */
			debug_print(DEBUG_OUTPUT_LLVM, 1, "GEP swap srcA and srcB\n");
			value_tmp = srcA;
			srcA = srcB;
			srcB = value_tmp;
		}

		debug_print(DEBUG_OUTPUT_LLVM, 1, "srcA = %p, srcB = %p\n", srcA, srcB);
		sprint_srcA_srcB(OS1, srcA, srcB);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();
		debug_print(DEBUG_OUTPUT_LLVM, 1, "isConstant() srcA = 0x%x, srcB = 0x%x\n", srcA->getType()->getTypeID(), srcB->getType()->getTypeID());
		{
			int srcA_type = srcA->getType()->getTypeID();
			int srcB_type = srcB->getType()->getTypeID();
			if ((Type::TypeID::IntegerTyID == srcA_type) && (Type::TypeID::PointerTyID == srcB_type)) {
				/* Swap srcA and srcB */
				Value *tmp_src = srcA;
				srcA = srcB;
				srcB = tmp_src;
				sprint_srcA_srcB(OS1, srcA, srcB);
				debug_print(DEBUG_OUTPUT_LLVM, 1, "swapped %s\n", Buf1.c_str());
				Buf1.clear();
			}
		}

		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:GEP1\n", inst, inst_log1->instruction.opcode);
		dstA = builder->CreateGEP(srcA, srcB, buffer);
		//dstA = GetElementPtrInst::Create(srcA, srcB, buffer, bb[node]);
		//         Type *AgTy = cast<PointerType>(I->getType())->getElementType();
		//         StructType *STy = cast<StructType>(AgTy);
		//         Value *Idx = GetElementPtrInst::Create(
                //                        STy, *AI, Idxs, (*AI)->getName() + "." + Twine(i), Call);

		//dstA = GetElementPtrInst::Create(STy, srcA, srcB, buffer, bb[node]);
		// FIXME: JCD must get GEP working. 
		//dstA = srcA;
		value[inst_log1->value3.value_id] = dstA;

		dstA->print(OS1);
		OS1 << "\n";
		OS1.flush();
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		break;

	case 0x36:  // TRUNC
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:TRUNC\n", inst, inst_log1->instruction.opcode);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx, value_id3 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value3.value_id,
			external_entry_point->label_redirect[inst_log1->value3.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value3.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];

		srcA->print(OS1);
		OS1 << "\n";
		OS1.flush();
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();

		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value3.value_id]));
		value_id_dst = external_entry_point->label_redirect[inst_log1->value3.value_id].index;
		label = &external_entry_point->labels[value_id_dst];
		tmp = label_to_string(label, buffer, 1023);
		if (external_entry_point->labels[value_id_dst].tip2) {
			size_bits = external_entry_point->tip2[external_entry_point->labels[value_id_dst].tip2].integer_size;
		} else {
			size_bits = 8;
		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "label->tip2: size_bits = 0x%lx\n", size_bits);
		dstA = builder->CreateTrunc(srcA, IntegerType::get(mod->getContext(), size_bits), buffer);
		value[value_id_dst] = dstA;

		dstA->print(OS1);
		OS1 << "\n";
		OS1.flush();
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		break;

	case 0x37:  // ZEXT
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:ZEXT\n", inst, inst_log1->instruction.opcode);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx, value_id3 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value3.value_id,
			external_entry_point->label_redirect[inst_log1->value3.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value3.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value3.value_id]));
		value_id_dst = external_entry_point->label_redirect[inst_log1->value3.value_id].index;
		label = &external_entry_point->labels[value_id_dst];
		tmp = label_to_string(label, buffer, 1023);
		if (external_entry_point->labels[value_id_dst].tip2) {
			size_bits = external_entry_point->tip2[external_entry_point->labels[value_id_dst].tip2].integer_size;
		} else {
			size_bits = 8;
		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "label->tip2: size_bits = 0x%lx\n", size_bits);
		dstA = builder->CreateZExt(srcA, IntegerType::get(mod->getContext(), size_bits), buffer);
		value[value_id_dst] = dstA;
		dstA->print(OS1);
		OS1 << "\n";
		OS1.flush();
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		break;

	case 0x38:  // BITCAST
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM 0x%x: OPCODE = 0x%x:BITCAST\n", inst, inst_log1->instruction.opcode);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "value_id1 = 0x%lx->0x%lx:0x%lx, value_id3 = 0x%lx->0x%lx:0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value1.value_id].index,
			inst_log1->value3.value_id,
			external_entry_point->label_redirect[inst_log1->value3.value_id].domain,
			external_entry_point->label_redirect[inst_log1->value3.value_id].index);
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value1.value_id]));
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].index;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		tmp = check_domain(&(external_entry_point->label_redirect[inst_log1->value3.value_id]));
		value_id_dst = external_entry_point->label_redirect[inst_log1->value3.value_id].index;
		label = &external_entry_point->labels[value_id_dst];
		tmp = label_to_string(label, buffer, 1023);
		if (external_entry_point->labels[value_id_dst].tip2) {
			uint64_t pointer_to_tip;
			pointer_to_tip = external_entry_point->tip2[label->tip2].pointer_to_tip;
			if (pointer_to_tip) {
				size_bits = external_entry_point->tip2[pointer_to_tip].integer_size;
			} else {
				size_bits = 8;
			}
		} else {
			size_bits = 8;
		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "BITCAST: label->tip2: size_bits = 0x%lx\n", size_bits);
		dstA = builder->CreateBitCast(srcA, PointerType::get(IntegerType::get(mod->getContext(), size_bits), 0), buffer);
		value[value_id_dst] = dstA;
		dstA->print(OS1);
		OS1 << "\n";
		OS1.flush();
		debug_print(DEBUG_OUTPUT_LLVM, 1, "dstA: %s\n", Buf1.c_str());
		Buf1.clear();
		break;


	default:
		debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: LLVM 0x%x: OPCODE = 0x%x. Not yet handled.\n", inst, inst_log1->instruction.opcode);
		exit(1);
		result = 1;
		break;
	}

	return result;
} 

int LLVM_ir_export::add_node_instructions(struct self_s *self, Module *mod, struct declaration_s *declaration, Value** value, BasicBlock **bb, int node, int external_entry) 
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[external_entry]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	int nodes_size = external_entry_point->nodes_size;
	int l,m,n;
	int inst;
	int inst_next;
	int tmp;
	int node_true;
	int block_end;

	debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM Node 0x%x\n", node);
	IRBuilder<> *builder = declaration[external_entry].builder;
	builder->SetInsertPoint(bb[node]);
	inst = nodes[node].inst_start;
	inst_next = inst;

	do {
		inst = inst_next;
		inst_log1 =  &inst_log_entry[inst];
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM node end: inst_end = 0x%x, next_size = 0x%x, node_end = 0x%x\n",
			nodes[node].inst_end, inst_log1->next_size, inst_log1->node_end);
		tmp = add_instruction(self, mod, declaration, value, bb, node, external_entry, inst);
		if (inst_log1->next_size > 0) {
			inst_next = inst_log1->next[0];
		}
		debug_print(DEBUG_OUTPUT_LLVM, 1, "tmp = 0x%x\n", tmp);
		/* FIXME: is tmp really needed for block_end detection? */
		block_end = (inst_log1->node_end || !(inst_log1->next_size) || tmp);
		//block_end = (inst_log1->node_end || !(inst_log1->next_size));
	} while (!block_end);

	if (!tmp) {
		/* Only output the extra branch if the node did not do any branches or returns itself. */
		debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM node end: node = 0x%x, inst_end = 0x%x, next_size = 0x%x\n",
			node, nodes[node].inst_end, nodes[node].next_size);
		node_true = nodes[node].link_next[0].node;
		//BranchInst::Create(bb[node_true], bb[node]);
		builder->CreateBr(bb[node_true]);
	}
	return 0;
}

int LLVM_ir_export::fill_value(struct self_s *self, Value **value, int value_id, int external_entry)
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[external_entry]);
	struct label_s *label = &(external_entry_point->labels[value_id]);
	int labels_size = external_entry_point->variable_id;
	uint64_t size_bits;

	if (external_entry_point->labels[value_id].tip2) {
		size_bits = external_entry_point->tip2[external_entry_point->labels[value_id].tip2].integer_size;
	} else {
		size_bits = 8;
	}

	if ((label->scope == 3) &&
		(label->type == 3)) {
		if (size_bits == 32) {
			value[value_id] = ConstantInt::get(Type::getInt32Ty(Context), label->value);
		} else if (size_bits == 64) {
			value[value_id] = ConstantInt::get(Type::getInt64Ty(Context), label->value);
		} else {
			debug_print(DEBUG_OUTPUT_LLVM, 1, "ERROR: LLVM fill_value() failed with size_bits = 0x%lx\n", size_bits);
			return 1;
		}
		return 0;
	} else {
		debug_print(DEBUG_OUTPUT_LLVM, 1, "ERROR: LLVM fill_value(): value_id = 0x%x, label->scope = 0x%lx, label->type = 0x%lx\n",
			value_id,
			label->scope,
			label->type);
	}

	return 1;
}

int LLVM_ir_export::output(struct self_s *self)
{
	const char *function_name = "test123";
	char output_filename[512];
	int m;
	int l;
	int tmp;
	struct control_flow_node_s *nodes;
	int nodes_size;
	int node;
	struct label_s *labels;
	int labels_size;
	struct label_redirect_s *label_redirect;
	struct label_s *label;
	struct tip2_s *tip2;
	char buffer[1024];
	uint64_t index;
	uint64_t lab_pointer;
	uint64_t size_bits;
	std::string Buf1;
	raw_string_ostream OS1(Buf1);
	StringRef PassPipeline;

	debug_print(DEBUG_OUTPUT_LLVM, 1, "sizeof(void**) = 0x%lx, sizeof(Value**) = 0x%lx\n", sizeof(void**), sizeof(Value**));
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	struct declaration_s *declaration = static_cast <struct declaration_s *> (calloc(EXTERNAL_ENTRY_POINTS_MAX, sizeof (struct declaration_s)));

	Module *mod = new Module("test_llvm_export", Context);
	mod->setDataLayout("e-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-v64:64:64-v128:128:128-a0:0:64-s0:64:64-f80:128:128-n8:16:32:64-S128");
	mod->setTargetTriple("x86_64-pc-linux-gnu");

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid != 0) &&
			(external_entry_points[l].type == 1) &&
			(external_entry_points[l].nodes_size)) {
			nodes_size = external_entry_points[l].nodes_size;
			Value **value = (Value**) calloc(external_entry_points[l].variable_id, sizeof(Value*));
			external_entry_points[l].llvm_value = (void**)value;
			BasicBlock **bb = (BasicBlock **)calloc(nodes_size + 1, sizeof (BasicBlock *));
			external_entry_points[l].llvm_basic_blocks = (void**)bb;
		}
	}

	// Global Variables
	PointerType* PointerTy_1 = PointerType::get(IntegerType::get(mod->getContext(), 32), 0);
	GlobalVariable* gvar_ptr_mem = new GlobalVariable(/*Module=*/*mod,
	/*Type=*/PointerTy_1,
	/*isConstant=*/false,
	/*Linkage=*/GlobalValue::ExternalLinkage,
	/*Initializer=*/0,
	/*Name=*/"memjcd1");
	//gvar_ptr_mem->setAlignment(8);

	//mod->dump();
	mod->print(llvm::errs(), nullptr);

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid != 0) &&
			(external_entry_points[l].type == 1) && 
			(external_entry_points[l].nodes_size)) {
			Value **value = (Value**)external_entry_points[l].llvm_value;
			nodes = external_entry_points[l].nodes;
			nodes_size = external_entry_points[l].nodes_size;
			labels = external_entry_points[l].labels;
			labels_size = external_entry_points[l].variable_id;
			label_redirect = external_entry_points[l].label_redirect;
			tip2 = external_entry_points[l].tip2;

			for (m = 0; m < labels_size; m++) {
				//tmp = check_domain(&(label_redirect[m]));
				index = label_redirect[m].index;
				label = &labels[index];
				if (labels[index].tip2) {
					size_bits = tip2[labels[index].tip2].integer_size;
                                        if (size_bits < 8) {
                                            size_bits = 8;
                                        }
				} else {
					size_bits = 8;
				}
				if ((3 == label->scope) && (2 == label->type)) {
					debug_print(DEBUG_OUTPUT_LLVM, 1, "Adding GLOBAL: Label:0x%x: &data found. size=0x%lx, pointer=0x%lx\n",
							m, size_bits,
							tip2[labels[index].tip2].pointer);
					tmp = label_to_string(&(labels[index]), buffer, 1023);
					GlobalVariable* gvar_mem1 = new GlobalVariable(/*Module=*/*mod,
						/*Type=*/IntegerType::get(mod->getContext(), size_bits),
						/*isConstant=*/false,
						///*Linkage=*/GlobalValue::InternalLinkage,
						/*Linkage=*/GlobalValue::ExternalLinkage,
						/*Initializer=*/0, // has initializer, specified below
						/*Name=*/buffer);
					gvar_mem1->setAlignment(size_bits >> 3);
					value[m] = gvar_mem1;
				}
			}
		}
	}

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid != 0) &&
			(external_entry_points[l].type == 1)) {
			//std::vector<Type*>FuncTy_0_args;
			struct label_s *labels_ext = external_entry_points[l].labels;
			Value **value = (Value**)external_entry_points[l].llvm_value;
#if 0
			for (m = 0; m < external_entry_points[l].params_reg_ordered_size; m++) {
				index = external_entry_points[l].params[m];
				if (labels_ext[index].lab_pointer > 0) {
					int size = labels_ext[index].pointer_type_size_bits;
					debug_print(DEBUG_OUTPUT_LLVM, 1, "Reg Param=0x%x: Pointer Label 0x%x, size_bits = 0x%x\n", m, index, size);
					if (size < 8) {
						debug_print(DEBUG_OUTPUT_LLVM, 1, "FIXME: size too small\n");
						size = 8;
					}
					declaration[l].FuncTy_0_args.push_back(PointerType::get(IntegerType::get(mod->getContext(), size), 0));
				} else {
					int size = labels_ext[index].size_bits;
					debug_print(DEBUG_OUTPUT_LLVM, 1, "Reg Param=0x%x: Label 0x%x, size_bits = 0x%x\n", m, index, size);
					declaration[l].FuncTy_0_args.push_back(IntegerType::get(mod->getContext(), size));
				}
			}

			for (m = 0; m < external_entry_points[l].params_stack_ordered_size; m++) {
				index = external_entry_points[l].params_stack_ordered[m];
				if (index == 3) {
				/* EIP or param_stack0000 */
				}
				if (labels_ext[index].lab_pointer > 0) {
					int size = labels_ext[index].pointer_type_size_bits;
					debug_print(DEBUG_OUTPUT_LLVM, 1, "Stack Param=0x%x: Pointer Label 0x%x, size_bits = 0x%x\n", m, index, size);
					if (size < 8) {
						debug_print(DEBUG_OUTPUT_LLVM, 1, "FIXME: size too small\n");
						size = 64;
					}
					declaration[l].FuncTy_0_args.push_back(PointerType::get(IntegerType::get(mod->getContext(), size), 0));
				} else {
					int size = labels_ext[index].size_bits;
					debug_print(DEBUG_OUTPUT_LLVM, 1, "Stack Param=0x%x: Label 0x%x, size_bits = 0x%x\n", m, index, size);
					declaration[l].FuncTy_0_args.push_back(IntegerType::get(mod->getContext(), size));
				}
			}
#endif
			if (external_entry_points[l].params_size > 0) {
				char buffer[1024];
				for (m = 0; m < external_entry_points[l].params_size; m++) {
					uint64_t label_index;
					tmp = external_entry_points[l].params[m];
					check_domain(&(external_entry_points[l].label_redirect[tmp]));
					label_index = external_entry_points[l].label_redirect[tmp].index;
					//if (label_index == 3) {
					///* EIP or param_stack0000 */
					//}
					if (labels_ext[label_index].tip2) {
						lab_pointer = external_entry_points[l].tip2[labels_ext[label_index].tip2].pointer;
					} else {
						lab_pointer = 0;
					}
					if (lab_pointer > 0) {
						//int size = labels_ext[label_index].pointer_type_size_bits;
						// FIXME:  get the correct size here for the pointer
						size_bits = 8;
						debug_print(DEBUG_OUTPUT_LLVM, 1, "Stack Param=0x%x: Pointer Label 0x%lx, size_bits = 0x%lx\n",
							m, label_index, size_bits);
						if (size_bits < 8) {
							debug_print(DEBUG_OUTPUT_LLVM, 1, "FIXME: size too small\n");
							size_bits = 8;
						}
						declaration[l].FuncTy_0_args.push_back(PointerType::get(IntegerType::get(mod->getContext(), size_bits), 0));
					} else {
						if (labels_ext[label_index].tip2) {
							size_bits = external_entry_points[l].tip2[labels_ext[label_index].tip2].integer_size;
						} else {
							size_bits = 8;
						}
						debug_print(DEBUG_OUTPUT_LLVM, 1, "Stack Param=0x%x: Label 0x%lx, size_bits = 0x%lx\n",
							m, label_index, size_bits);
						declaration[l].FuncTy_0_args.push_back(IntegerType::get(mod->getContext(), size_bits));
					}
				}
			}



			// dump names for all arguments.
			debug_print(DEBUG_OUTPUT_LLVM, 1, "Dump all the function args LLVM version\n");
			unsigned Idx = 0;
			for (Idx = 0; Idx < declaration[l].FuncTy_0_args.size(); Idx++) {
				//declaration[l].FuncTy_0_args[Idx]->dump();
				declaration[l].FuncTy_0_args[Idx]->print(llvm::errs());
			}
			debug_print(DEBUG_OUTPUT_LLVM, 1, "Dump all the function args Source version\n");
			if (external_entry_points[l].params_size > 0) {
				char buffer[1024];
				for (m = 0; m < external_entry_points[l].params_size; m++) {
					int label_index;
					tmp = external_entry_points[l].params[m];
					check_domain(&(external_entry_points[l].label_redirect[tmp]));
					label_index = external_entry_points[l].label_redirect[tmp].index;
					printf("Label 0x%x->0x%x:", tmp, label_index);
					tmp = label_to_string(&external_entry_points[l].labels[label_index], buffer, 1023);
					label = &external_entry_points[l].labels[label_index];
					if (label->tip2) {
						size_bits = external_entry_points[l].tip2[label->tip2].integer_size;
					} else {
						size_bits = 8;
					}
					if (label->tip2) {
						lab_pointer = external_entry_points[l].tip2[label->tip2].pointer;
					} else {
						lab_pointer = 0;
					}
					printf("%s/0x%lx,ps=0x%x, lp=0x%lx\n",
						buffer,
						size_bits,
						/* FIXME: Get the pointer size right */
						8,
						lab_pointer);

					tmp = printf("\n");
				}
			}
		}
	}
	/* Initialise the function type declarations */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid != 0) &&
			(external_entry_points[l].type == 1)) {
			FunctionType *FT;
			Value **value = (Value**)external_entry_points[l].llvm_value;
			/* FIXME: Need to be able to adjust the return type. */
			index = external_entry_points[l].function_return_type;
			lab_pointer = external_entry_points[l].tip2[index].pointer;
			size_bits = external_entry_points[l].tip2[index].integer_size;
			debug_print(DEBUG_OUTPUT_LLVM, 1, "FT return type: index=0x%lx, size_bits=0x%lx\n",
				       index, size_bits);
			if (lab_pointer) {
				/* Pointer type */
				PointerType* PointerTy_1 = PointerType::get(IntegerType::get(mod->getContext(), 64), 0);
				FT = FunctionType::get(PointerTy_1,
						declaration[l].FuncTy_0_args,
						false); /*not vararg*/
			} else {
				/* Integer type */
				IntegerType* IntTy_1 = IntegerType::get(mod->getContext(), size_bits);
				FT = FunctionType::get(IntTy_1,
						declaration[l].FuncTy_0_args,
						false); /*not vararg*/
			}
			declaration[l].FT = FT;
		}
	}
	/* Initialise the function with parameters declarations */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid != 0) &&
			(external_entry_points[l].type == 1)) {
			function_name = external_entry_points[l].name;
			Value **value = (Value**)external_entry_points[l].llvm_value;
			Function *F =
				Function::Create(declaration[l].FT, Function::ExternalLinkage, function_name, mod);

			declaration[l].F = F;
			Function::arg_iterator AI = F->arg_begin();
			char buffer[1024];
			for (m = 0; m < external_entry_points[l].params_size; m++) {
				int label_index;
				tmp = external_entry_points[l].params[m];
				check_domain(&(external_entry_points[l].label_redirect[tmp]));
				label_index = external_entry_points[l].label_redirect[tmp].index;
				tmp = label_to_string(&external_entry_points[l].labels[label_index], buffer, 1023);
				printf("buffer=%s\n", buffer);
				AI->setName(buffer);
				value[label_index] = &*AI;
				AI++;
			}

			declaration[l].F->print(OS1);
			debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
			Buf1.clear();
		}
	}

#if 0
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid != 0) &&
			(external_entry_points[l].type == 1)) {
			Function::arg_iterator args = declaration[l].F->arg_begin();
			debug_print(DEBUG_OUTPUT_LLVM, 1, "Function: %s()  param_size = 0x%x\n", function_name, external_entry_points[l].params_size);
			for (m = 0; m < external_entry_points[l].params_reg_ordered_size; m++) {
				index = external_entry_points[l].params_reg_ordered[m];
				tmp = label_to_string(&(labels[index]), buffer, 1023);
				debug_print(DEBUG_OUTPUT_LLVM, 1, "Adding reg param:%s:value index=0x%x\n", buffer, index);
				args->setName(buffer);
				args++;
			}
			for (m = 0; m < external_entry_points[l].params_stack_ordered_size; m++) {
				index = external_entry_points[l].params_stack_ordered[m];
				tmp = label_to_string(&(labels[index]), buffer, 1023);
				debug_print(DEBUG_OUTPUT_LLVM, 1, "Adding stack param:%s:value index=0x%x\n", buffer, index);
				args->setName(buffer);
				args++;
			}
			declaration[l].F->dump();
		}
	}
#endif

#if 0
	// Debug params_reg_ordered indexes
	for (m = 0; m < external_entry_points[n].params_reg_ordered_size; m++) {
		index = external_entry_points[n].params_reg_ordered[m];
		printf("external_entry_points[%d].params_reg_ordered[%d] = %d;\n",
			n, m, index);
	}
	Function::arg_iterator args = declaration[n].F->arg_begin();
	debug_print(DEBUG_OUTPUT_LLVM, 1, "Function: %s()  param_size = 0x%x\n", function_name, external_entry_points[n].params_size);
	for (m = 0; m < external_entry_points[n].params_reg_ordered_size; m++) {
		index = external_entry_points[n].params_reg_ordered[m];
		if (!index) {
			debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: value[index]: Index = 0. \n");
			continue;
		}
		value[index] = &*args;
		tmp = label_to_string(&(labels[index]), buffer, 1023);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "Adding reg param:%s:value index=0x%x\n", buffer, index);
		value[index]->setName(buffer);
		sprint_value(OS1, value[index]);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();
		args++;
	}
	for (m = 0; m < external_entry_points[n].params_stack_ordered_size; m++) {
		index = external_entry_points[n].params_stack_ordered[m];
		if (!index) {
			debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: value[index]: Index = 0. \n");
			exit(1);
		}
		value[index] = &*args;
		tmp = label_to_string(&(labels[index]), buffer, 1023);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "Adding stack param:%s:value index=0x%x\n", buffer, index);
		value[index]->setName(buffer);
		sprint_value(OS1, value[index]);
		debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
		Buf1.clear();
		args++;
	}
#endif

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid != 0) &&
			(external_entry_points[l].type == 1) && 
			(external_entry_points[l].nodes_size)) {
			Value **value = (Value**)external_entry_points[l].llvm_value;
			BasicBlock **bb = (BasicBlock**)external_entry_points[l].llvm_basic_blocks;
			nodes = external_entry_points[l].nodes;
			nodes_size = external_entry_points[l].nodes_size;
			labels = external_entry_points[l].labels;
			labels_size = external_entry_points[l].variable_id;
			label_redirect = external_entry_points[l].label_redirect;
			tip2 = external_entry_points[l].tip2;

			/* Create all the nodes/basic blocks */
			for (m = 1; m < nodes_size; m++) {
				std::string node_string;
				std::stringstream tmp_str;
				tmp_str << "Node_0x" << std::hex << m;
				node_string = tmp_str.str();
				debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM2: %s\n", node_string.c_str());
				bb[m] = BasicBlock::Create(Context, node_string, declaration[l].F);
			}
			IRBuilder<> *builder = new IRBuilder<>(bb[1]);
			declaration[l].builder = builder;
		}
	}
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid != 0) &&
			(external_entry_points[l].type == 1) && 
			(external_entry_points[l].nodes_size)) {
			Value **value = (Value**)external_entry_points[l].llvm_value;
			BasicBlock **bb = (BasicBlock**)external_entry_points[l].llvm_basic_blocks;
			nodes = external_entry_points[l].nodes;
			nodes_size = external_entry_points[l].nodes_size;
			labels = external_entry_points[l].labels;
			labels_size = external_entry_points[l].variable_id;
			label_redirect = external_entry_points[l].label_redirect;
			tip2 = external_entry_points[l].tip2;
			IRBuilder<> *builder = declaration[l].builder;
			builder->SetInsertPoint(bb[1]);

			/* Create the AllocaInst's */
			/* labels[0] should be empty and is a invalid value to errors can be caught. */
			for (m = 1; m < labels_size; m++) {
				int size_bits;
				/* local_stack */
				if ((labels[m].scope == 1) && 
					(labels[m].type == 2)) {
					tmp = label_to_string(&labels[m], buffer, 1023);
					/* FIXME: get these corrected */
#if 0
					if (labels[m].lab_pointer && labels[m].pointer_type == 2) {
						size_bits = labels[m].pointer_type_size_bits;
						debug_print(DEBUG_OUTPUT_LLVM, 1, "Creating alloca for ptr to int label 0x%x, size_bits = 0x%x\n", m, size_bits);
						//AllocaInst* ptr_local = new AllocaInst(IntegerType::get(mod->getContext(), size_bits), buffer, bb[1]);
						AllocaInst* ptr_local = builder->CreateAlloca(IntegerType::get(mod->getContext(), size_bits), nullptr, buffer);
						ptr_local->setAlignment(size_bits >> 3);
						value[m] = ptr_local;
					} else {
						size_bits = labels[m].pointer_type_size_bits;
						debug_print(DEBUG_OUTPUT_LLVM, 1, "Creating alloca for ptr to ptr label 0x%x, size_bits = 0x%x\n", m, size_bits);
						PointerType* PointerTy_1 = PointerType::get(IntegerType::get(mod->getContext(), size_bits), 0);
						//AllocaInst* ptr_local = new AllocaInst(PointerTy_1, buffer, bb[1]);
						AllocaInst* ptr_local = builder->CreateAlloca(PointerTy_1, nullptr, buffer);
						ptr_local->setAlignment(size_bits >> 3);
						value[m] = ptr_local;
					}
#endif
					/* FIXME: temp all alloc are I8 */
					if (tip2[m].pointer) {
						size_bits = 8;
						debug_print(DEBUG_OUTPUT_LLVM, 1, "Creating alloca for ptr to ptr label 0x%x, size_bits = 0x%x\n", m, size_bits);
						PointerType* PointerTy_1 = PointerType::get(IntegerType::get(mod->getContext(), size_bits), 0);
						AllocaInst* ptr_local = builder->CreateAlloca(PointerTy_1, nullptr, buffer);
						ptr_local->setAlignment(size_bits >> 3);
						value[m] = ptr_local;
					} else {
						size_bits = tip2[m].integer_size;
						debug_print(DEBUG_OUTPUT_LLVM, 1, "Creating alloca for ptr to int label 0x%x, size_bits = 0x%x\n", m, size_bits);
						AllocaInst* ptr_local = builder->CreateAlloca(IntegerType::get(mod->getContext(), size_bits), nullptr, buffer);
						ptr_local->setAlignment(size_bits >> 3);
						value[m] = ptr_local;
					}
				}
			}
				
			/* FIXME: this needs the node to follow paths so the value[] is filled in the correct order */
			debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM: starting nodes\n");
			for (m = 1; m < nodes_size; m++) {
				debug_print(DEBUG_OUTPUT_LLVM, 1, "JCD12: node:0x%x: next_size = 0x%x\n", m, nodes[m].next_size);
			};
			for (node = 1; node < nodes_size; node++) {
				debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM: PHI PHASE 1: node=0x%x\n", node);

				builder->SetInsertPoint(bb[node]);
				/* Output PHI instructions first */
				for (m = 0; m < nodes[node].phi_size; m++) {
					int value_id = nodes[node].phi[m].value_id;
					int size_bits;
					int value_id1;
					int redirect_value_id;
					int first_previous_node;
					PHINode* phi_node;
					debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM:phi 0x%x, value_id = 0x%x, reg=0x%x\n", m, value_id, nodes[node].phi[m].reg);
					if (!value_id) {
						debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: labels[value_id]: value_id = 0. \n");
						exit(1);
					}
					tmp = label_to_string(&labels[value_id], buffer, 1023);
					if (labels[value_id].tip2) {
						lab_pointer = external_entry_points[l].tip2[labels[value_id].tip2].pointer;
					} else {
						lab_pointer = 0;
					}
					if (lab_pointer) {
						//size_bits = labels[m].pointer_type_size_bits;
						/* FIXME:size 8 */
						//if (!size_bits) size_bits = 8;
						size_bits = 8;
						PointerType* PointerTy_1 = PointerType::get(IntegerType::get(mod->getContext(), size_bits), 0);
						//phi_node = PHINode::Create(PointerTy_1,
						//	nodes[node].phi[m].phi_node_size,
						//	buffer, bb[node]);
						phi_node = builder->CreatePHI(PointerTy_1,
							nodes[node].phi[m].phi_node_size,
							buffer);
						value[value_id] = phi_node;
					} else {
						if (labels[value_id].tip2) {
							size_bits = external_entry_points[l].tip2[labels[value_id].tip2].integer_size;
						} else {
							size_bits = 8;
						}
						debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM phi base size = 0x%x\n", size_bits);
						//phi_node = PHINode::Create(IntegerType::get(mod->getContext(), size_bits),
						//	nodes[node].phi[m].phi_node_size,
						//	buffer, bb[node]);
						phi_node = builder->CreatePHI(IntegerType::get(mod->getContext(), size_bits),
							nodes[node].phi[m].phi_node_size,
							buffer);
						value[value_id] = phi_node;
					}
					value_id1 = nodes[node].phi[m].phi_node[0].value_id;
					if (!value_id1) {
						debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: labels_redirect[value_id1]: value_id = 0. \n");
						exit(1);
					}
					check_domain(&(label_redirect[value_id1]));
					redirect_value_id = label_redirect[value_id1].index;
					first_previous_node = nodes[node].phi[m].phi_node[0].first_prev_node;
					debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM phi value_id1 = 0x%x, fpn = 0x%x\n", redirect_value_id, first_previous_node);
					sprint_value(OS1, value[value_id]);
					debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
					Buf1.clear();
					sprint_value(OS1, value[redirect_value_id]);
					debug_print(DEBUG_OUTPUT_LLVM, 1, "%s\n", Buf1.c_str());
					Buf1.clear();
					if (redirect_value_id > 0) {
						phi_node->addIncoming(value[redirect_value_id], bb[first_previous_node]);
					}
					/* The rest of the PHI instruction is added later */
				}
				LLVM_ir_export::add_node_instructions(self, mod, declaration, value, bb, node, l);
			}
#if 1
			for (node = 1; node < nodes_size; node++) {
				debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM: PHI PHASE 2: node=0x%x\n", node);

				for (m = 0; m < nodes[node].phi_size; m++) {
					//int size_bits = labels[nodes[node].phi[m].value_id].size_bits;
					debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM:phi 0x%x\n", m);
					//debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM phi base size = 0x%x\n", size_bits);
					PHINode* phi_node = (PHINode*)value[nodes[node].phi[m].value_id];
					/* l = 0 has already been handled */
					for (int n = 1; n < nodes[node].phi[m].phi_node_size; n++) {
						int value_id;
						int redirect_value_id;
						int first_previous_node;
						value_id = nodes[node].phi[m].phi_node[n].value_id;
						if (!value_id) {
							debug_print(DEBUG_OUTPUT_LLVM, 0, "ERROR: labels_redirect[value_id]: value_id = 0. \n");
							exit(1);
						}
						check_domain(&(label_redirect[value_id]));
						redirect_value_id = label_redirect[value_id].index;
						first_previous_node = nodes[node].phi[m].phi_node[n].first_prev_node;
						debug_print(DEBUG_OUTPUT_LLVM, 1, "LLVM:phi 0x%x:0x%x FPN=0x%x, SN=0x%x, value_id=0x%x, redirected_value_id=0x%x\n",
							m, n,
							nodes[node].phi[m].phi_node[n].first_prev_node,
							nodes[node].phi[m].phi_node[n].node,
							value_id,
							redirect_value_id);
							/* FIXME: add this size */
							//labels[redirect_value_id].size_bits);
						if (value_id > 0) {
							phi_node->addIncoming(value[redirect_value_id], bb[first_previous_node]);
						}
					}
				}
			}
		}
	}
	//mod->dump();
	mod->print(llvm::errs(), nullptr);
#endif
	/* FIXME: Work with more than one function */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		 if (external_entry_points[l].type == 1) {
			 function_name = external_entry_points[l].name;
			 break;
		 }
	}
	debug_print(DEBUG_OUTPUT_LLVM, 1, "output_filename: %s\n", function_name);
	snprintf(output_filename, 500, "./llvm/%s.bc", function_name);
	std::string ErrorInfo;
	std::error_code error_code;
	raw_fd_ostream OS(output_filename, error_code, llvm::sys::fs::F_None);
	raw_fd_ostream OS2("llvm_output_errors.txt", error_code, llvm::sys::fs::F_None);

	if (error_code) {
		// *ErrorMessage = strdup(error_code.message().c_str());
		return -1;
	}

	TargetMachine* TM = nullptr;
	PassBuilder PB(TM);

	LoopAnalysisManager LAM(DebugPM);
	FunctionAnalysisManager FAM(DebugPM);
	CGSCCAnalysisManager CGAM(DebugPM);
	ModuleAnalysisManager MAM(DebugPM);

	PB.registerModuleAnalyses(MAM);
	PB.registerCGSCCAnalyses(CGAM);
	PB.registerFunctionAnalyses(FAM);
	PB.registerLoopAnalyses(LAM);
	PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
	//OS2 << PB;

	ModulePassManager MPM(DebugPM);
	//MAM.add(new MYTool());

	/* True is is fails */
	if (verifyModule(*mod, &OS2)) {
		PassPipeline = "function(print)";
		if (!PB.parsePassPipeline(MPM, PassPipeline, 0,
			DebugPM)) {
			std::cout << ": unable to parse pass pipeline description. " ;
			std::cout << PassPipeline.data() ;
			std::cout << "\n" ;
			return 1;
		}

		MPM.run(*mod, MAM);
		printf(": Error verifying module!\n");
		debug_print(DEBUG_OUTPUT_LLVM, 1, ": Error verifying module!\n");
		OS2.close();
		exit(1);
	}

//	PassPipeline = "print,module(function(dse),cgscc(function-attrs)),print,deadargelim,print";
	PassPipeline = "print,module(function(dse),cgscc(function-attrs)),print";
	if (!PB.parsePassPipeline(MPM, PassPipeline, 0,
		DebugPM)) {
		std::cout << ": unable to parse pass pipeline description. " ;
		std::cout << PassPipeline.data() ;
		std::cout << "\n" ;
		return 1;
	}

	MPM.run(*mod, MAM);


	WriteBitcodeToFile(mod, OS);
	delete mod;

	return 0;
}

int LLVM_ir_export_entry(struct self_s *self)
{
	int tmp;
	LLVM_ir_export object;
	tmp = object.output(self);
	return tmp;
}

extern "C" int llvm_export(struct self_s *self)
{
	int tmp;
	tmp = LLVM_ir_export_entry(self);
	return tmp;
}
