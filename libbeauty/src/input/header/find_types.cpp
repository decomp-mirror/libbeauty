/*
 *  Copyright (C) 2018  The libbeauty Team
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
 *
 * 11-9-2017 Initial work.
 *   Copyright (C) 2018 James Courtier-Dutton James@superbug.co.uk
 *
 */

#include "llvm/IR/LLVMContext.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/AssemblyAnnotationWriter.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/IRReader/IRReader.h"
#include <system_error>
#include <iostream>
#include <vector>
#include <global_struct.h>
#include <debug_llvm.h>
#include <input.h>
using namespace llvm;

static cl::opt<std::string>
InputFilename(cl::Positional, cl::desc("<input bitcode>"), cl::init("-"));

static cl::opt<bool>
	MaterializeMetadata("materialize-metadata",
		cl::desc("Load module without materializing metadata, "
				 "then materialize only the metadata"));

static void diagnosticHandler(const DiagnosticInfo &DI, void *Context) {
	raw_ostream &OS = outs();
	OS << (char *)Context << ": ";
	switch (DI.getSeverity()) {
		case DS_Error: OS << "error: "; break;
		case DS_Warning: OS << "warning: "; break;
		case DS_Remark: OS << "remark: "; break;
		case DS_Note: OS << "note: "; break;
	}

	DiagnosticPrinterRawOStream DP(OS);
	DI.print(DP);
	OS << '\n';

	if (DI.getSeverity() == DS_Error) {
		debug_print(DEBUG_INPUT_HEADER, 0, "Exiting\n");
		exit(1);
	}
}

static ExitOnError ExitOnErr;
#if 0
static std::unique_ptr<Module> openInputFile(LLVMContext &Context) {
	debug_print(DEBUG_INPUT_HEADER, 0, "Entered\n");
	ErrorOr<std::unique_ptr<MemoryBuffer>> MB_err =
		(MemoryBuffer::getFileOrSTDIN(InputFilename));
	if (MB_err.getError()) {
		debug_print(DEBUG_INPUT_HEADER, 0, "File Not Found\n");
	}
	std::unique_ptr<MemoryBuffer> MB = MB_err;

	//std::unique_ptr<MemoryBuffer> MB =
	//	ExitOnErr(errorOrToExpected(MemoryBuffer::getFileOrSTDIN(InputFilename)));
	debug_print(DEBUG_INPUT_HEADER, 0, "Entered2\n");
	std::unique_ptr<Module> M =
		ExitOnErr(getOwningLazyBitcodeModule(std::move(MB), Context,
						 /*ShouldLazyLoadMetadata=*/false));
	//auto M =
	//	getOwningLazyBitcodeModule(std::move(MB), Context,
	//					 /*ShouldLazyLoadMetadata=*/false);
	//if (MaterializeMetadata)
	//  ExitOnErr(M->materializeMetadata());
	//else
	debug_print(DEBUG_INPUT_HEADER, 0, "Entered3\n");
//	M->materializeAll();
	debug_print(DEBUG_INPUT_HEADER, 0, "Ended\n");
	return M;
}
#endif

int LLVM_input_header::input_dump_mod(struct self_s *self) {
	debug_print(DEBUG_INPUT_HEADER, 0, "Entered\n");
	outs() << *Mod;
	return 0;
}

int LLVM_input_header::input_find_types(struct self_s *self, char *filename, struct input_find_types_s *find_types) {

	debug_print(DEBUG_INPUT_HEADER, 0, "Entered\n");
	llvm::TypeFinder type_finder;
	llvm_shutdown_obj Y;  // Call llvm_shutdown() on exit.
	InputFilename = filename;
	LLVM_input_header::Context.setDiagnosticHandler(diagnosticHandler, nullptr);
	SMDiagnostic error;
	int n;
	uint64_t size;
  //Module *m = parseIRFile("hello.bc", error, context);
	//std::unique_ptr<Module> Mod = openInputFile(Context);
	//std::unique_ptr<Module> Mod = parseIRFile(filename, error, Context);
	LLVM_input_header::Mod = parseIRFile(filename, error, Context);
	//llvm:Module *Mod = parseIRFile(filename, error, Context);
	//Module *Mod = parseIRFile(filename, error, Context);
	//outs() << *Mod;
	if (!Mod) {
		debug_print(DEBUG_INPUT_HEADER, 0, "Exiting. Probably File not found\n");
		exit(1);
	}
	//auto Mod = openInputFile(Context);
	type_finder.run(*Mod, true);

	for (TypeFinder::const_iterator I = type_finder.begin(),
			 E = type_finder.end();
			 I != E; ++I) {
		debug_print(DEBUG_INPUT_HEADER, 0, "Found TypeFinder:\n");
		outs() << "Found TypeFinder:\n";
		StructType *STy = *I;
		outs() << *STy;
		outs() << "\n";
		outs() << "Name:" << STy->getStructName() << "\n";
		outs() << "Num Elems:" << STy->getStructNumElements() << "\n";
		for (StructType::element_iterator I2 = STy->element_begin(),
				 E2 = STy->element_end();
				 I2 != E2; ++I2) {
			Type *Ty = *I2;
			outs() << *Ty << "\n";
			Type::TypeID type_id = Ty->getTypeID();
			outs() << "Type ID:" << type_id << "\n";
			unsigned num_contained_types = Ty->getNumContainedTypes();
			outs() << "Num Containded Types:" << num_contained_types << "\n";

		}
		outs() << "\n";
	}
	outs() << "\n";

#if 0
	for (Module::global_value_iterator I = Mod->global_value_begin(),
			 E = Mod->global_value_end();
			 I != E; ++I) {
		outs() << "Found Global object:\n";
		I->print(llvm::outs());
	}
	outs() << "\n";

	for (Module::const_global_iterator I = Mod->global_begin(),
			 E = Mod->global_end();
			 I != E; ++I) {
		outs() << "Found Global:\n";
		I->print(llvm::outs());
	}
	outs() << "\n";
#endif

#if 1
	n = 1;
	size = Mod->size();
	LLVM_input_header::functions_size = size;
	LLVM_input_header::functions =
    		new Module::const_iterator[size + 1];
	functions[0] = Mod->end(); // Empty first record.
	for (Module::const_iterator I = Mod->begin(),
			 E = Mod->end();
			 I != E; ++I) {
		outs() << "Found Funct:\n";
		functions[n] = I;
		n++;
		I->print(llvm::outs());
	}
	outs() << "\n";
#endif
#if 0
	for (Module::const_ifunc_iterator I = Mod->ifunc_begin(),
			 E = Mod->ifunc_end();
			 I != E; ++I) {
		outs() << "Found ifunc:\n";
		I->print(llvm::outs());
	}
	outs() << "\n";
#endif
#if 0
	for (Module::const_alias_iterator I = Mod->alias_begin(),
			 E = Mod->alias_end();
			 I != E; ++I) {
		outs() << "Found Alias:\n";
		I->print(llvm::outs());
	}
	outs() << "\n";

	// Go over all named mdnodes in the module
	for (Module::const_named_metadata_iterator I = Mod->named_metadata_begin(),
																						 E = Mod->named_metadata_end();
			 I != E; ++I) {
		outs() << "Found MDNode:\n";
		I->print(llvm::outs());

		for (unsigned i = 0, e = I->getNumOperands(); i != e; ++i) {
			Metadata *Op = I->getOperand(i);
			if (auto *N = dyn_cast<MDNode>(Op)) {
				outs() << "	Has MDNode operand:\n	";
				// N->dump();
				outs() << "	" << N->getNumOperands() << " operands\n";
			}
		}
	}
	outs() << "\n";
#endif
	debug_print(DEBUG_INPUT_HEADER, 0, "Ended\n");
	return 0;
}

int LLVM_input_header::lookup_external_function(struct self_s *self, const char *symbol_name, int *result) {
	int found = 1; // 1 = not-found, 0 = found.
	int tmp;
	uint64_t nl;

	for(nl = 1; nl <= LLVM_input_header::functions_size; nl++) {
		tmp = functions[nl]->getName().compare(symbol_name);
		if (!tmp) {
			*result = nl;
			found = 0;
			break;
		}
	}
	return found;
}

int LLVM_input_header::input_external_function_get_size(struct self_s *self, int function_index, int *fields_size) {
	int tmp = 0;
	debug_print(DEBUG_INPUT_HEADER, 0, "Entered\n");
	if (function_index > functions_size) {
		return 1;
	}
	*fields_size = functions[function_index]->getFunctionType()->getNumParams();
	debug_print(DEBUG_INPUT_HEADER, 0, "NumOperands = %d\n", *fields_size);
	return 0;
}

StringRef LLVM_input_header::get_function_name(struct self_s *self, int function_index) {
	int tmp = 0;
	debug_print(DEBUG_INPUT_HEADER, 0, "Entered\n");
	if (function_index > functions_size) {
		debug_print(DEBUG_INPUT_HEADER, 0, "function_index out of range\n");
		exit(1);
	}
	return functions[function_index]->getName();
}

int LLVM_input_header::input_external_function_get_return_type(struct self_s *self, int function_index, int *lab_pointer, int *size_bits) {
	int tmp = 0;
	int integer_type = 0;
	debug_print(DEBUG_INPUT_HEADER, 0, "Entered\n");
	if (function_index > functions_size) {
		return 1;
	}
	*size_bits = 0;
	*lab_pointer = 0;
    integer_type = functions[function_index]->getReturnType()->isIntegerTy();
    if (integer_type) {
    	*size_bits = functions[function_index]->getReturnType()->getScalarSizeInBits();
    }
    llvm::outs() << " - SizeInBits\n";
    if (functions[function_index]->getReturnType()->isPointerTy()) {
    	*lab_pointer = 1;
    	*size_bits = 8;
    }
	debug_print(DEBUG_INPUT_HEADER, 0, "Size = %d, lab_pointer = %d\n", *size_bits, *lab_pointer);
	return 0;
}

FunctionType *LLVM_input_header::get_function_type( int function_index) {

	FunctionType *ft = (*functions[function_index]).getFunctionType();

	return ft;
	//Auto fred &(*functions[function_index]).F


}
extern "C" int input_dump_mod(struct self_s *self) {
	int tmp;
	LLVM_input_header *input_header = (LLVM_input_header*)self->input_header;
	tmp = input_header->input_dump_mod(self);
	return tmp;
}

extern "C" int input_find_types(struct self_s *self, char *filename, struct input_find_types_s *find_types) {
	int tmp;
	debug_print(DEBUG_INPUT_HEADER, 0, "Entered\n");
	LLVM_input_header *input_header = new(LLVM_input_header);
	void *ref = input_header;
	self->input_header = ref;
	debug_print(DEBUG_INPUT_HEADER, 0, "sizeof: %lu\n", sizeof(input_header));
	tmp = input_header->input_find_types(self, filename, find_types);
	debug_print(DEBUG_INPUT_HEADER, 0, "Ended\n");
	return tmp;
}

extern "C" int lookup_external_function(struct self_s *self, const char *symbol_name, int *result)
{
	int tmp;
	LLVM_input_header *input_header = (LLVM_input_header*)self->input_header;
	tmp = input_header->lookup_external_function(self, symbol_name, result);
	return tmp;
}

extern "C" int input_external_function_get_size(struct self_s *self, int function_index, int *fields_size) {
	int tmp;
	LLVM_input_header *input_header = (LLVM_input_header*)self->input_header;
	tmp = input_header->input_external_function_get_size(self, function_index, fields_size);
	return tmp;
}

extern "C" int input_external_function_get_name(struct self_s *self, int function_index, char **function_name) {
	int tmp;
	LLVM_input_header *input_header = (LLVM_input_header*)self->input_header;
	StringRef name = input_header->get_function_name(self, function_index);
	char *name2 = strndup(name.data(), 1024);
	*function_name = name2;
	return tmp;
}

extern "C" int input_external_function_get_return_type(struct self_s *self, int function_index, int *lab_pointer, int *size_bits) {
	int tmp;
	LLVM_input_header *input_header = (LLVM_input_header*)self->input_header;
	tmp = input_header->input_external_function_get_return_type(self, function_index, lab_pointer, size_bits);
	return tmp;
}
