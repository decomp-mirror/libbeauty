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
#include <global_struct.h>
#include <debug_llvm.h>
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
extern "C" int input_find_types(char *filename, struct input_find_types_s *find_types) {

	debug_print(DEBUG_INPUT_HEADER, 0, "Entered\n");
	LLVMContext Context;
	llvm::TypeFinder type_finder;
	llvm_shutdown_obj Y;  // Call llvm_shutdown() on exit.
	InputFilename = filename;
	Context.setDiagnosticHandler(diagnosticHandler, nullptr);
	SMDiagnostic error;
  //Module *m = parseIRFile("hello.bc", error, context);
	//std::unique_ptr<Module> Mod = openInputFile(Context);
	std::unique_ptr<Module> Mod = parseIRFile(filename, error, Context);
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



	for (Module::const_iterator I = Mod->begin(),
			 E = Mod->end();
			 I != E; ++I) {
		outs() << "Found Funct:\n";
		I->print(llvm::outs());
	}
	outs() << "\n";

	for (Module::const_ifunc_iterator I = Mod->ifunc_begin(),
			 E = Mod->ifunc_end();
			 I != E; ++I) {
		outs() << "Found ifunc:\n";
		I->print(llvm::outs());
	}
	outs() << "\n";

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
