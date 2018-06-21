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
#include <system_error>
#include <iostream>
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

	if (DI.getSeverity() == DS_Error)
		exit(1);
}

static ExitOnError ExitOnErr;

static std::unique_ptr<Module> openInputFile(LLVMContext &Context) {
	std::unique_ptr<MemoryBuffer> MB =
		ExitOnErr(errorOrToExpected(MemoryBuffer::getFileOrSTDIN(InputFilename)));
	std::unique_ptr<Module> M =
		ExitOnErr(getOwningLazyBitcodeModule(std::move(MB), Context,
						 /*ShouldLazyLoadMetadata=*/false));
	//if (MaterializeMetadata)
	//  ExitOnErr(M->materializeMetadata());
	//else
	ExitOnErr(M->materializeAll());
	return M;
}

int main(int argc, char **argv) {

	std::cout << "test0\n";
	LLVMContext Context;
	llvm::TypeFinder type_finder;
	llvm_shutdown_obj Y;  // Call llvm_shutdown() on exit.
	InputFilename = argv[1];
	Context.setDiagnosticHandler(diagnosticHandler, argv[0]);

	//std::unique_ptr<Module> Mod = openInputFile(Context);
	auto Mod = openInputFile(Context);
	type_finder.run(*Mod, true);

	for (TypeFinder::const_iterator I = type_finder.begin(),
			 E = type_finder.end();
			 I != E; ++I) {
		outs() << "Found TypeFinder:\n";
		StructType *STy = *I;
		outs() << *STy;
	}
	outs() << "\n";

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

    outs() << "\n";
    const auto &FL = Mod->getFunctionList();
    //int64_t size = FL.size();
    int64_t size = Mod->size();
    outs() << "size = " << size << "\n";
    outs() << "sizeM = " << Mod->size() << "\n";
    Module::const_iterator it = Mod->begin();
    Module::const_iterator functions[size + 1];
    functions[0] = Mod->end();
    for (int n = 0; n < size; n++) {
    	functions[n + 1] = it;
    	++it;
    }
    Module::FunctionListType FL2[size + 1];

    llvm::outs() << "\nName: ";
    llvm::outs() << "\n";
    //llvm::outs() << FL2[0]->getName();
    llvm::outs() << functions[2]->getName();
    llvm::outs() << "\n";
    llvm::outs() << (functions[2] == Mod->end());
    llvm::outs() << " - Done\n";


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

	return 0;
}
