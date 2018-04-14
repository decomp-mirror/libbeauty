/* Test creation of a .bc file for LLVM IR*/

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <global_struct.h>

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

// Example pass: just dumps the insns for every block.
namespace {
  struct MYTool : public ModulePass {
    static char ID;
    MYTool() : ModulePass(ID) {}
    virtual bool runOnModule(Module &M) {
      errs() << "Basic JCD Block\n";
      return false;
    }
  };
}

// Pass info
char MYTool::ID = 0; // LLVM ignores the actual value
static RegisterPass<MYTool> X("mytool", "Example pass", false, false);

// Pass loading stuff
// To use, run: clang -Xclang -load -Xclang <your-pass>.so <other-args> ...

// This function is of type PassManagerBuilder::ExtensionFn
//static void loadPass(const PassManagerBuilder &Builder, PassManagerBase &PM) {
//  PM.add(new MYTool());
//}

