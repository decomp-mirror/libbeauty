#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <iostream>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
//#include <llvm/Transforms/Scalar/LoopPassManager.h>

#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/MathExtras.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Bitcode/BitcodeWriter.h>

using namespace llvm;

static cl::opt<bool>
	DebugPM("debug-pass-manager", cl::Hidden,
		cl::desc("Print pass management debugging information"));




Module* makeLLVMModule(LLVMContext &Context, char *output_filename);

int main(int argc, char**argv) {
  char *output_filename;
  char *output_filename2;
  std::string ErrorInfo;
  std::error_code error_code;
  LLVMContext Context;

  output_filename = (char*)calloc(512, 1);
  snprintf(output_filename, 500, "test_llvm_builder_output.bc");
  output_filename2 = (char*)calloc(512, 1);
  snprintf(output_filename2, 500, "test_llvm_builder_error.txt");
  Module* Mod = makeLLVMModule(Context, output_filename);
// Verify Module
  //raw_fd_ostream OS(output_filename, error_code, 0);
  raw_fd_ostream OS2(output_filename2, error_code, sys::fs::OpenFlags::F_None);
  if (verifyModule(*Mod, &OS2)) {
    printf(": Error constructing function!\n");
    return 1;
  }
// Output Module Bitcode to file
  //raw_fd_ostream OS(output_filename, error_code, 0);
  raw_fd_ostream OS(output_filename, error_code, sys::fs::OpenFlags::F_None);

  if (error_code) {
  // *ErrorMessage = strdup(error_code.message().c_str());
    return 0;
  }
  WriteBitcodeToFile(Mod, OS);

  TargetMachine* TM = nullptr;
  StringRef PassPipeline = "cgscc(function-attrs),print";
//  StringRef PassPipeline = "function(print)";
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

  ModulePassManager MPM(DebugPM);

	if (!PB.parsePassPipeline(MPM, PassPipeline, 0,
		DebugPM)) {
		std::cout << ": unable to parse pass pipeline description. " ;
		std::cout << PassPipeline.data() ;
		std::cout << "\n" ;
		return 1;
	}


  MPM.run(*Mod, MAM);


//  verifyModule(*Mod, PrintMessageAction);
//  PassManager PM;
//  PM.add(createPrintModulePass(&outs()));
//  PM.run(*Mod);
  return 0;
}


Module* makeLLVMModule(LLVMContext &Context, char *output_filename) {
 // Module Construction
 Module* module = new Module(output_filename, Context);
 LLVMContext& C = module->getContext();
 module->setDataLayout("");
 module->setTargetTriple("x86_64-pc-linux-gnu");
 // Type Definitions
 std::vector<Type*>FuncTy_0_args;
 PointerType* PointerTy_1 = PointerType::get(IntegerType::get(module->getContext(), 32), 0);
 PointerType* PointerTy_2 = PointerType::get(IntegerType::get(module->getContext(), 8), 0);
 PointerTy_1->dump();
 PointerTy_2->dump();
 if (PointerTy_1 == PointerTy_2) {
	printf("Match\n");
 }
 IntegerType* IntegerTy_1 = IntegerType::get(module->getContext(), 32);
 // Constant Definitions
 ConstantInt* const_int64_1 = ConstantInt::get(C, APInt(64, StringRef("10"), 10));
// PointerType* const_ptr_int64_1 = PointerType::get(ConstantInt::get(C, APInt(64, StringRef("10"), 10)));
 Value* const_ptr_int64_1 = ConstantExpr::getIntToPtr(
		     const_int64_1 , PointerTy_1);
 ConstantInt* const_int64_2 = ConstantInt::get(C, APInt(64, StringRef("20"), 20));
// This creates the i8* type
//PointerType* PointerTy = PointerType::get(IntegerType::get(mod->getContext(), 8), 0);
// This creates the i8** type
//PointerType* PointerPtrTy = PointerType::get(PointerTy, 0); 
 // Create the first args. Note: Name added later after Function* created.
FuncTy_0_args.push_back(PointerTy_1); // First arg
//std::cout << FuncTy_0_args[0] << "\n";


FuncTy_0_args.push_back(IntegerType::get(module->getContext(), 32)); // Second arg
//FuncTy_0_args[0]->dump();
//FuncTy_0_args[1]->dump();

 FunctionType* FuncTy_0 = FunctionType::get(
 /*Result=*/IntegerType::get(module->getContext(), 32),
 /*Params=*/FuncTy_0_args,
 /*isVarArg=*/false);
 
// PointerType* PointerTy_2 = PointerType::get(PointerTy_1, 0);

// Global Variables
 GlobalVariable* gvar_ptr_mem = new GlobalVariable(/*Module=*/*module,
 /*Type=*/PointerTy_1,
 /*isConstant=*/false,
 /*Linkage=*/GlobalValue::ExternalLinkage,
 /*Initializer=*/0,
 /*Name=*/"mem");
 //gvar_ptr_mem->setAlignment(8);

 GlobalVariable* gvar_ptr_mem2 = new GlobalVariable(/*Module=*/*module,
 /*Type=*/PointerTy_1,
 /*isConstant=*/false,
 /*Linkage=*/GlobalValue::ExternalLinkage,
 /*Initializer=*/0,
 /*Name=*/"mem2");
 gvar_ptr_mem2->setAlignment(4);
 
 ConstantInt* int64_1 = ConstantInt::get(IntegerType::get(module->getContext(), 32), 0x123);
 GlobalVariable* gvar_ptr_mem3 = new GlobalVariable(/*Module=*/*module,
 /*Type=*/IntegerTy_1,
 /*isConstant=*/false,
 /*Linkage=*/GlobalValue::InternalLinkage,
 /*Initializer=*/int64_1,
 /*Name=*/"mem3");
 gvar_ptr_mem3->setAlignment(4);
// ConstantInt* int64_1 = ConstantInt::get(IntegerType::get(module->getContext(), 32), 0x123);
// gvar_ptr_mem3->setInitializer(int64_1); 
 
 
 // Function Declarations

//define void @test0()
 Function* test0_func = cast<Function>(module->
   getOrInsertFunction("test0", FuncTy_0));
 IRBuilder<> *builder = new IRBuilder<>(BasicBlock::Create(C, "label0", test0_func));
 BasicBlock* bb0 = builder->GetInsertBlock();
 

 Function::arg_iterator AI = test0_func->arg_begin();
 AI->setName("Pointer_1");
// AllocaInst *Alloca = CreateEntryBlockAlloca(F, Args[Idx]);
 AllocaInst *Alloca1 = builder->CreateAlloca(PointerTy_1, 0, "Pointer_2");
 AllocaInst *Alloca2 = builder->CreateAlloca(IntegerType::get(module->getContext(), 32), 0, "Int_2");
 // Store the initial value into the alloca.
 Value* ptr_1 = &*AI;
//builder->CreateStore(AI, Alloca);
// AI->dump();
 AI++;
 AI->setName("Int32_1");
 Value* int32_1 = &*AI;
// Alloca = builder->CreateAlloca(PointerTy_1, 0, "Pointer_2");
// Value* ptr_2 = builder->CreateStore(&*AI, Alloca);


// AllocaInst* ptr_5 = builder->CreateAlloca(PointerTy_1);
// Value *gep_inst = GetElementPtrInst::Create(STy, ptr_fred2, const_int32_3, "gep1", label_4);
 //ret void
// LoadInst* ptr_5 = builder->CreateLoad(gvar_ptr_mem, "ptr_5");
// Value* ptr_5 = builder->CreateAlignedLoad(gvar_ptr_mem, 8, "ptr_5");
 Value* ptr_5 = builder->CreateLoad(gvar_ptr_mem, "ptr_5");
//  ptr_5->setAlignment(8);
 Value* ptr_6 = builder->CreateGEP(ptr_1, ConstantInt::get(C, APInt(32, 2)), "ptr_6");
 Value* ptr_7 = builder->CreateGEP(const_ptr_int64_1, const_int64_2, "ptr_7");
 Value* int_6 = builder->CreateAlignedLoad(ptr_6, 8, "int_6");
 Value* int_7 = builder->CreateAlignedLoad(ptr_7, 8, "int_7");

//  GetElementPtrInst* ptr_6 = GetElementPtrInst::Create(IntegerType::get(mod->getContext(), 32), ptr_5, {
//   const_int64_3
//  }, "", label_4);
// Value* cond1 = builder->CreateICmpEQ(ConstantInt::get(C, APInt(32, 1)), ConstantInt::get(C, APInt(32, 2)), "cond1");
// Value* cond1 = builder->CreateICmpEQ(ConstantInt::get(C, APInt(32,1)), int_6, "cond1");
 Value* cond1 = builder->CreateICmpEQ(int_6, int_7, "cond1");
 BasicBlock *bb1 = BasicBlock::Create(C, "label1", test0_func);
 BasicBlock *bb2 = BasicBlock::Create(C, "label2", test0_func);
 BasicBlock *bb3 = BasicBlock::Create(C, "label3", test0_func);
 builder->CreateCondBr(cond1, bb1, bb2);
 builder->SetInsertPoint(bb1);
 Value* ptr_5_1 = builder->CreateGEP(ptr_5, ConstantInt::get(C, APInt(32, 1)), "ptr_5_1");
 builder->CreateBr(bb3);
 builder->SetInsertPoint(bb2);
 Value* ptr_5_2 = builder->CreateGEP(ptr_5, ConstantInt::get(C, APInt(32, 2)), "ptr_5_2");
 builder->CreateBr(bb3);

 builder->SetInsertPoint(bb3);
 PHINode *phi_0 = builder->CreatePHI(PointerTy_1, 2, "ptr_8");
 phi_0->addIncoming(ptr_5_1, bb1);
 phi_0->addIncoming(ptr_5_2, bb2);
 Value* ptr_10 = phi_0;

 Value* ret = builder->CreateRet(int32_1);
// Value* ret = builder->CreateRetVoid();

// ReturnInst::Create(C, bb);

#if 0 
// Function* func_test0 = module->getFunction("test0");
// if (!func_test0) {
// func_test0 = Function::Create(
  /*Type=*/FuncTy_0,
  /*Linkage=*/GlobalValue::ExternalLinkage,
  /*Name=*/"test0", module); 
// func_test0->setCallingConv(CallingConv::C);
// }
 AttributeSet func_test0_PAL;
 {
  SmallVector<AttributeSet, 4> Attrs;
  AttributeSet PAS;
   {
    AttrBuilder B;
    B.addAttribute(Attribute::NoUnwind);
    B.addAttribute(Attribute::UWTable);
    PAS = AttributeSet::get(module->getContext(), ~0U, B);
   }
  
  Attrs.push_back(PAS);
  func_test0_PAL = AttributeSet::get(module->getContext(), Attrs);
  
 }
 func_test0->setAttributes(func_test0_PAL);
 
 // Global Variable Declarations

 
 // Constant Definitions
 ConstantInt* const_int32_3 = ConstantInt::get(module->getContext(), APInt(32, StringRef("1"), 10));
 
 // Global Variable Definitions
 
 // Function Definitions
 
 // Function: test0 (func_test0)
 {
  Function::arg_iterator args = func_test0->arg_begin();
  Value* ptr_fred = &*args;
  args++;
  ptr_fred->setName("fred");
  
  BasicBlock* label_4 = BasicBlock::Create(module->getContext(), "",func_test0,0);
  
  // Block  (label_4)
  AllocaInst* ptr_5 = new AllocaInst(PointerTy_1, "", label_4);
  ptr_5->setAlignment(8);
  AllocaInst* ptr_fred1 = new AllocaInst(IntegerType::get(module->getContext(), 32), "fred1", label_4);
  ptr_fred1->setAlignment(4);
  AllocaInst* ptr_fred2 = new AllocaInst(PointerTy_1, "fred2", label_4);
  ptr_fred2->setAlignment(8);
  LoadInst* int32_15 = new LoadInst(ptr_fred1, "", false, label_4);
  int32_15->setAlignment(4);
  //tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
  //dstA = GetElementPtrInst::Create(srcA, srcB, buffer, bb[node]);
  //         Type *AgTy = cast<PointerType>(I->getType())->getElementType();
  //         StructType *STy = cast<StructType>(AgTy);
  //         Value *Idx = GetElementPtrInst::Create(
  //                        STy, *AI, Idxs, (*AI)->getName() + "." + Twine(i), Call);

  //dstA = GetElementPtrInst::Create(STy, srcA, srcB, buffer, bb[node]);
  Type *AgTy = cast<PointerType>(const_int32_3->getType())->getElementType();
  StructType *STy = cast<StructType>(AgTy);
  Value *gep_inst = GetElementPtrInst::Create(STy, ptr_fred2, const_int32_3, "gep1", label_4);
  // FIXME: JCD must get GEP working. 
  ReturnInst::Create(module->getContext(), int32_15, label_4);
#endif 
 
 return module;
}
