//===-- HelloWorld.cpp - Example Transformations --------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif

#include <fstream>
#include <iostream>
#include<unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <map>

#include "afl-llvm-common.h"

using namespace llvm;

namespace {

#if LLVM_MAJOR >= 11  
class BranchComplexityPass : public PassInfoMixin<BranchComplexityPass> {
  public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
    static bool isRequired() {return true;} 
  
#else 
class BranchComplexityPass : public ModulePass {
    public: 
      static char ID;
      BranchComplexityPass() : ModulePass(ID) {}
      bool runOnModule(Module &M);
#endif
  };
}

std::vector<std::string>* split_string(std::string s,char delim) {
  std::vector<std::string> *ret = new std::vector<std::string>();

  if(s.find("@") != std::string::npos){
    std::stringstream stream(s);
    std::string token;

    while(std::getline(stream,token,delim))
      ret->push_back(token);
  } else{
    ret->push_back(s);
  }

  return ret;
}

//PreservedAnalyses branch_complexity_instrument_line(Module &M, std::string line){
#if LLVM_VERSION_MAJOR >= 11  
  PreservedAnalyses branch_complexity_instrument_line(Module &M, std::string line){
#else
  bool branch_complexity_instrument_line(Module &M, std::string line){
#endif
  std::map<std::string, int> built_map;
  std::string matched;

  for(Function &F : M.getFunctionList()) {
      // errs() << "In function " << F.getName() << "\n";
      for(BasicBlock &BB : F.getBasicBlockList()) {
        for (Instruction &inst : BB.getInstList()){
          matched = "";
          if(DILocation *Loc = inst.getDebugLoc().get()){

            std::string loc_s =  std::string(std::string(Loc->getDirectory())) + std::string("/") + std::string(Loc->getFilename().data()) 
                + std::string(":") + std::to_string(Loc->getLine());
            
            if (getenv("AFL_DEBUG")){
              errs() << "In  " << inst << " " + loc_s << "\n";
            }

            bool t = false;
          
            for(std::string l : *split_string(line,'@')){
              // errs() << "Searching " << l << " in " << loc_s << "\n";
              if(loc_s.length() >= l.length() && loc_s.compare(loc_s.length() - l.length(), l.length(),l) == 0){
                matched = l;
                t = true;
                break;
              }
            }

            if(!t){
              continue;
            }

            // if(loc_s.find(line) == std::string::npos)
            //   continue;

            if(!built_map[matched]){
              errs() << "Found: " << inst << " " + loc_s << "\n" << "Adding instumentation\n";

              IRBuilder<> assertBuilder(&inst);
              FunctionCallee fn = M.getOrInsertFunction("abort",
                                                    FunctionType::getVoidTy(M.getContext()));
              assertBuilder.CreateCall(fn,ArrayRef<Value *>({}));
              built_map[matched] = true;
            }
          }
        }
      }
  }
  #if LLVM_VERSION_MAJOR >= 11  
        return PreservedAnalyses::all();
  #else
        return true;
  #endif
}

#if LLVM_MAJOR >= 11
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "BranchComplexityPass", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

#if LLVM_VERSION_MAJOR == 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
#if LLVM_VERSION_MAJOR >= 16
            PB.registerOptimizerEarlyEPCallback(
#else
            PB.registerOptimizerLastEPCallback(
#endif
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(BranchComplexityPass());

                });

          }};

}
#else
static void registerBranchComplexityPass(const PassManagerBuilder &,
                                     legacy::PassManagerBase &PM) {

  PM.add(new BranchComplexityPass());
}

char BranchComplexityPass::ID = 0;
static RegisterPass<BranchComplexityPass>
  X(/*PassArg=*/"BranchComplexityPass", /*Name=*/"BranchComplexityPass",/*CFGOnly=*/false, /*is_analysis=*/false);

static RegisterStandardPasses RegisterBranchComplexityPass(
    PassManagerBuilder::EP_OptimizerLast, registerBranchComplexityPass);

static RegisterStandardPasses RegisterBranchComplexityPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerBranchComplexityPass);
#endif

//PreservedAnalyses BranchComplexityPass::run(Module &M, ModuleAnalysisManager &MAM) {
#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  PreservedAnalyses BranchComplexityPass::run(Module &M, ModuleAnalysisManager &MAM){
#else
  bool BranchComplexityPass::runOnModule(Module &M){
#endif
    char *instr_line = getenv("AFL_BRANCH_LINE");

    if (instr_line == NULL){
        #if LLVM_VERSION_MAJOR >= 11  
          return PreservedAnalyses::all();
        #else
          return true;
        #endif
    }

    
        //instr_line.erase(instr_line.find_last_not_of("\n"));
    return branch_complexity_instrument_line(M,instr_line);
}

