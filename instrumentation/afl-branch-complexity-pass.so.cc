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
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"

#include <fstream>
#include <iostream>
#include<unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <cstring>

#include "afl-llvm-common.h"

using namespace llvm;

namespace {

class BranchComplexityPass : public PassInfoMixin<BranchComplexityPass> {
  public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
    static bool isRequired() {return true;} 
  };
}

PreservedAnalyses branch_complexity_instrument_line(Module &M, std::string line){
  for(Function &F : M.getFunctionList()) {
      bool build = false;
      for(BasicBlock &BB : F.getBasicBlockList()) {
        for (Instruction &inst : BB.getInstList()){
          if(DILocation *Loc = inst.getDebugLoc().get()){

            std::string loc_s =  std::string(std::string(Loc->getDirectory())) + std::string("/") + std::string(Loc->getFilename().data()) 
                + std::string(":") + std::to_string(Loc->getLine());
            
            if(loc_s.find(line) == std::string::npos)
              continue;
            
            if(!build){
              errs() << "Found: " << inst << " " + loc_s << "\n" << "Adding instumentation\n";

              IRBuilder<> assertBuilder(&inst);
              FunctionCallee fn = M.getOrInsertFunction("abort",
                                                    FunctionType::getVoidTy(M.getContext()));
              assertBuilder.CreateCall(fn,ArrayRef<Value *>({}));
              build = true;
            }
          }
        }
      }
  }
  return PreservedAnalyses::all();
}

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

PreservedAnalyses BranchComplexityPass::run(Module &M, ModuleAnalysisManager &MAM) {
    char *issue = getenv("OSS_FUZZ_ISSUE");
    char *file_url = getenv("OSS_FUZZ_URL");
    char *enable = getenv("OSS_FUZZ_BRANCH_COMPLEXITY");

    if (enable == NULL){
        return PreservedAnalyses::all();
    }

    std::ifstream instrFile;

    instrFile.open("instr_list.txt", std::ios::in);

    if(issue == NULL || (file_url == NULL && ! instrFile.is_open())){
      errs() << "Insufficient information given for the instrumentation\n";
      return PreservedAnalyses::all();
    }


    if(!instrFile.is_open()){

      pid_t pid = fork();

      if(pid != 0){
        waitpid(pid,NULL,0);
      } else {
        execl("/usr/bin/curl","curl","-o","instr_list.txt",file_url,NULL);
      } 

      instrFile.open("instr_list.txt", std::ios::in);
    }
    
    std::string line;
    PreservedAnalyses ret;
    while(std::getline(instrFile,line)) {
      if(line.rfind(issue,0) == 0){
        std::string instr_line = line.substr(line.find(" ") + 1);
        instr_line.erase(instr_line.find_last_not_of("\n"));
        ret = branch_complexity_instrument_line(M,instr_line);
      }
    }

    instrFile.close();
    return ret;
}

