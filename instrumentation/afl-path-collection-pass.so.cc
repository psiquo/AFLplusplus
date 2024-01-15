//===-- HelloWorld.cpp - Example Transformations --------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Utils/HelloWorld.h"
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

class PathCollection : public PassInfoMixin<PathCollection> {
  public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
    static bool isRequired() {return true;} 
  };
}

PreservedAnalyses path_collection_instrument_line(Module &M, std::string line){
  bool build = false;
  for(Function &F : M.getFunctionList()) {
      for(BasicBlock &BB : F.getBasicBlockList()) {
        for (Instruction &inst : BB.getInstList()){
          if(DILocation *Loc = inst.getDebugLoc().get()){

            std::string loc_s =  std::string(std::string(Loc->getDirectory())) + std::string("/") + std::string(Loc->getFilename().data()) 
                + std::string(":") + std::to_string(Loc->getLine());
    		
            //if(!std::string(F.getName()).compare("parseCodeSection"))	    
	          // errs() << F.getName() << ":" << inst << "\t" << loc_s << "\n"; 
            if(loc_s.find(line) == std::string::npos)
              continue;
            
            if(!build){
              errs() << "Found: " << inst << " " + loc_s << "\n" << "Adding instumentation\n";

              IRBuilder<> assertBuilder(&inst);
              FunctionCallee fn = M.getOrInsertFunction("__dump_path_collection",
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

  return {LLVM_PLUGIN_API_VERSION, "PathCollection", "v0.1",
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

                  MPM.addPass(PathCollection());

                });

          }};

}

PreservedAnalyses PathCollection::run(Module &M, ModuleAnalysisManager &MAM) {
    char *instr_line = getenv("AFL_CODE_DUMP");

    if (instr_line == NULL){
        return PreservedAnalyses::all();
    }

    return path_collection_instrument_line(M,instr_line);
}

