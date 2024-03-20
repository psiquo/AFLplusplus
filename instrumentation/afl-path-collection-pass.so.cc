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
#include <map>
#include <vector>
#include <sstream>

#include "afl-llvm-common.h"

using namespace llvm;

namespace {

#if LLVM_MAJOR >= 11  
class PathCollection : public PassInfoMixin<PathCollection> {
  public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
    static bool isRequired() {return true;} 
#else 
  class PathCollection : public ModulePass {
    public: 
      static char ID;
      PathCollection() : ModulePass(ID) {}
      bool runOnModule(Module &M)
#endif
  };
}

std::vector<std::string>* split_string(std::string s,char delim) {
  std::vector<std::string> *ret = new std::vector<std::string>();

  std::stringstream stream(s);
  std::string token;

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

#if LLVM_VERSION_MAJOR >= 11  
  PreservedAnalyses path_collection_instrument_line(Module &M, std::string line){
#else
  bool path_collection_instrument_line(Module &M, std::string line){
#endif
  std::map<std::string, int> built_map;
  std::string matched;

  for(Function &F : M.getFunctionList()) {
      for(BasicBlock &BB : F.getBasicBlockList()) {
        for (Instruction &inst : BB.getInstList()){
          matched = "";
          if(DILocation *Loc = inst.getDebugLoc().get()){

            std::string loc_s =  std::string(std::string(Loc->getDirectory())) + std::string("/") + std::string(Loc->getFilename().data()) 
                + std::string(":") + std::to_string(Loc->getLine());
    		
            //if(!std::string(F.getName()).compare("parseCodeSection"))	    
	          //errs() << F.getName() << ":" << inst << "\t" << loc_s << "\n"; 
            bool t = false;
            for(std::string l : *split_string(line,'@')){
              //errs() << "Looking for " << l << "\n";
              if(loc_s.length() >= l.length() && loc_s.compare(loc_s.length() - l.length(), l.length(),l) == 0){
                matched = l;
                t = true;
                break;
              }
            }

            if(!t){
              continue;
            }
            
            if(!built_map[matched]){
              errs() << "Found: " << inst << " " + loc_s << "\n" << "Adding path instrumentation\n";

              IRBuilder<> assertBuilder(&inst);
              FunctionCallee fn = M.getOrInsertFunction("__dump_path_collection",
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
#else
char PathCollection::ID = 0;
static RegisterPass<PathCollection>
  X(/*PassArg=*/"PathCollection", /*Name=*/"PathCollection",/*CFGOnly=*/false, /*is_analysis=*/false);

#endif



#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  PreservedAnalyses PathCollection::run(Module &M, ModuleAnalysisManager &MAM){
#else
  bool PathCollection::runOnModule(Module &M){
#endif
    char *instr_line = getenv("AFL_CODE_DUMP");

    if (instr_line == NULL){
      #if LLVM_VERSION_MAJOR >= 11  
        return PreservedAnalyses::all();
      #else
        return true;
      #endif
    }

    return path_collection_instrument_line(M,instr_line);
}

