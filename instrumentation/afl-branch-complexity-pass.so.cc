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
#include <string>
#include <vector>
#include <sstream>
#include <map>

#include "afl-llvm-common.h"

using namespace llvm;

namespace {

class BranchComplexityPass : public PassInfoMixin<BranchComplexityPass> {
  public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
    static bool isRequired() {return true;} 
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

PreservedAnalyses branch_complexity_instrument_line(Module &M, std::string line){
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
            
            // errs() << "In  " << inst << " " + loc_s << "\n";
            
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

    // char *file_path = getenv("OSS_FUZZ_FILE_PATH");

    std::ifstream instrFile;

    //errs() << "Given instrumentation path: " << file_path << "\n";
    // errs() << "DIRLOC: ";
    // system("pwd");
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
        //instr_line.erase(instr_line.find_last_not_of("\n"));
        ret = branch_complexity_instrument_line(M,instr_line);
      }
    }

    instrFile.close();
    return ret;
}

