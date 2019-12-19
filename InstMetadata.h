//===----------- InstMetadata.h ---------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declarations of all Metadata intended to be associated
// with various instructions during the process of raising binaries using
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#ifndef TOOLS_LLVM_MCTOLL_INSTMETADATA_H_
#define TOOLS_LLVM_MCTOLL_INSTMETADATA_H_

#define RODATA_INDEX_MD_STR "ROData_Index"
#define RODATA_CONTENT_MD_STR "ROData_Content"
#define RODATA_SEC_INFO_MD_STR "ROData_SecInfo"

#include "llvm/IR/Instruction.h"
namespace mctoll {
static bool hasRODataAccess(Instruction *I) {
  return (I->hasMetadata(RODATA_INDEX_MD_STR) ||
          I->hasMetadata(RODATA_CONTENT_MD_STR));
}
} // namespace mctoll
#endif /* TOOLS_LLVM_MCTOLL_INSTMETADATA_H_ */
