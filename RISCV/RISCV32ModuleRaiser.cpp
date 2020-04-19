//===-- RISCV32ModuleRaiser.cpp -------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of RISCV32ModuleRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "RISCV32ModuleRaiser.h"
#include "llvm/Object/ELFObjectFile.h"

using namespace llvm;

namespace RaiserContext {
extern SmallVector<ModuleRaiser *, 4> ModuleRaiserRegistry;
}

bool RISCV32ModuleRaiser::collectDynamicRelocations() {
  if (!Obj->isELF())
    return false;

  const ELF32LEObjectFile *Elf32LEObjFile = dyn_cast<ELF32LEObjectFile>(Obj);
  if (!Elf32LEObjFile)
    return false;

  // Collect all relocation records from various relocation sections
  std::vector<SectionRef> DynRelSec = Obj->dynamic_relocation_sections();
  for (const SectionRef &Section : DynRelSec)
    for (const RelocationRef &Reloc : Section.relocations())
      DynRelocs.push_back(Reloc);

  return true;
}

#ifdef __cplusplus
extern "C" {
#endif

void InitializeRISCV32ModuleRaiser() {
  ModuleRaiser *m = new RISCV32ModuleRaiser();
  RaiserContext::ModuleRaiserRegistry.push_back(m);
}

#ifdef __cplusplus
}
#endif
