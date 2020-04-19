//===-- RISCV64ModuleRaiser.cpp -------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of RISCV64ModuleRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "RISCV64ModuleRaiser.h"
#include "llvm/Object/ELFObjectFile.h"

using namespace llvm;

namespace RaiserContext {
extern SmallVector<ModuleRaiser *, 4> ModuleRaiserRegistry;
}

bool RISCV64ModuleRaiser::collectDynamicRelocations() {
  if (!Obj->isELF())
    return false;

  const ELF64LEObjectFile *Elf64LEObjFile = dyn_cast<ELF64LEObjectFile>(Obj);
  if (!Elf64LEObjFile)
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

void InitializeRISCV64ModuleRaiser() {
  ModuleRaiser *m = new RISCV64ModuleRaiser();
  RaiserContext::ModuleRaiserRegistry.push_back(m);
}

#ifdef __cplusplus
}
#endif
