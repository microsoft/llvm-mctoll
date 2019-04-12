//===-- ARMModuleRaiser.cpp -------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ARMModuleRaiser.h"
#include "llvm/Object/ELFObjectFile.h"

using namespace llvm;

namespace RaiserContext {
extern SmallVector<ModuleRaiser *, 4> ModuleRaiserRegistry;
}

bool ARMModuleRaiser::collectDynamicRelocations() {
  if (!Obj->isELF()) {
    return false;
  }

  const ELF32LEObjectFile *Elf32LEObjFile = dyn_cast<ELF32LEObjectFile>(Obj);
  if (!Elf32LEObjFile) {
    return false;
  }

  std::vector<SectionRef> DynRelSec = Obj->dynamic_relocation_sections();

  for (const SectionRef &Section : DynRelSec) {
    for (const RelocationRef &Reloc : Section.relocations()) {
      DynRelocs.push_back(Reloc);
    }
  }

  // Get relocations of .got.plt section from .rela.plt if it exists. I do not
  // see an API in ObjectFile class to get at these.

  // Find .got.plt and .rel.plt sections Note: A lot of verification and double
  // checking done in the following code.
  const ELFFile<ELF32LE> *ElfFile = Elf32LEObjFile->getELFFile();
  // Find .rel.plt
  SectionRef DotGotDotPltSec, DotRelaDotPltSec;
  for (const SectionRef Section : Obj->sections()) {
    StringRef SecName;
    Section.getName(SecName);
    if (SecName.equals(".rel.plt")) {
      DotRelaDotPltSec = Section;
    } else if (SecName.equals(".got")) {
      DotGotDotPltSec = Section;
    }
  }

  if (DotRelaDotPltSec.getObject() != nullptr) {
    // Do some additional sanity checks
    assert((DotGotDotPltSec.getObject() != nullptr) &&
           "Failed to find .got section");
    auto DotRelaDotPltShdr = ElfFile->getSection(DotRelaDotPltSec.getIndex());
    assert(DotRelaDotPltShdr && "Failed to find .rel.plt section");
    for (const RelocationRef &Reloc : DotRelaDotPltSec.relocations()) {
      DynRelocs.push_back(Reloc);
    }
  }
  return true;
}

#ifdef __cplusplus
extern "C" {
#endif

void InitializeARMModuleRaiser() {
  ModuleRaiser *m = new ARMModuleRaiser();
  RaiserContext::ModuleRaiserRegistry.push_back(m);
  return;
}

#ifdef __cplusplus
}
#endif
