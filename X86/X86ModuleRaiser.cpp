//===-- X86ModuleRaiser.cpp -------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of X86ModuleRaiser class for use by
// llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "X86ModuleRaiser.h"
#include "llvm/Object/ELFObjectFile.h"

using namespace llvm;

namespace RaiserContext {
extern SmallVector<ModuleRaiser *, 4> ModuleRaiserRegistry;
}

bool X86ModuleRaiser::collectDynamicRelocations() {
  if (!Obj->isELF())
    return false;

  const ELF64LEObjectFile *Elf64LEObjFile = dyn_cast<ELF64LEObjectFile>(Obj);
  if (!Elf64LEObjFile)
    return false;

  std::vector<SectionRef> DynRelSec = Obj->dynamic_relocation_sections();
  for (const SectionRef &Section : DynRelSec)
    for (const RelocationRef &Reloc : Section.relocations())
      DynRelocs.push_back(Reloc);

  // Find .got.plt and .rela.plt sections
  const ELFFile<ELF64LE> *ElfFile = Elf64LEObjFile->getELFFile();
  SectionRef DotGotDotPltSec, DotRelaDotPltSec;
  for (const SectionRef Section : Obj->sections()) {
    StringRef SecName;
    if (auto NameOrErr = Section.getName())
      SecName = *NameOrErr;
    else {
      consumeError(NameOrErr.takeError());
      continue;
    }

    if (SecName.equals(".rela.plt"))
      DotRelaDotPltSec = Section;
    else if (SecName.equals(".got.plt"))
      DotGotDotPltSec = Section;
  }

  if (!DotRelaDotPltSec.getObject() || !DotGotDotPltSec.getObject())
    return false;

  // Perform some sanity checks
  if (auto DotRelaDotPltShdr =
          ElfFile->getSection(DotRelaDotPltSec.getIndex())) {
    assert((DotRelaDotPltShdr.get()->sh_info == DotGotDotPltSec.getIndex()) &&
           ".rela.plt does not refer .got.plt section");
    assert((DotRelaDotPltShdr.get()->sh_type == ELF::SHT_RELA) &&
           "Unexpected type of section .rela.plt");
  }

  // If the binary has .got.plt section, read the dynamic relocations.
  for (const RelocationRef &Reloc : DotRelaDotPltSec.relocations())
    DynRelocs.push_back(Reloc);

  return true;
}

#ifdef __cplusplus
extern "C" {
#endif

void InitializeX86ModuleRaiser() {
  ModuleRaiser *m = new X86ModuleRaiser();
  RaiserContext::ModuleRaiserRegistry.push_back(m);
}

#ifdef __cplusplus
}
#endif
