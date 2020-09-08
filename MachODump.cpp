//===-- MachODump.cpp - Object file dumping utility for llvm --------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements the MachO-specific dumper for llvm-mctoll.
//
//===----------------------------------------------------------------------===//

#include "llvm-mctoll.h"
#include "llvm-c/Disassembler.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/Triple.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/Config/config.h"
#include "llvm/DebugInfo/DIContext.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/MC/MCTargetOptions.h"
#include "llvm/Object/MachO.h"
#include "llvm/Object/MachOUniversal.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/GraphWriter.h"
#include "llvm/Support/LEB128.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cstring>
#include <system_error>

#ifdef HAVE_LIBXAR
extern "C" {
#include <xar/xar.h>
}
#endif

using namespace llvm;
using namespace object;

extern cl::opt<std::string> MCPU;
extern cl::list<std::string> MAttrs;

static cl::opt<bool>
    UseDbg("g",
           cl::desc("Print line information from debug info if available"));

static cl::opt<std::string> DSYMFile("dsym",
                                     cl::desc("Use .dSYM file for debug info"));

static cl::opt<bool> FullLeadingAddr("full-leading-addr",
                                     cl::desc("Print full leading address"));

static cl::opt<bool> NoLeadingHeaders("no-leading-headers",
                                      cl::desc("Print no leading headers"));
cl::opt<bool>
    ArchiveMemberOffsets("archive-member-offsets",
                         cl::desc("Print the offset to each archive member for "
                                  "Mach-O archives (requires -macho and "
                                  "-archive-headers)"));

cl::opt<bool>
    llvm::NonVerbose("non-verbose",
                     cl::desc("Print the info for Mach-O objects in "
                              "non-verbose or numeric form (requires -macho)"));

cl::opt<std::string> llvm::DisSymName(
    "dis-symname",
    cl::desc("disassemble just this symbol's instructions (requires -macho)"));

static cl::opt<bool> NoSymbolicOperands(
    "no-symbolic-operands",
    cl::desc("do not symbolic operands when disassembling (requires -macho)"));

static cl::list<std::string>
    ArchFlags("arch", cl::desc("architecture(s) from a Mach-O file to dump"),
              cl::ZeroOrMore);

bool ArchAll = false;

static std::string ThumbTripleName;

static const Target *GetTarget(const MachOObjectFile *MachOObj,
                               const char **McpuDefault,
                               const Target **ThumbTarget) {
  // Figure out the target triple.
  llvm::Triple TT(TripleName);
  if (TripleName.empty()) {
    TT = MachOObj->getArchTriple(McpuDefault);
    TripleName = TT.str();
  }

  if (TT.getArch() == Triple::arm) {
    // We've inferred a 32-bit ARM target from the object file. All MachO CPUs
    // that support ARM are also capable of Thumb mode.
    llvm::Triple ThumbTriple = TT;
    std::string ThumbName = (Twine("thumb") + TT.getArchName().substr(3)).str();
    ThumbTriple.setArchName(ThumbName);
    ThumbTripleName = ThumbTriple.str();
  }

  // Get the target specific parser.
  std::string Error;
  const Target *TheTarget = TargetRegistry::lookupTarget(TripleName, Error);
  if (TheTarget && ThumbTripleName.empty())
    return TheTarget;

  *ThumbTarget = TargetRegistry::lookupTarget(ThumbTripleName, Error);
  if (*ThumbTarget)
    return TheTarget;

  errs() << "llvm-mctoll: error: unable to get target for '";
  if (!TheTarget)
    errs() << TripleName;
  else
    errs() << ThumbTripleName;
  errs() << "', see --version and --triple.\n";
  return nullptr;
}

struct SymbolSorter {
  bool operator()(const SymbolRef &A, const SymbolRef &B) {
    Expected<SymbolRef::Type> ATypeOrErr = A.getType();
    if (!ATypeOrErr)
      report_error(ATypeOrErr.takeError(), A.getObject()->getFileName());

    SymbolRef::Type AType = *ATypeOrErr;
    Expected<SymbolRef::Type> BTypeOrErr = B.getType();
    if (!BTypeOrErr)
      report_error(BTypeOrErr.takeError(), B.getObject()->getFileName());
    SymbolRef::Type BType = *BTypeOrErr;
    auto ASymOrErr = A.getValue();
    if (!ASymOrErr)
      report_error(ASymOrErr.takeError(), A.getObject()->getFileName());
    auto BSymOrErr = B.getValue();
    if (!BSymOrErr)
      report_error(BSymOrErr.takeError(), B.getObject()->getFileName());
    uint64_t AAddr = (AType != SymbolRef::ST_Function) ? 0 : *ASymOrErr;
    uint64_t BAddr = (BType != SymbolRef::ST_Function) ? 0 : *BSymOrErr;
    return AAddr < BAddr;
  }
};

// Types for the storted data in code table that is built before disassembly
// and the predicate function to sort them.
typedef std::pair<uint64_t, DiceRef> DiceTableEntry;
typedef std::vector<DiceTableEntry> DiceTable;
typedef DiceTable::iterator dice_table_iterator;

// This is used to search for a data in code table entry for the PC being
// disassembled.  The j parameter has the PC in j.first.  A single data in code
// table entry can cover many bytes for each of its Kind's.  So if the offset,
// aka the i.first value, of the data in code table entry plus its Length
// covers the PC being searched for this will return true.  If not it will
// return false.
static bool compareDiceTableEntries(const DiceTableEntry &i,
                                    const DiceTableEntry &j) {
  uint16_t Length;
  i.second.getLength(Length);

  return j.first >= i.first && j.first < i.first + Length;
}

static uint64_t DumpDataInCode(const uint8_t *bytes, uint64_t Length,
                               unsigned short Kind) {
  uint32_t Value, Size = 1;

  switch (Kind) {
  default:
  case MachO::DICE_KIND_DATA:
    if (Length >= 4) {
      dumpBytes(makeArrayRef(bytes, 4), outs());
      Value = bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0];
      outs() << "\t.long " << Value;
      Size = 4;
    } else if (Length >= 2) {
      dumpBytes(makeArrayRef(bytes, 2), outs());
      Value = bytes[1] << 8 | bytes[0];
      outs() << "\t.short " << Value;
      Size = 2;
    } else {
      dumpBytes(makeArrayRef(bytes, 2), outs());
      Value = bytes[0];
      outs() << "\t.byte " << Value;
      Size = 1;
    }
    if (Kind == MachO::DICE_KIND_DATA)
      outs() << "\t@ KIND_DATA\n";
    else
      outs() << "\t@ data in code kind = " << Kind << "\n";
    break;
  case MachO::DICE_KIND_JUMP_TABLE8:
    dumpBytes(makeArrayRef(bytes, 1), outs());
    Value = bytes[0];
    outs() << "\t.byte " << format("%3u", Value) << "\t@ KIND_JUMP_TABLE8\n";
    Size = 1;
    break;
  case MachO::DICE_KIND_JUMP_TABLE16:
    dumpBytes(makeArrayRef(bytes, 2), outs());
    Value = bytes[1] << 8 | bytes[0];
    outs() << "\t.short " << format("%5u", Value & 0xffff)
           << "\t@ KIND_JUMP_TABLE16\n";
    Size = 2;
    break;
  case MachO::DICE_KIND_JUMP_TABLE32:
  case MachO::DICE_KIND_ABS_JUMP_TABLE32:
    dumpBytes(makeArrayRef(bytes, 4), outs());
    Value = bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0];
    outs() << "\t.long " << Value;
    if (Kind == MachO::DICE_KIND_JUMP_TABLE32)
      outs() << "\t@ KIND_JUMP_TABLE32\n";
    else
      outs() << "\t@ KIND_ABS_JUMP_TABLE32\n";
    Size = 4;
    break;
  }
  return Size;
}

static void getSectionsAndSymbols(MachOObjectFile *MachOObj,
                                  std::vector<SectionRef> &Sections,
                                  std::vector<SymbolRef> &Symbols,
                                  SmallVectorImpl<uint64_t> &FoundFns,
                                  uint64_t &BaseSegmentAddress) {
  const StringRef FileName = MachOObj->getFileName();
  for (const SymbolRef &Symbol : MachOObj->symbols()) {
    StringRef SymName = unwrapOrError(Symbol.getName(), FileName);
    if (!SymName.startswith("ltmp"))
      Symbols.push_back(Symbol);
  }

  for (const SectionRef &Section : MachOObj->sections()) {
    StringRef SecName;
    if (auto NameOrErr = Section.getName())
      SecName = *NameOrErr;
    else
      consumeError(NameOrErr.takeError());
    Sections.push_back(Section);
  }

  bool BaseSegmentAddressSet = false;
  for (const auto &Command : MachOObj->load_commands()) {
    if (Command.C.cmd == MachO::LC_FUNCTION_STARTS) {
      // We found a function starts segment, parse the addresses for later
      // consumption.
      MachO::linkedit_data_command LLC =
          MachOObj->getLinkeditDataLoadCommand(Command);

      MachOObj->ReadULEB128s(LLC.dataoff, FoundFns);
    } else if (Command.C.cmd == MachO::LC_SEGMENT) {
      MachO::segment_command SLC = MachOObj->getSegmentLoadCommand(Command);
      StringRef SegName = SLC.segname;
      if (!BaseSegmentAddressSet && SegName != "__PAGEZERO") {
        BaseSegmentAddressSet = true;
        BaseSegmentAddress = SLC.vmaddr;
      }
    }
  }
}

typedef DenseMap<uint64_t, StringRef> SymbolAddressMap;

static void CreateSymbolAddressMap(MachOObjectFile *O,
                                   SymbolAddressMap *AddrMap) {
  // Create a map of symbol addresses to symbol names.
  const StringRef FileName = O->getFileName();
  for (const SymbolRef &Symbol : O->symbols()) {
    SymbolRef::Type ST = unwrapOrError(Symbol.getType(), FileName);
    if (ST == SymbolRef::ST_Function || ST == SymbolRef::ST_Data ||
        ST == SymbolRef::ST_Other) {
      auto SymOrErr = Symbol.getValue();
      if (!SymOrErr)
        report_error(SymOrErr.takeError(), Symbol.getObject()->getFileName());
      uint64_t Address = *SymOrErr;
      StringRef SymName = unwrapOrError(Symbol.getName(), FileName);
      if (!SymName.startswith(".objc"))
        (*AddrMap)[Address] = SymName;
    }
  }
}

// GuessSymbolName is passed the address of what might be a symbol and a
// pointer to the SymbolAddressMap.  It returns the name of a symbol
// with that address or nullptr if no symbol is found with that address.
static const char *GuessSymbolName(uint64_t value, SymbolAddressMap *AddrMap) {
  const char *SymbolName = nullptr;
  // A DenseMap can't lookup up some values.
  if (value != 0xffffffffffffffffULL && value != 0xfffffffffffffffeULL) {
    StringRef name = AddrMap->lookup(value);
    if (!name.empty())
      SymbolName = name.data();
  }
  return SymbolName;
}

static void DumpCstringChar(const char c) {
  char p[2];
  p[0] = c;
  p[1] = '\0';
  outs().write_escaped(p);
}

static void DumpCstringSection(MachOObjectFile *O, const char *sect,
                               uint32_t sect_size, uint64_t sect_addr,
                               bool print_addresses) {
  for (uint32_t i = 0; i < sect_size; i++) {
    if (print_addresses) {
      if (O->is64Bit())
        outs() << format("%016" PRIx64, sect_addr + i) << "  ";
      else
        outs() << format("%08" PRIx64, sect_addr + i) << "  ";
    }
    for (; i < sect_size && sect[i] != '\0'; i++)
      DumpCstringChar(sect[i]);
    if (i < sect_size && sect[i] == '\0')
      outs() << "\n";
  }
}

static void DumpLiteral4(uint32_t l, float f) {
  outs() << format("0x%08" PRIx32, l);
  if ((l & 0x7f800000) != 0x7f800000)
    outs() << format(" (%.16e)\n", f);
  else {
    if (l == 0x7f800000)
      outs() << " (+Infinity)\n";
    else if (l == 0xff800000)
      outs() << " (-Infinity)\n";
    else if ((l & 0x00400000) == 0x00400000)
      outs() << " (non-signaling Not-a-Number)\n";
    else
      outs() << " (signaling Not-a-Number)\n";
  }
}

static void DumpLiteral4Section(MachOObjectFile *O, const char *sect,
                                uint32_t sect_size, uint64_t sect_addr,
                                bool print_addresses) {
  for (uint32_t i = 0; i < sect_size; i += sizeof(float)) {
    if (print_addresses) {
      if (O->is64Bit())
        outs() << format("%016" PRIx64, sect_addr + i) << "  ";
      else
        outs() << format("%08" PRIx64, sect_addr + i) << "  ";
    }
    float f;
    memcpy(&f, sect + i, sizeof(float));
    if (O->isLittleEndian() != sys::IsLittleEndianHost)
      sys::swapByteOrder(f);
    uint32_t l;
    memcpy(&l, sect + i, sizeof(uint32_t));
    if (O->isLittleEndian() != sys::IsLittleEndianHost)
      sys::swapByteOrder(l);
    DumpLiteral4(l, f);
  }
}

static void DumpLiteral8(MachOObjectFile *O, uint32_t l0, uint32_t l1,
                         double d) {
  outs() << format("0x%08" PRIx32, l0) << " " << format("0x%08" PRIx32, l1);
  uint32_t Hi, Lo;
  Hi = (O->isLittleEndian()) ? l1 : l0;
  Lo = (O->isLittleEndian()) ? l0 : l1;

  // Hi is the high word, so this is equivalent to if(isfinite(d))
  if ((Hi & 0x7ff00000) != 0x7ff00000)
    outs() << format(" (%.16e)\n", d);
  else {
    if (Hi == 0x7ff00000 && Lo == 0)
      outs() << " (+Infinity)\n";
    else if (Hi == 0xfff00000 && Lo == 0)
      outs() << " (-Infinity)\n";
    else if ((Hi & 0x00080000) == 0x00080000)
      outs() << " (non-signaling Not-a-Number)\n";
    else
      outs() << " (signaling Not-a-Number)\n";
  }
}

static void DumpLiteral8Section(MachOObjectFile *O, const char *sect,
                                uint32_t sect_size, uint64_t sect_addr,
                                bool print_addresses) {
  for (uint32_t i = 0; i < sect_size; i += sizeof(double)) {
    if (print_addresses) {
      if (O->is64Bit())
        outs() << format("%016" PRIx64, sect_addr + i) << "  ";
      else
        outs() << format("%08" PRIx64, sect_addr + i) << "  ";
    }
    double d;
    memcpy(&d, sect + i, sizeof(double));
    if (O->isLittleEndian() != sys::IsLittleEndianHost)
      sys::swapByteOrder(d);
    uint32_t l0, l1;
    memcpy(&l0, sect + i, sizeof(uint32_t));
    memcpy(&l1, sect + i + sizeof(uint32_t), sizeof(uint32_t));
    if (O->isLittleEndian() != sys::IsLittleEndianHost) {
      sys::swapByteOrder(l0);
      sys::swapByteOrder(l1);
    }
    DumpLiteral8(O, l0, l1, d);
  }
}

static void DumpLiteral16(uint32_t l0, uint32_t l1, uint32_t l2, uint32_t l3) {
  outs() << format("0x%08" PRIx32, l0) << " ";
  outs() << format("0x%08" PRIx32, l1) << " ";
  outs() << format("0x%08" PRIx32, l2) << " ";
  outs() << format("0x%08" PRIx32, l3) << "\n";
}

static void DumpLiteral16Section(MachOObjectFile *O, const char *sect,
                                 uint32_t sect_size, uint64_t sect_addr,
                                 bool print_addresses) {
  for (uint32_t i = 0; i < sect_size; i += 16) {
    if (print_addresses) {
      if (O->is64Bit())
        outs() << format("%016" PRIx64, sect_addr + i) << "  ";
      else
        outs() << format("%08" PRIx64, sect_addr + i) << "  ";
    }
    uint32_t l0, l1, l2, l3;
    memcpy(&l0, sect + i, sizeof(uint32_t));
    memcpy(&l1, sect + i + sizeof(uint32_t), sizeof(uint32_t));
    memcpy(&l2, sect + i + 2 * sizeof(uint32_t), sizeof(uint32_t));
    memcpy(&l3, sect + i + 3 * sizeof(uint32_t), sizeof(uint32_t));
    if (O->isLittleEndian() != sys::IsLittleEndianHost) {
      sys::swapByteOrder(l0);
      sys::swapByteOrder(l1);
      sys::swapByteOrder(l2);
      sys::swapByteOrder(l3);
    }
    DumpLiteral16(l0, l1, l2, l3);
  }
}

static void DumpLiteralPointerSection(MachOObjectFile *O,
                                      const SectionRef &Section,
                                      const char *sect, uint32_t sect_size,
                                      uint64_t sect_addr,
                                      bool print_addresses) {
  // Collect the literal sections in this Mach-O file.
  std::vector<SectionRef> LiteralSections;
  for (const SectionRef &Section : O->sections()) {
    DataRefImpl Ref = Section.getRawDataRefImpl();
    uint32_t section_type;
    if (O->is64Bit()) {
      const MachO::section_64 Sec = O->getSection64(Ref);
      section_type = Sec.flags & MachO::SECTION_TYPE;
    } else {
      const MachO::section Sec = O->getSection(Ref);
      section_type = Sec.flags & MachO::SECTION_TYPE;
    }
    if (section_type == MachO::S_CSTRING_LITERALS ||
        section_type == MachO::S_4BYTE_LITERALS ||
        section_type == MachO::S_8BYTE_LITERALS ||
        section_type == MachO::S_16BYTE_LITERALS)
      LiteralSections.push_back(Section);
  }

  // Set the size of the literal pointer.
  uint32_t lp_size = O->is64Bit() ? 8 : 4;

  // Collect the external relocation symbols for the literal pointers.
  std::vector<std::pair<uint64_t, SymbolRef>> Relocs;
  for (const RelocationRef &Reloc : Section.relocations()) {
    DataRefImpl Rel;
    MachO::any_relocation_info RE;
    bool isExtern = false;
    Rel = Reloc.getRawDataRefImpl();
    RE = O->getRelocation(Rel);
    isExtern = O->getPlainRelocationExternal(RE);
    if (isExtern) {
      uint64_t RelocOffset = Reloc.getOffset();
      symbol_iterator RelocSym = Reloc.getSymbol();
      Relocs.push_back(std::make_pair(RelocOffset, *RelocSym));
    }
  }
  array_pod_sort(Relocs.begin(), Relocs.end());

  // Dump each literal pointer.
  for (uint32_t i = 0; i < sect_size; i += lp_size) {
    if (print_addresses) {
      if (O->is64Bit())
        outs() << format("%016" PRIx64, sect_addr + i) << "  ";
      else
        outs() << format("%08" PRIx64, sect_addr + i) << "  ";
    }
    uint64_t lp;
    if (O->is64Bit()) {
      memcpy(&lp, sect + i, sizeof(uint64_t));
      if (O->isLittleEndian() != sys::IsLittleEndianHost)
        sys::swapByteOrder(lp);
    } else {
      uint32_t li;
      memcpy(&li, sect + i, sizeof(uint32_t));
      if (O->isLittleEndian() != sys::IsLittleEndianHost)
        sys::swapByteOrder(li);
      lp = li;
    }

    // First look for an external relocation entry for this literal pointer.
    auto Reloc = find_if(Relocs, [&](const std::pair<uint64_t, SymbolRef> &P) {
      return P.first == i;
    });
    if (Reloc != Relocs.end()) {
      symbol_iterator RelocSym = Reloc->second;
      StringRef SymName = unwrapOrError(RelocSym->getName(), O->getFileName());
      outs() << "external relocation entry for symbol:" << SymName << "\n";
      continue;
    }

    // For local references see what the section the literal pointer points to.
    auto Sect = find_if(LiteralSections, [&](const SectionRef &R) {
      return lp >= R.getAddress() && lp < R.getAddress() + R.getSize();
    });
    if (Sect == LiteralSections.end()) {
      outs() << format("0x%" PRIx64, lp) << " (not in a literal section)\n";
      continue;
    }

    uint64_t SectAddress = Sect->getAddress();
    uint64_t SectSize = Sect->getSize();

    StringRef SectName;
    if (auto NameOrErr = Section.getName())
      SectName = *NameOrErr;
    else
      consumeError(NameOrErr.takeError());

    DataRefImpl Ref = Sect->getRawDataRefImpl();
    StringRef SegmentName = O->getSectionFinalSegmentName(Ref);
    outs() << SegmentName << ":" << SectName << ":";

    uint32_t section_type;
    if (O->is64Bit()) {
      const MachO::section_64 Sec = O->getSection64(Ref);
      section_type = Sec.flags & MachO::SECTION_TYPE;
    } else {
      const MachO::section Sec = O->getSection(Ref);
      section_type = Sec.flags & MachO::SECTION_TYPE;
    }

    StringRef BytesStr = unwrapOrError(Sect->getContents(), O->getFileName());

    const char *Contents = reinterpret_cast<const char *>(BytesStr.data());

    switch (section_type) {
    case MachO::S_CSTRING_LITERALS:
      for (uint64_t i = lp - SectAddress; i < SectSize && Contents[i] != '\0';
           i++) {
        DumpCstringChar(Contents[i]);
      }
      outs() << "\n";
      break;
    case MachO::S_4BYTE_LITERALS:
      float f;
      memcpy(&f, Contents + (lp - SectAddress), sizeof(float));
      uint32_t l;
      memcpy(&l, Contents + (lp - SectAddress), sizeof(uint32_t));
      if (O->isLittleEndian() != sys::IsLittleEndianHost) {
        sys::swapByteOrder(f);
        sys::swapByteOrder(l);
      }
      DumpLiteral4(l, f);
      break;
    case MachO::S_8BYTE_LITERALS: {
      double d;
      memcpy(&d, Contents + (lp - SectAddress), sizeof(double));
      uint32_t l0, l1;
      memcpy(&l0, Contents + (lp - SectAddress), sizeof(uint32_t));
      memcpy(&l1, Contents + (lp - SectAddress) + sizeof(uint32_t),
             sizeof(uint32_t));
      if (O->isLittleEndian() != sys::IsLittleEndianHost) {
        sys::swapByteOrder(f);
        sys::swapByteOrder(l0);
        sys::swapByteOrder(l1);
      }
      DumpLiteral8(O, l0, l1, d);
      break;
    }
    case MachO::S_16BYTE_LITERALS: {
      uint32_t l0, l1, l2, l3;
      memcpy(&l0, Contents + (lp - SectAddress), sizeof(uint32_t));
      memcpy(&l1, Contents + (lp - SectAddress) + sizeof(uint32_t),
             sizeof(uint32_t));
      memcpy(&l2, Contents + (lp - SectAddress) + 2 * sizeof(uint32_t),
             sizeof(uint32_t));
      memcpy(&l3, Contents + (lp - SectAddress) + 3 * sizeof(uint32_t),
             sizeof(uint32_t));
      if (O->isLittleEndian() != sys::IsLittleEndianHost) {
        sys::swapByteOrder(l0);
        sys::swapByteOrder(l1);
        sys::swapByteOrder(l2);
        sys::swapByteOrder(l3);
      }
      DumpLiteral16(l0, l1, l2, l3);
      break;
    }
    }
  }
}

static void DumpInitTermPointerSection(MachOObjectFile *O, const char *sect,
                                       uint32_t sect_size, uint64_t sect_addr,
                                       SymbolAddressMap *AddrMap,
                                       bool verbose) {
  uint32_t stride;
  stride = (O->is64Bit()) ? sizeof(uint64_t) : sizeof(uint32_t);
  for (uint32_t i = 0; i < sect_size; i += stride) {
    const char *SymbolName = nullptr;
    if (O->is64Bit()) {
      outs() << format("0x%016" PRIx64, sect_addr + i * stride) << " ";
      uint64_t pointer_value;
      memcpy(&pointer_value, sect + i, stride);
      if (O->isLittleEndian() != sys::IsLittleEndianHost)
        sys::swapByteOrder(pointer_value);
      outs() << format("0x%016" PRIx64, pointer_value);
      if (verbose)
        SymbolName = GuessSymbolName(pointer_value, AddrMap);
    } else {
      outs() << format("0x%08" PRIx64, sect_addr + i * stride) << " ";
      uint32_t pointer_value;
      memcpy(&pointer_value, sect + i, stride);
      if (O->isLittleEndian() != sys::IsLittleEndianHost)
        sys::swapByteOrder(pointer_value);
      outs() << format("0x%08" PRIx32, pointer_value);
      if (verbose)
        SymbolName = GuessSymbolName(pointer_value, AddrMap);
    }
    if (SymbolName)
      outs() << " " << SymbolName;
    outs() << "\n";
  }
}

static void DumpRawSectionContents(MachOObjectFile *O, const char *sect,
                                   uint32_t size, uint64_t addr) {
  uint32_t cputype = O->getHeader().cputype;
  if (cputype == MachO::CPU_TYPE_I386 || cputype == MachO::CPU_TYPE_X86_64) {
    uint32_t j;
    for (uint32_t i = 0; i < size; i += j, addr += j) {
      if (O->is64Bit())
        outs() << format("%016" PRIx64, addr) << "\t";
      else
        outs() << format("%08" PRIx64, addr) << "\t";
      for (j = 0; j < 16 && i + j < size; j++) {
        uint8_t byte_word = *(sect + i + j);
        outs() << format("%02" PRIx32, (uint32_t)byte_word) << " ";
      }
      outs() << "\n";
    }
  } else {
    uint32_t j;
    for (uint32_t i = 0; i < size; i += j, addr += j) {
      if (O->is64Bit())
        outs() << format("%016" PRIx64, addr) << "\t";
      else
        outs() << format("%08" PRIx64, addr) << "\t";
      for (j = 0; j < 4 * sizeof(int32_t) && i + j < size;
           j += sizeof(int32_t)) {
        if (i + j + sizeof(int32_t) <= size) {
          uint32_t long_word;
          memcpy(&long_word, sect + i + j, sizeof(int32_t));
          if (O->isLittleEndian() != sys::IsLittleEndianHost)
            sys::swapByteOrder(long_word);
          outs() << format("%08" PRIx32, long_word) << " ";
        } else {
          for (uint32_t k = 0; i + j + k < size; k++) {
            uint8_t byte_word = *(sect + i + j + k);
            outs() << format("%02" PRIx32, (uint32_t)byte_word) << " ";
          }
        }
      }
      outs() << "\n";
    }
  }
}

static void DisassembleMachO(StringRef Filename, MachOObjectFile *MachOOF,
                             StringRef DisSegName, StringRef DisSectName);
static void DumpProtocolSection(MachOObjectFile *O, const char *sect,
                                uint32_t size, uint32_t addr);
#ifdef HAVE_LIBXAR
static void DumpBitcodeSection(MachOObjectFile *O, const char *sect,
                               uint32_t size, bool verbose, bool PrintXarHeader,
                               bool PrintXarFileHeaders,
                               std::string XarMemberName);
#endif // defined(HAVE_LIBXAR)

static void DumpSectionContents(StringRef Filename, MachOObjectFile *O,
                                bool verbose) {
  SymbolAddressMap AddrMap;
  if (verbose)
    CreateSymbolAddressMap(O, &AddrMap);

  for (unsigned i = 0; i < FilterSections.size(); ++i) {
    StringRef DumpSection = FilterSections[i];
    std::pair<StringRef, StringRef> DumpSegSectName;
    DumpSegSectName = DumpSection.split(',');
    StringRef DumpSegName, DumpSectName;
    if (DumpSegSectName.second.size()) {
      DumpSegName = DumpSegSectName.first;
      DumpSectName = DumpSegSectName.second;
    } else {
      DumpSegName = "";
      DumpSectName = DumpSegSectName.first;
    }
    for (const SectionRef &Section : O->sections()) {
      StringRef SectName;
      if (auto NameOrErr = Section.getName())
        SectName = *NameOrErr;
      else
        consumeError(NameOrErr.takeError());

      DataRefImpl Ref = Section.getRawDataRefImpl();
      StringRef SegName = O->getSectionFinalSegmentName(Ref);
      if ((DumpSegName.empty() || SegName == DumpSegName) &&
          (SectName == DumpSectName)) {

        uint32_t section_flags;
        if (O->is64Bit()) {
          const MachO::section_64 Sec = O->getSection64(Ref);
          section_flags = Sec.flags;

        } else {
          const MachO::section Sec = O->getSection(Ref);
          section_flags = Sec.flags;
        }
        uint32_t section_type = section_flags & MachO::SECTION_TYPE;

        StringRef BytesStr =
            unwrapOrError(Section.getContents(), O->getFileName());
        const char *sect = reinterpret_cast<const char *>(BytesStr.data());
        uint32_t sect_size = BytesStr.size();
        uint64_t sect_addr = Section.getAddress();

        outs() << "Contents of (" << SegName << "," << SectName
               << ") section\n";

        if (verbose) {
          if ((section_flags & MachO::S_ATTR_PURE_INSTRUCTIONS) ||
              (section_flags & MachO::S_ATTR_SOME_INSTRUCTIONS)) {
            DisassembleMachO(Filename, O, SegName, SectName);
            continue;
          }
          if (SegName == "__TEXT" && SectName == "__info_plist") {
            outs() << sect;
            continue;
          }
          if (SegName == "__OBJC" && SectName == "__protocol") {
            DumpProtocolSection(O, sect, sect_size, sect_addr);
            continue;
          }
#ifdef HAVE_LIBXAR
          if (SegName == "__LLVM" && SectName == "__bundle") {
            DumpBitcodeSection(O, sect, sect_size, verbose, !NoSymbolicOperands,
                               true, "");
            continue;
          }
#endif // defined(HAVE_LIBXAR)
          switch (section_type) {
          case MachO::S_REGULAR:
            DumpRawSectionContents(O, sect, sect_size, sect_addr);
            break;
          case MachO::S_ZEROFILL:
            outs() << "zerofill section and has no contents in the file\n";
            break;
          case MachO::S_CSTRING_LITERALS:
            DumpCstringSection(O, sect, sect_size, sect_addr, true);
            break;
          case MachO::S_4BYTE_LITERALS:
            DumpLiteral4Section(O, sect, sect_size, sect_addr, true);
            break;
          case MachO::S_8BYTE_LITERALS:
            DumpLiteral8Section(O, sect, sect_size, sect_addr, true);
            break;
          case MachO::S_16BYTE_LITERALS:
            DumpLiteral16Section(O, sect, sect_size, sect_addr, true);
            break;
          case MachO::S_LITERAL_POINTERS:
            DumpLiteralPointerSection(O, Section, sect, sect_size, sect_addr,
                                      true);
            break;
          case MachO::S_MOD_INIT_FUNC_POINTERS:
          case MachO::S_MOD_TERM_FUNC_POINTERS:
            DumpInitTermPointerSection(O, sect, sect_size, sect_addr, &AddrMap,
                                       verbose);
            break;
          default:
            outs() << "Unknown section type ("
                   << format("0x%08" PRIx32, section_type) << ")\n";
            DumpRawSectionContents(O, sect, sect_size, sect_addr);
            break;
          }
        } else {
          if (section_type == MachO::S_ZEROFILL)
            outs() << "zerofill section and has no contents in the file\n";
          else
            DumpRawSectionContents(O, sect, sect_size, sect_addr);
        }
      }
    }
  }
}

// checkMachOAndArchFlags() checks to see if the ObjectFile is a Mach-O file
// and if it is and there is a list of architecture flags is specified then
// check to make sure this Mach-O file is one of those architectures or all
// architectures were specified.  If not then an error is generated and this
// routine returns false.  Else it returns true.
static bool checkMachOAndArchFlags(ObjectFile *O, StringRef Filename) {
  auto *MachO = dyn_cast<MachOObjectFile>(O);

  if (!MachO || ArchAll || ArchFlags.empty())
    return true;

  MachO::mach_header H;
  MachO::mach_header_64 H_64;
  Triple T;
  const char *McpuDefault, *ArchFlag;
  if (MachO->is64Bit()) {
    H_64 = MachO->MachOObjectFile::getHeader64();
    T = MachOObjectFile::getArchTriple(H_64.cputype, H_64.cpusubtype,
                                       &McpuDefault, &ArchFlag);
  } else {
    H = MachO->MachOObjectFile::getHeader();
    T = MachOObjectFile::getArchTriple(H.cputype, H.cpusubtype, &McpuDefault,
                                       &ArchFlag);
  }
  const std::string ArchFlagName(ArchFlag);
  if (none_of(ArchFlags,
              [&](const std::string &Name) { return Name == ArchFlagName; })) {
    errs() << "llvm-mctoll: " + Filename + ": No architecture specified.\n";
    return false;
  }
  return true;
}

// ProcessMachO() is passed a single opened Mach-O file, which may be an
// archive member and or in a slice of a universal file.  It prints the
// the file name and header info and then processes it according to the
// command line options.
static void ProcessMachO(StringRef Name, MachOObjectFile *MachOOF,
                         StringRef ArchiveMemberName = StringRef(),
                         StringRef ArchitectureName = StringRef()) {
  if (Disassemble || (FilterSections.size() != 0)) {
    if (!NoLeadingHeaders) {
      outs() << Name;
      if (!ArchiveMemberName.empty())
        outs() << '(' << ArchiveMemberName << ')';
      if (!ArchitectureName.empty())
        outs() << " (architecture " << ArchitectureName << ")";
      outs() << ":\n";
    }
  }
  // To use the report_error() form with an ArchiveName and FileName set
  // these up based on what is passed for Name and ArchiveMemberName.
  StringRef ArchiveName;
  StringRef FileName;
  if (!ArchiveMemberName.empty()) {
    ArchiveName = Name;
    FileName = ArchiveMemberName;
  } else {
    ArchiveName = StringRef();
    FileName = Name;
  }

  // If we need the symbol table to do the operation then check it here to
  // produce a good error message as to where the Mach-O file comes from in
  // the error message.
  if (Disassemble || FilterSections.size() != 0)
    if (Error Err = MachOOF->checkSymbolTable())
      report_error(std::move(Err), ArchiveName, FileName, ArchitectureName);

  if (Disassemble) {
    if (MachOOF->getHeader().filetype == MachO::MH_KEXT_BUNDLE &&
        MachOOF->getHeader().cputype == MachO::CPU_TYPE_ARM64)
      DisassembleMachO(FileName, MachOOF, "__TEXT_EXEC", "__text");
    else
      DisassembleMachO(FileName, MachOOF, "__TEXT", "__text");
  }
  if (FilterSections.size() != 0)
    DumpSectionContents(FileName, MachOOF, !NonVerbose);
}

// ParseInputMachO() parses the named Mach-O file in Filename and handles the
// -arch flags selecting just those slices as specified by them and also parses
// archive files.  Then for each individual Mach-O file ProcessMachO() is
// called to process the file based on the command line options.
void llvm::parseInputMachO(StringRef Filename) {
  // Check for -arch all and verifiy the -arch flags are valid.
  for (unsigned i = 0; i < ArchFlags.size(); ++i) {
    if (ArchFlags[i] == "all") {
      ArchAll = true;
    } else {
      if (!MachOObjectFile::isValidArch(ArchFlags[i])) {
        errs() << "llvm-mctoll: Unknown architecture named '" + ArchFlags[i] +
                      "'for the -arch option\n";
        return;
      }
    }
  }

  // Attempt to open the binary.
  Expected<OwningBinary<Binary>> BinaryOrErr = createBinary(Filename);
  if (!BinaryOrErr) {
    if (auto E = isNotObjectErrorInvalidFileType(BinaryOrErr.takeError()))
      report_error(std::move(E), Filename);
    else
      outs() << Filename << ": is not an object file\n";
    return;
  }
  Binary &Bin = *BinaryOrErr.get().getBinary();

  if (Archive *A = dyn_cast<Archive>(&Bin)) {
    outs() << "Archive : " << Filename << "\n";

    Error Err = Error::success();
    for (auto &C : A->children(Err)) {
      Expected<std::unique_ptr<Binary>> ChildOrErr = C.getAsBinary();
      if (!ChildOrErr) {
        if (auto E = isNotObjectErrorInvalidFileType(ChildOrErr.takeError()))
          report_error(std::move(E), Filename, C);
        continue;
      }
      if (MachOObjectFile *O = dyn_cast<MachOObjectFile>(&*ChildOrErr.get())) {
        if (!checkMachOAndArchFlags(O, Filename))
          return;
        ProcessMachO(Filename, O, O->getFileName());
      }
    }
    if (Err)
      report_error(std::move(Err), Filename);
    return;
  }

  if (MachOUniversalBinary *UB = dyn_cast<MachOUniversalBinary>(&Bin)) {
    // If we have a list of architecture flags specified dump only those.
    if (!ArchAll && ArchFlags.size() != 0) {
      // Look for a slice in the universal binary that matches each ArchFlag.
      bool ArchFound;
      for (unsigned i = 0; i < ArchFlags.size(); ++i) {
        ArchFound = false;
        for (MachOUniversalBinary::object_iterator I = UB->begin_objects(),
                                                   E = UB->end_objects();
             I != E; ++I) {
          if (ArchFlags[i] == I->getArchFlagName()) {
            ArchFound = true;
            Expected<std::unique_ptr<ObjectFile>> ObjOrErr =
                I->getAsObjectFile();
            std::string ArchitectureName = "";
            if (ArchFlags.size() > 1)
              ArchitectureName = I->getArchFlagName();
            if (ObjOrErr) {
              ObjectFile &O = *ObjOrErr.get();
              if (MachOObjectFile *MachOOF = dyn_cast<MachOObjectFile>(&O))
                ProcessMachO(Filename, MachOOF, "", ArchitectureName);
            } else if (auto E = isNotObjectErrorInvalidFileType(
                           ObjOrErr.takeError())) {
              report_error(std::move(E), Filename, StringRef(),
                           ArchitectureName);
              continue;
            } else if (Expected<std::unique_ptr<Archive>> AOrErr =
                           I->getAsArchive()) {
              std::unique_ptr<Archive> &A = *AOrErr;
              outs() << "Archive : " << Filename;
              if (!ArchitectureName.empty())
                outs() << " (architecture " << ArchitectureName << ")";
              outs() << "\n";
              Error Err = Error::success();
              for (auto &C : A->children(Err)) {
                Expected<std::unique_ptr<Binary>> ChildOrErr = C.getAsBinary();
                if (!ChildOrErr) {
                  if (auto E = isNotObjectErrorInvalidFileType(
                          ChildOrErr.takeError()))
                    report_error(std::move(E), Filename, C, ArchitectureName);
                  continue;
                }
                if (MachOObjectFile *O =
                        dyn_cast<MachOObjectFile>(&*ChildOrErr.get()))
                  ProcessMachO(Filename, O, O->getFileName(), ArchitectureName);
              }
              if (Err)
                report_error(std::move(Err), Filename);
            } else {
              consumeError(AOrErr.takeError());
              error("Mach-O universal file: " + Filename + " for " +
                    "architecture " + StringRef(I->getArchFlagName()) +
                    " is not a Mach-O file or an archive file");
            }
          }
        }
        if (!ArchFound) {
          errs() << "llvm-mctoll: file: " + Filename + " does not contain "
                 << "architecture: " + ArchFlags[i] + "\n";
          return;
        }
      }
      return;
    }
    // No architecture flags were specified so if this contains a slice that
    // matches the host architecture dump only that.
    if (!ArchAll) {
      for (MachOUniversalBinary::object_iterator I = UB->begin_objects(),
                                                 E = UB->end_objects();
           I != E; ++I) {
        if (MachOObjectFile::getHostArch().getArchName() ==
            I->getArchFlagName()) {
          Expected<std::unique_ptr<ObjectFile>> ObjOrErr = I->getAsObjectFile();
          std::string ArchiveName;
          ArchiveName.clear();
          if (ObjOrErr) {
            ObjectFile &O = *ObjOrErr.get();
            if (MachOObjectFile *MachOOF = dyn_cast<MachOObjectFile>(&O))
              ProcessMachO(Filename, MachOOF);
          } else if (auto E = isNotObjectErrorInvalidFileType(
                         ObjOrErr.takeError())) {
            report_error(std::move(E), Filename);
            continue;
          } else if (Expected<std::unique_ptr<Archive>> AOrErr =
                         I->getAsArchive()) {
            std::unique_ptr<Archive> &A = *AOrErr;
            Error Err = Error::success();
            for (auto &C : A->children(Err)) {
              Expected<std::unique_ptr<Binary>> ChildOrErr = C.getAsBinary();
              if (!ChildOrErr) {
                if (auto E =
                        isNotObjectErrorInvalidFileType(ChildOrErr.takeError()))
                  report_error(std::move(E), Filename, C);
                continue;
              }
              if (MachOObjectFile *O =
                      dyn_cast<MachOObjectFile>(&*ChildOrErr.get()))
                ProcessMachO(Filename, O, O->getFileName());
            }
            if (Err)
              report_error(std::move(Err), Filename);
          } else {
            consumeError(AOrErr.takeError());
            error("Mach-O universal file: " + Filename + " for architecture " +
                  StringRef(I->getArchFlagName()) +
                  " is not a Mach-O file or an archive file");
          }
          return;
        }
      }
    }
    // Either all architectures have been specified or none have been specified
    // and this does not contain the host architecture so dump all the slices.
    bool moreThanOneArch = UB->getNumberOfObjects() > 1;
    for (MachOUniversalBinary::object_iterator I = UB->begin_objects(),
                                               E = UB->end_objects();
         I != E; ++I) {
      Expected<std::unique_ptr<ObjectFile>> ObjOrErr = I->getAsObjectFile();
      std::string ArchitectureName = "";
      if (moreThanOneArch)
        ArchitectureName = I->getArchFlagName();
      if (ObjOrErr) {
        ObjectFile &Obj = *ObjOrErr.get();
        if (MachOObjectFile *MachOOF = dyn_cast<MachOObjectFile>(&Obj))
          ProcessMachO(Filename, MachOOF, "", ArchitectureName);
      } else if (auto E =
                     isNotObjectErrorInvalidFileType(ObjOrErr.takeError())) {
        report_error(std::move(E), Filename, StringRef(), ArchitectureName);

        continue;
      } else if (Expected<std::unique_ptr<Archive>> AOrErr =
                     I->getAsArchive()) {
        std::unique_ptr<Archive> &A = *AOrErr;
        outs() << "Archive : " << Filename;
        if (!ArchitectureName.empty())
          outs() << " (architecture " << ArchitectureName << ")";
        outs() << "\n";
        Error Err = Error::success();
        for (auto &C : A->children(Err)) {
          Expected<std::unique_ptr<Binary>> ChildOrErr = C.getAsBinary();
          if (!ChildOrErr) {
            if (auto E =
                    isNotObjectErrorInvalidFileType(ChildOrErr.takeError()))
              report_error(std::move(E), Filename, C, ArchitectureName);
            continue;
          }
          if (MachOObjectFile *O =
                  dyn_cast<MachOObjectFile>(&*ChildOrErr.get())) {
            if (MachOObjectFile *MachOOF = dyn_cast<MachOObjectFile>(O))
              ProcessMachO(Filename, MachOOF, MachOOF->getFileName(),
                           ArchitectureName);
          }
        }
        if (Err)
          report_error(std::move(Err), Filename);
      } else {
        consumeError(AOrErr.takeError());
        error("Mach-O universal file: " + Filename + " for architecture " +
              StringRef(I->getArchFlagName()) +
              " is not a Mach-O file or an archive file");
      }
    }
    return;
  }
  if (ObjectFile *O = dyn_cast<ObjectFile>(&Bin)) {
    if (!checkMachOAndArchFlags(O, Filename))
      return;
    if (MachOObjectFile *MachOOF = dyn_cast<MachOObjectFile>(&*O)) {
      ProcessMachO(Filename, MachOOF);
    } else
      errs() << "llvm-mctoll: '" << Filename << "': "
             << "Object is not a Mach-O file type.\n";
    return;
  }
  llvm_unreachable("Input object can't be invalid at this point");
}

// The block of info used by the Symbolizer call backs.
struct DisassembleInfo {
  bool verbose;
  MachOObjectFile *O;
  SectionRef S;
  SymbolAddressMap *AddrMap;
  std::vector<SectionRef> *Sections;
  const char *class_name;
  const char *selector_name;
  char *method;
  char *demangled_name;
  uint64_t adrp_addr;
  uint32_t adrp_inst;
  std::unique_ptr<SymbolAddressMap> bindtable;
  uint32_t depth;
};

// SymbolizerGetOpInfo() is the operand information call back function.
// This is called to get the symbolic information for operand(s) of an
// instruction when it is being done.  This routine does this from
// the relocation information, symbol table, etc. That block of information
// is a pointer to the struct DisassembleInfo that was passed when the
// disassembler context was created and passed to back to here when
// called back by the disassembler for instruction operands that could have
// relocation information. The address of the instruction containing operand is
// at the Pc parameter.  The immediate value the operand has is passed in
// op_info->Value and is at Offset past the start of the instruction and has a
// byte Size of 1, 2 or 4. The symbolc information is returned in TagBuf is the
// LLVMOpInfo1 struct defined in the header "llvm-c/Disassembler.h" as symbol
// names and addends of the symbolic expression to add for the operand.  The
// value of TagType is currently 1 (for the LLVMOpInfo1 struct). If symbolic
// information is returned then this function returns 1 else it returns 0.
static int SymbolizerGetOpInfo(void *DisInfo, uint64_t Pc, uint64_t Offset,
                               uint64_t Size, int TagType, void *TagBuf) {
  struct DisassembleInfo *info = (struct DisassembleInfo *)DisInfo;
  struct LLVMOpInfo1 *op_info = (struct LLVMOpInfo1 *)TagBuf;
  uint64_t value = op_info->Value;

  // Make sure all fields returned are zero if we don't set them.
  memset((void *)op_info, '\0', sizeof(struct LLVMOpInfo1));
  op_info->Value = value;

  // If the TagType is not the value 1 which it code knows about or if no
  // verbose symbolic information is wanted then just return 0, indicating no
  // information is being returned.
  if (TagType != 1 || !info->verbose)
    return 0;

  unsigned int Arch = info->O->getArch();
  if (Arch == Triple::x86) {
    if (Size != 1 && Size != 2 && Size != 4 && Size != 0)
      return 0;
    if (info->O->getHeader().filetype != MachO::MH_OBJECT) {
      // TODO:
      // Search the external relocation entries of a fully linked image
      // (if any) for an entry that matches this segment offset.
      // uint32_t seg_offset = (Pc + Offset);
      return 0;
    }
    // In MH_OBJECT filetypes search the section's relocation entries (if any)
    // for an entry for this section offset.
    uint32_t sect_addr = info->S.getAddress();
    uint32_t sect_offset = (Pc + Offset) - sect_addr;
    bool reloc_found = false;
    DataRefImpl Rel;
    MachO::any_relocation_info RE;
    bool isExtern = false;
    SymbolRef Symbol;
    bool r_scattered = false;
    uint32_t r_value, pair_r_value, r_type;
    for (const RelocationRef &Reloc : info->S.relocations()) {
      uint64_t RelocOffset = Reloc.getOffset();
      if (RelocOffset == sect_offset) {
        Rel = Reloc.getRawDataRefImpl();
        RE = info->O->getRelocation(Rel);
        r_type = info->O->getAnyRelocationType(RE);
        r_scattered = info->O->isRelocationScattered(RE);
        if (r_scattered) {
          r_value = info->O->getScatteredRelocationValue(RE);
          if (r_type == MachO::GENERIC_RELOC_SECTDIFF ||
              r_type == MachO::GENERIC_RELOC_LOCAL_SECTDIFF) {
            DataRefImpl RelNext = Rel;
            info->O->moveRelocationNext(RelNext);
            MachO::any_relocation_info RENext;
            RENext = info->O->getRelocation(RelNext);
            if (info->O->isRelocationScattered(RENext))
              pair_r_value = info->O->getScatteredRelocationValue(RENext);
            else
              return 0;
          }
        } else {
          isExtern = info->O->getPlainRelocationExternal(RE);
          if (isExtern) {
            symbol_iterator RelocSym = Reloc.getSymbol();
            Symbol = *RelocSym;
          }
        }
        reloc_found = true;
        break;
      }
    }
    if (reloc_found && isExtern) {
      op_info->AddSymbol.Present = 1;
      op_info->AddSymbol.Name =
          unwrapOrError(Symbol.getName(), info->O->getFileName()).data();
      // For i386 extern relocation entries the value in the instruction is
      // the offset from the symbol, and value is already set in op_info->Value.
      return 1;
    }
    if (reloc_found && (r_type == MachO::GENERIC_RELOC_SECTDIFF ||
                        r_type == MachO::GENERIC_RELOC_LOCAL_SECTDIFF)) {
      const char *add = GuessSymbolName(r_value, info->AddrMap);
      const char *sub = GuessSymbolName(pair_r_value, info->AddrMap);
      uint32_t offset = value - (r_value - pair_r_value);
      op_info->AddSymbol.Present = 1;
      if (add != nullptr)
        op_info->AddSymbol.Name = add;
      else
        op_info->AddSymbol.Value = r_value;
      op_info->SubtractSymbol.Present = 1;
      if (sub != nullptr)
        op_info->SubtractSymbol.Name = sub;
      else
        op_info->SubtractSymbol.Value = pair_r_value;
      op_info->Value = offset;
      return 1;
    }
    return 0;
  }
  if (Arch == Triple::x86_64) {
    if (Size != 1 && Size != 2 && Size != 4 && Size != 0)
      return 0;
    // For non MH_OBJECT types, like MH_KEXT_BUNDLE, Search the external
    // relocation entries of a linked image (if any) for an entry that matches
    // this segment offset.
    if (info->O->getHeader().filetype != MachO::MH_OBJECT) {
      uint64_t seg_offset = Pc + Offset;
      bool reloc_found = false;
      DataRefImpl Rel;
      MachO::any_relocation_info RE;
      bool isExtern = false;
      SymbolRef Symbol;
      for (const RelocationRef &Reloc : info->O->external_relocations()) {
        uint64_t RelocOffset = Reloc.getOffset();
        if (RelocOffset == seg_offset) {
          Rel = Reloc.getRawDataRefImpl();
          RE = info->O->getRelocation(Rel);
          // external relocation entries should always be external.
          isExtern = info->O->getPlainRelocationExternal(RE);
          if (isExtern) {
            symbol_iterator RelocSym = Reloc.getSymbol();
            Symbol = *RelocSym;
          }
          reloc_found = true;
          break;
        }
      }
      if (reloc_found && isExtern) {
        // The Value passed in will be adjusted by the Pc if the instruction
        // adds the Pc.  But for x86_64 external relocation entries the Value
        // is the offset from the external symbol.
        if (info->O->getAnyRelocationPCRel(RE))
          op_info->Value -= Pc + Offset + Size;
        const char *name =
            unwrapOrError(Symbol.getName(), info->O->getFileName()).data();
        op_info->AddSymbol.Present = 1;
        op_info->AddSymbol.Name = name;
        return 1;
      }
      return 0;
    }
    // In MH_OBJECT filetypes search the section's relocation entries (if any)
    // for an entry for this section offset.
    uint64_t sect_addr = info->S.getAddress();
    uint64_t sect_offset = (Pc + Offset) - sect_addr;
    bool reloc_found = false;
    DataRefImpl Rel;
    MachO::any_relocation_info RE;
    bool isExtern = false;
    SymbolRef Symbol;
    for (const RelocationRef &Reloc : info->S.relocations()) {
      uint64_t RelocOffset = Reloc.getOffset();
      if (RelocOffset == sect_offset) {
        Rel = Reloc.getRawDataRefImpl();
        RE = info->O->getRelocation(Rel);
        // NOTE: Scattered relocations don't exist on x86_64.
        isExtern = info->O->getPlainRelocationExternal(RE);
        if (isExtern) {
          symbol_iterator RelocSym = Reloc.getSymbol();
          Symbol = *RelocSym;
        }
        reloc_found = true;
        break;
      }
    }
    if (reloc_found && isExtern) {
      // The Value passed in will be adjusted by the Pc if the instruction
      // adds the Pc.  But for x86_64 external relocation entries the Value
      // is the offset from the external symbol.
      if (info->O->getAnyRelocationPCRel(RE))
        op_info->Value -= Pc + Offset + Size;
      Expected<StringRef> SymName = Symbol.getName();
      if (!SymName)
        report_error(SymName.takeError(), info->O->getFileName());
      const char *name = SymName->data();
      unsigned Type = info->O->getAnyRelocationType(RE);
      if (Type == MachO::X86_64_RELOC_SUBTRACTOR) {
        DataRefImpl RelNext = Rel;
        info->O->moveRelocationNext(RelNext);
        MachO::any_relocation_info RENext = info->O->getRelocation(RelNext);
        unsigned TypeNext = info->O->getAnyRelocationType(RENext);
        bool isExternNext = info->O->getPlainRelocationExternal(RENext);
        unsigned SymbolNum = info->O->getPlainRelocationSymbolNum(RENext);
        if (TypeNext == MachO::X86_64_RELOC_UNSIGNED && isExternNext) {
          op_info->SubtractSymbol.Present = 1;
          op_info->SubtractSymbol.Name = name;
          symbol_iterator RelocSymNext = info->O->getSymbolByIndex(SymbolNum);
          Symbol = *RelocSymNext;
          Expected<StringRef> SymNameNext = Symbol.getName();
          if (!SymNameNext)
            report_error(SymNameNext.takeError(), info->O->getFileName());
          name = SymNameNext->data();
        }
      }
      // TODO: add the VariantKinds to op_info->VariantKind for relocation types
      // like: X86_64_RELOC_TLV, X86_64_RELOC_GOT_LOAD and X86_64_RELOC_GOT.
      op_info->AddSymbol.Present = 1;
      op_info->AddSymbol.Name = name;
      return 1;
    }
    return 0;
  }
  if (Arch == Triple::arm) {
    if (Offset != 0 || (Size != 4 && Size != 2))
      return 0;
    if (info->O->getHeader().filetype != MachO::MH_OBJECT) {
      // TODO:
      // Search the external relocation entries of a fully linked image
      // (if any) for an entry that matches this segment offset.
      // uint32_t seg_offset = (Pc + Offset);
      return 0;
    }
    // In MH_OBJECT filetypes search the section's relocation entries (if any)
    // for an entry for this section offset.
    uint32_t sect_addr = info->S.getAddress();
    uint32_t sect_offset = (Pc + Offset) - sect_addr;
    DataRefImpl Rel;
    MachO::any_relocation_info RE;
    bool isExtern = false;
    SymbolRef Symbol;
    bool r_scattered = false;
    uint32_t r_value, pair_r_value, r_type, r_length, other_half;
    auto Reloc =
        find_if(info->S.relocations(), [&](const RelocationRef &Reloc) {
          uint64_t RelocOffset = Reloc.getOffset();
          return RelocOffset == sect_offset;
        });

    if (Reloc == info->S.relocations().end())
      return 0;

    Rel = Reloc->getRawDataRefImpl();
    RE = info->O->getRelocation(Rel);
    r_length = info->O->getAnyRelocationLength(RE);
    r_scattered = info->O->isRelocationScattered(RE);
    if (r_scattered) {
      r_value = info->O->getScatteredRelocationValue(RE);
      r_type = info->O->getScatteredRelocationType(RE);
    } else {
      r_type = info->O->getAnyRelocationType(RE);
      isExtern = info->O->getPlainRelocationExternal(RE);
      if (isExtern) {
        symbol_iterator RelocSym = Reloc->getSymbol();
        Symbol = *RelocSym;
      }
    }
    if (r_type == MachO::ARM_RELOC_HALF ||
        r_type == MachO::ARM_RELOC_SECTDIFF ||
        r_type == MachO::ARM_RELOC_LOCAL_SECTDIFF ||
        r_type == MachO::ARM_RELOC_HALF_SECTDIFF) {
      DataRefImpl RelNext = Rel;
      info->O->moveRelocationNext(RelNext);
      MachO::any_relocation_info RENext;
      RENext = info->O->getRelocation(RelNext);
      other_half = info->O->getAnyRelocationAddress(RENext) & 0xffff;
      if (info->O->isRelocationScattered(RENext))
        pair_r_value = info->O->getScatteredRelocationValue(RENext);
    }

    if (isExtern) {
      Expected<StringRef> SymName = Symbol.getName();
      if (!SymName)
        report_error(SymName.takeError(), info->O->getFileName());
      const char *name = SymName->data();
      op_info->AddSymbol.Present = 1;
      op_info->AddSymbol.Name = name;
      switch (r_type) {
      case MachO::ARM_RELOC_HALF:
        if ((r_length & 0x1) == 1) {
          op_info->Value = value << 16 | other_half;
          op_info->VariantKind = LLVMDisassembler_VariantKind_ARM_HI16;
        } else {
          op_info->Value = other_half << 16 | value;
          op_info->VariantKind = LLVMDisassembler_VariantKind_ARM_LO16;
        }
        break;
      default:
        break;
      }
      return 1;
    }
    // If we have a branch that is not an external relocation entry then
    // return 0 so the code in tryAddingSymbolicOperand() can use the
    // SymbolLookUp call back with the branch target address to look up the
    // symbol and possibility add an annotation for a symbol stub.
    if (isExtern == 0 && (r_type == MachO::ARM_RELOC_BR24 ||
                          r_type == MachO::ARM_THUMB_RELOC_BR22))
      return 0;

    uint32_t offset = 0;
    if (r_type == MachO::ARM_RELOC_HALF ||
        r_type == MachO::ARM_RELOC_HALF_SECTDIFF) {
      if ((r_length & 0x1) == 1)
        value = value << 16 | other_half;
      else
        value = other_half << 16 | value;
    }
    if (r_scattered && (r_type != MachO::ARM_RELOC_HALF &&
                        r_type != MachO::ARM_RELOC_HALF_SECTDIFF)) {
      offset = value - r_value;
      value = r_value;
    }

    if (r_type == MachO::ARM_RELOC_HALF_SECTDIFF) {
      if ((r_length & 0x1) == 1)
        op_info->VariantKind = LLVMDisassembler_VariantKind_ARM_HI16;
      else
        op_info->VariantKind = LLVMDisassembler_VariantKind_ARM_LO16;
      const char *add = GuessSymbolName(r_value, info->AddrMap);
      const char *sub = GuessSymbolName(pair_r_value, info->AddrMap);
      int32_t offset = value - (r_value - pair_r_value);
      op_info->AddSymbol.Present = 1;
      if (add != nullptr)
        op_info->AddSymbol.Name = add;
      else
        op_info->AddSymbol.Value = r_value;
      op_info->SubtractSymbol.Present = 1;
      if (sub != nullptr)
        op_info->SubtractSymbol.Name = sub;
      else
        op_info->SubtractSymbol.Value = pair_r_value;
      op_info->Value = offset;
      return 1;
    }

    op_info->AddSymbol.Present = 1;
    op_info->Value = offset;
    if (r_type == MachO::ARM_RELOC_HALF) {
      if ((r_length & 0x1) == 1)
        op_info->VariantKind = LLVMDisassembler_VariantKind_ARM_HI16;
      else
        op_info->VariantKind = LLVMDisassembler_VariantKind_ARM_LO16;
    }
    const char *add = GuessSymbolName(value, info->AddrMap);
    if (add != nullptr) {
      op_info->AddSymbol.Name = add;
      return 1;
    }
    op_info->AddSymbol.Value = value;
    return 1;
  }
  if (Arch == Triple::aarch64) {
    if (Offset != 0 || Size != 4)
      return 0;
    if (info->O->getHeader().filetype != MachO::MH_OBJECT) {
      // TODO:
      // Search the external relocation entries of a fully linked image
      // (if any) for an entry that matches this segment offset.
      // uint64_t seg_offset = (Pc + Offset);
      return 0;
    }
    // In MH_OBJECT filetypes search the section's relocation entries (if any)
    // for an entry for this section offset.
    uint64_t sect_addr = info->S.getAddress();
    uint64_t sect_offset = (Pc + Offset) - sect_addr;
    auto Reloc =
        find_if(info->S.relocations(), [&](const RelocationRef &Reloc) {
          uint64_t RelocOffset = Reloc.getOffset();
          return RelocOffset == sect_offset;
        });

    if (Reloc == info->S.relocations().end())
      return 0;

    DataRefImpl Rel = Reloc->getRawDataRefImpl();
    MachO::any_relocation_info RE = info->O->getRelocation(Rel);
    uint32_t r_type = info->O->getAnyRelocationType(RE);
    if (r_type == MachO::ARM64_RELOC_ADDEND) {
      DataRefImpl RelNext = Rel;
      info->O->moveRelocationNext(RelNext);
      MachO::any_relocation_info RENext = info->O->getRelocation(RelNext);
      if (value == 0) {
        value = info->O->getPlainRelocationSymbolNum(RENext);
        op_info->Value = value;
      }
    }
    // NOTE: Scattered relocations don't exist on arm64.
    if (!info->O->getPlainRelocationExternal(RE))
      return 0;
    Expected<StringRef> SymName = Reloc->getSymbol()->getName();
    if (!SymName)
      report_error(SymName.takeError(), info->O->getFileName());
    const char *name = SymName->data();
    op_info->AddSymbol.Present = 1;
    op_info->AddSymbol.Name = name;

    switch (r_type) {
    case MachO::ARM64_RELOC_PAGE21:
      /* @page */
      op_info->VariantKind = LLVMDisassembler_VariantKind_ARM64_PAGE;
      break;
    case MachO::ARM64_RELOC_PAGEOFF12:
      /* @pageoff */
      op_info->VariantKind = LLVMDisassembler_VariantKind_ARM64_PAGEOFF;
      break;
    case MachO::ARM64_RELOC_GOT_LOAD_PAGE21:
      /* @gotpage */
      op_info->VariantKind = LLVMDisassembler_VariantKind_ARM64_GOTPAGE;
      break;
    case MachO::ARM64_RELOC_GOT_LOAD_PAGEOFF12:
      /* @gotpageoff */
      op_info->VariantKind = LLVMDisassembler_VariantKind_ARM64_GOTPAGEOFF;
      break;
    case MachO::ARM64_RELOC_TLVP_LOAD_PAGE21:
      /* @tvlppage is not implemented in llvm-mc */
      op_info->VariantKind = LLVMDisassembler_VariantKind_ARM64_TLVP;
      break;
    case MachO::ARM64_RELOC_TLVP_LOAD_PAGEOFF12:
      /* @tvlppageoff is not implemented in llvm-mc */
      op_info->VariantKind = LLVMDisassembler_VariantKind_ARM64_TLVOFF;
      break;
    default:
    case MachO::ARM64_RELOC_BRANCH26:
      op_info->VariantKind = LLVMDisassembler_VariantKind_None;
      break;
    }
    return 1;
  }
  return 0;
}

// GuessCstringPointer is passed the address of what might be a pointer to a
// literal string in a cstring section.  If that address is in a cstring section
// it returns a pointer to that string.  Else it returns nullptr.
static const char *GuessCstringPointer(uint64_t ReferenceValue,
                                       struct DisassembleInfo *info) {
  for (const auto &Load : info->O->load_commands()) {
    if (Load.C.cmd == MachO::LC_SEGMENT_64) {
      MachO::segment_command_64 Seg = info->O->getSegment64LoadCommand(Load);
      for (unsigned J = 0; J < Seg.nsects; ++J) {
        MachO::section_64 Sec = info->O->getSection64(Load, J);
        uint32_t section_type = Sec.flags & MachO::SECTION_TYPE;
        if (section_type == MachO::S_CSTRING_LITERALS &&
            ReferenceValue >= Sec.addr &&
            ReferenceValue < Sec.addr + Sec.size) {
          uint64_t sect_offset = ReferenceValue - Sec.addr;
          uint64_t object_offset = Sec.offset + sect_offset;
          StringRef MachOContents = info->O->getData();
          uint64_t object_size = MachOContents.size();
          const char *object_addr = (const char *)MachOContents.data();
          if (object_offset < object_size) {
            const char *name = object_addr + object_offset;
            return name;
          } else {
            return nullptr;
          }
        }
      }
    } else if (Load.C.cmd == MachO::LC_SEGMENT) {
      MachO::segment_command Seg = info->O->getSegmentLoadCommand(Load);
      for (unsigned J = 0; J < Seg.nsects; ++J) {
        MachO::section Sec = info->O->getSection(Load, J);
        uint32_t section_type = Sec.flags & MachO::SECTION_TYPE;
        if (section_type == MachO::S_CSTRING_LITERALS &&
            ReferenceValue >= Sec.addr &&
            ReferenceValue < Sec.addr + Sec.size) {
          uint64_t sect_offset = ReferenceValue - Sec.addr;
          uint64_t object_offset = Sec.offset + sect_offset;
          StringRef MachOContents = info->O->getData();
          uint64_t object_size = MachOContents.size();
          const char *object_addr = (const char *)MachOContents.data();
          if (object_offset < object_size) {
            const char *name = object_addr + object_offset;
            return name;
          } else {
            return nullptr;
          }
        }
      }
    }
  }
  return nullptr;
}

// GuessIndirectSymbol returns the name of the indirect symbol for the
// ReferenceValue passed in or nullptr.  This is used when ReferenceValue maybe
// an address of a symbol stub or a lazy or non-lazy pointer to associate the
// symbol name being referenced by the stub or pointer.
static const char *GuessIndirectSymbol(uint64_t ReferenceValue,
                                       struct DisassembleInfo *info) {
  MachO::dysymtab_command Dysymtab = info->O->getDysymtabLoadCommand();
  MachO::symtab_command Symtab = info->O->getSymtabLoadCommand();
  for (const auto &Load : info->O->load_commands()) {
    if (Load.C.cmd == MachO::LC_SEGMENT_64) {
      MachO::segment_command_64 Seg = info->O->getSegment64LoadCommand(Load);
      for (unsigned J = 0; J < Seg.nsects; ++J) {
        MachO::section_64 Sec = info->O->getSection64(Load, J);
        uint32_t section_type = Sec.flags & MachO::SECTION_TYPE;
        if ((section_type == MachO::S_NON_LAZY_SYMBOL_POINTERS ||
             section_type == MachO::S_LAZY_SYMBOL_POINTERS ||
             section_type == MachO::S_LAZY_DYLIB_SYMBOL_POINTERS ||
             section_type == MachO::S_THREAD_LOCAL_VARIABLE_POINTERS ||
             section_type == MachO::S_SYMBOL_STUBS) &&
            ReferenceValue >= Sec.addr &&
            ReferenceValue < Sec.addr + Sec.size) {
          uint32_t stride;
          if (section_type == MachO::S_SYMBOL_STUBS)
            stride = Sec.reserved2;
          else
            stride = 8;
          if (stride == 0)
            return nullptr;
          uint32_t index = Sec.reserved1 + (ReferenceValue - Sec.addr) / stride;
          if (index < Dysymtab.nindirectsyms) {
            uint32_t indirect_symbol =
                info->O->getIndirectSymbolTableEntry(Dysymtab, index);
            if (indirect_symbol < Symtab.nsyms) {
              symbol_iterator Sym = info->O->getSymbolByIndex(indirect_symbol);
              return unwrapOrError(Sym->getName(), info->O->getFileName())
                  .data();
            }
          }
        }
      }
    } else if (Load.C.cmd == MachO::LC_SEGMENT) {
      MachO::segment_command Seg = info->O->getSegmentLoadCommand(Load);
      for (unsigned J = 0; J < Seg.nsects; ++J) {
        MachO::section Sec = info->O->getSection(Load, J);
        uint32_t section_type = Sec.flags & MachO::SECTION_TYPE;
        if ((section_type == MachO::S_NON_LAZY_SYMBOL_POINTERS ||
             section_type == MachO::S_LAZY_SYMBOL_POINTERS ||
             section_type == MachO::S_LAZY_DYLIB_SYMBOL_POINTERS ||
             section_type == MachO::S_THREAD_LOCAL_VARIABLE_POINTERS ||
             section_type == MachO::S_SYMBOL_STUBS) &&
            ReferenceValue >= Sec.addr &&
            ReferenceValue < Sec.addr + Sec.size) {
          uint32_t stride;
          if (section_type == MachO::S_SYMBOL_STUBS)
            stride = Sec.reserved2;
          else
            stride = 4;
          if (stride == 0)
            return nullptr;
          uint32_t index = Sec.reserved1 + (ReferenceValue - Sec.addr) / stride;
          if (index < Dysymtab.nindirectsyms) {
            uint32_t indirect_symbol =
                info->O->getIndirectSymbolTableEntry(Dysymtab, index);
            if (indirect_symbol < Symtab.nsyms) {
              symbol_iterator Sym = info->O->getSymbolByIndex(indirect_symbol);
              SymbolRef Symbol = *Sym;
              Expected<StringRef> SymName = Symbol.getName();
              if (!SymName)
                report_error(SymName.takeError(), info->O->getFileName());
              const char *name = SymName->data();
              return name;
            }
          }
        }
      }
    }
  }
  return nullptr;
}

// method_reference() is called passing it the ReferenceName that might be
// a reference it to an Objective-C method call.  If so then it allocates and
// assembles a method call string with the values last seen and saved in
// the DisassembleInfo's class_name and selector_name fields.  This is saved
// into the method field of the info and any previous string is free'ed.
// Then the class_name field in the info is set to nullptr.  The method call
// string is set into ReferenceName and ReferenceType is set to
// LLVMDisassembler_ReferenceType_Out_Objc_Message.  If this not a method call
// then both ReferenceType and ReferenceName are left unchanged.
static void method_reference(struct DisassembleInfo *info,
                             uint64_t *ReferenceType,
                             const char **ReferenceName) {
  unsigned int Arch = info->O->getArch();
  if (*ReferenceName != nullptr) {
    if (strcmp(*ReferenceName, "_objc_msgSend") == 0) {
      if (info->selector_name != nullptr) {
        if (info->method != nullptr)
          free(info->method);
        if (info->class_name != nullptr) {
          info->method = (char *)malloc(5 + strlen(info->class_name) +
                                        strlen(info->selector_name));
          if (info->method != nullptr) {
            strcpy(info->method, "+[");
            strcat(info->method, info->class_name);
            strcat(info->method, " ");
            strcat(info->method, info->selector_name);
            strcat(info->method, "]");
            *ReferenceName = info->method;
            *ReferenceType = LLVMDisassembler_ReferenceType_Out_Objc_Message;
          }
        } else {
          info->method = (char *)malloc(9 + strlen(info->selector_name));
          if (info->method != nullptr) {
            if (Arch == Triple::x86_64)
              strcpy(info->method, "-[%rdi ");
            else if (Arch == Triple::aarch64)
              strcpy(info->method, "-[x0 ");
            else
              strcpy(info->method, "-[r? ");
            strcat(info->method, info->selector_name);
            strcat(info->method, "]");
            *ReferenceName = info->method;
            *ReferenceType = LLVMDisassembler_ReferenceType_Out_Objc_Message;
          }
        }
        info->class_name = nullptr;
      }
    } else if (strcmp(*ReferenceName, "_objc_msgSendSuper2") == 0) {
      if (info->selector_name != nullptr) {
        if (info->method != nullptr)
          free(info->method);
        info->method = (char *)malloc(17 + strlen(info->selector_name));
        if (info->method != nullptr) {
          if (Arch == Triple::x86_64)
            strcpy(info->method, "-[[%rdi super] ");
          else if (Arch == Triple::aarch64)
            strcpy(info->method, "-[[x0 super] ");
          else
            strcpy(info->method, "-[[r? super] ");
          strcat(info->method, info->selector_name);
          strcat(info->method, "]");
          *ReferenceName = info->method;
          *ReferenceType = LLVMDisassembler_ReferenceType_Out_Objc_Message;
        }
        info->class_name = nullptr;
      }
    }
  }
}

// GuessPointerPointer() is passed the address of what might be a pointer to
// a reference to an Objective-C class, selector, message ref or cfstring.
// If so the value of the pointer is returned and one of the booleans are set
// to true.  If not zero is returned and all the booleans are set to false.
static uint64_t GuessPointerPointer(uint64_t ReferenceValue,
                                    struct DisassembleInfo *info,
                                    bool &classref, bool &selref, bool &msgref,
                                    bool &cfstring) {
  classref = false;
  selref = false;
  msgref = false;
  cfstring = false;
  for (const auto &Load : info->O->load_commands()) {
    if (Load.C.cmd == MachO::LC_SEGMENT_64) {
      MachO::segment_command_64 Seg = info->O->getSegment64LoadCommand(Load);
      for (unsigned J = 0; J < Seg.nsects; ++J) {
        MachO::section_64 Sec = info->O->getSection64(Load, J);
        if ((strncmp(Sec.sectname, "__objc_selrefs", 16) == 0 ||
             strncmp(Sec.sectname, "__objc_classrefs", 16) == 0 ||
             strncmp(Sec.sectname, "__objc_superrefs", 16) == 0 ||
             strncmp(Sec.sectname, "__objc_msgrefs", 16) == 0 ||
             strncmp(Sec.sectname, "__cfstring", 16) == 0) &&
            ReferenceValue >= Sec.addr &&
            ReferenceValue < Sec.addr + Sec.size) {
          uint64_t sect_offset = ReferenceValue - Sec.addr;
          uint64_t object_offset = Sec.offset + sect_offset;
          StringRef MachOContents = info->O->getData();
          uint64_t object_size = MachOContents.size();
          const char *object_addr = (const char *)MachOContents.data();
          if (object_offset < object_size) {
            uint64_t pointer_value;
            memcpy(&pointer_value, object_addr + object_offset,
                   sizeof(uint64_t));
            if (info->O->isLittleEndian() != sys::IsLittleEndianHost)
              sys::swapByteOrder(pointer_value);
            if (strncmp(Sec.sectname, "__objc_selrefs", 16) == 0)
              selref = true;
            else if (strncmp(Sec.sectname, "__objc_classrefs", 16) == 0 ||
                     strncmp(Sec.sectname, "__objc_superrefs", 16) == 0)
              classref = true;
            else if (strncmp(Sec.sectname, "__objc_msgrefs", 16) == 0 &&
                     ReferenceValue + 8 < Sec.addr + Sec.size) {
              msgref = true;
              memcpy(&pointer_value, object_addr + object_offset + 8,
                     sizeof(uint64_t));
              if (info->O->isLittleEndian() != sys::IsLittleEndianHost)
                sys::swapByteOrder(pointer_value);
            } else if (strncmp(Sec.sectname, "__cfstring", 16) == 0)
              cfstring = true;
            return pointer_value;
          } else {
            return 0;
          }
        }
      }
    }
    // TODO: Look for LC_SEGMENT for 32-bit Mach-O files.
  }
  return 0;
}

// get_pointer_64 returns a pointer to the bytes in the object file at the
// Address from a section in the Mach-O file.  And indirectly returns the
// offset into the section, number of bytes left in the section past the offset
// and which section is was being referenced.  If the Address is not in a
// section nullptr is returned.
static const char *get_pointer_64(uint64_t Address, uint32_t &offset,
                                  uint32_t &left, SectionRef &S,
                                  DisassembleInfo *info,
                                  bool objc_only = false) {
  offset = 0;
  left = 0;
  S = SectionRef();
  for (unsigned SectIdx = 0; SectIdx != info->Sections->size(); SectIdx++) {
    uint64_t SectAddress = ((*(info->Sections))[SectIdx]).getAddress();
    uint64_t SectSize = ((*(info->Sections))[SectIdx]).getSize();
    if (SectSize == 0)
      continue;
    if (objc_only) {
      StringRef SectName;
      if (auto NameOrErr = ((*(info->Sections))[SectIdx]).getName())
        SectName = *NameOrErr;
      else
        consumeError(NameOrErr.takeError());

      DataRefImpl Ref = ((*(info->Sections))[SectIdx]).getRawDataRefImpl();
      StringRef SegName = info->O->getSectionFinalSegmentName(Ref);
      if (SegName != "__OBJC" && SectName != "__cstring")
        continue;
    }
    if (Address >= SectAddress && Address < SectAddress + SectSize) {
      S = (*(info->Sections))[SectIdx];
      offset = Address - SectAddress;
      left = SectSize - offset;
      StringRef SectContents = unwrapOrError(
          ((*(info->Sections))[SectIdx]).getContents(), info->O->getFileName());
      return SectContents.data() + offset;
    }
  }
  return nullptr;
}

static const char *get_pointer_32(uint32_t Address, uint32_t &offset,
                                  uint32_t &left, SectionRef &S,
                                  DisassembleInfo *info,
                                  bool objc_only = false) {
  return get_pointer_64(Address, offset, left, S, info, objc_only);
}

// get_symbol_64() returns the name of a symbol (or nullptr) and the address of
// the symbol indirectly through n_value. Based on the relocation information
// for the specified section offset in the specified section reference.
// If no relocation information is found and a non-zero ReferenceValue for the
// symbol is passed, look up that address in the info's AddrMap.
static const char *get_symbol_64(uint32_t sect_offset, SectionRef S,
                                 DisassembleInfo *info, uint64_t &n_value,
                                 uint64_t ReferenceValue = 0) {
  n_value = 0;
  if (!info->verbose)
    return nullptr;

  // See if there is an external relocation entry at the sect_offset.
  bool reloc_found = false;
  DataRefImpl Rel;
  MachO::any_relocation_info RE;
  bool isExtern = false;
  SymbolRef Symbol;
  for (const RelocationRef &Reloc : S.relocations()) {
    uint64_t RelocOffset = Reloc.getOffset();
    if (RelocOffset == sect_offset) {
      Rel = Reloc.getRawDataRefImpl();
      RE = info->O->getRelocation(Rel);
      if (info->O->isRelocationScattered(RE))
        continue;
      isExtern = info->O->getPlainRelocationExternal(RE);
      if (isExtern) {
        symbol_iterator RelocSym = Reloc.getSymbol();
        Symbol = *RelocSym;
      }
      reloc_found = true;
      break;
    }
  }
  // If there is an external relocation entry for a symbol in this section
  // at this section_offset then use that symbol's value for the n_value
  // and return its name.
  const char *SymbolName = nullptr;
  if (reloc_found && isExtern) {
    auto SymOrErr = Symbol.getValue();
    if (!SymOrErr)
      report_error(SymOrErr.takeError(), Symbol.getObject()->getFileName());
    n_value = *SymOrErr;
    Expected<StringRef> NameOrError = Symbol.getName();
    if (!NameOrError)
      report_error(NameOrError.takeError(), info->O->getFileName());
    StringRef Name = *NameOrError;
    if (!Name.empty()) {
      SymbolName = Name.data();
      return SymbolName;
    }
  }

  // TODO: For fully linked images, look through the external relocation
  // entries off the dynamic symtab command. For these the r_offset is from the
  // start of the first writeable segment in the Mach-O file.  So the offset
  // to this section from that segment is passed to this routine by the caller,
  // as the database_offset. Which is the difference of the section's starting
  // address and the first writable segment.
  //
  // NOTE: need add passing the database_offset to this routine.

  // We did not find an external relocation entry so look up the ReferenceValue
  // as an address of a symbol and if found return that symbol's name.
  SymbolName = GuessSymbolName(ReferenceValue, info->AddrMap);

  return SymbolName;
}

// These are structs in the Objective-C meta data and read to produce the
// comments for disassembly.  While these are part of the ABI they are no
// public defintions.  So the are here not in include/llvm/BinaryFormat/MachO.h
// .

// The cfstring object in a 64-bit Mach-O file.
struct cfstring64_t {
  uint64_t isa;        // class64_t * (64-bit pointer)
  uint64_t flags;      // flag bits
  uint64_t characters; // char * (64-bit pointer)
  uint64_t length;     // number of non-NULL characters in above
};

// The class object in a 64-bit Mach-O file.
struct class64_t {
  uint64_t isa;        // class64_t * (64-bit pointer)
  uint64_t superclass; // class64_t * (64-bit pointer)
  uint64_t cache;      // Cache (64-bit pointer)
  uint64_t vtable;     // IMP * (64-bit pointer)
  uint64_t data;       // class_ro64_t * (64-bit pointer)
};

struct class32_t {
  uint32_t isa;        /* class32_t * (32-bit pointer) */
  uint32_t superclass; /* class32_t * (32-bit pointer) */
  uint32_t cache;      /* Cache (32-bit pointer) */
  uint32_t vtable;     /* IMP * (32-bit pointer) */
  uint32_t data;       /* class_ro32_t * (32-bit pointer) */
};

struct class_ro64_t {
  uint32_t flags;
  uint32_t instanceStart;
  uint32_t instanceSize;
  uint32_t reserved;
  uint64_t ivarLayout;     // const uint8_t * (64-bit pointer)
  uint64_t name;           // const char * (64-bit pointer)
  uint64_t baseMethods;    // const method_list_t * (64-bit pointer)
  uint64_t baseProtocols;  // const protocol_list_t * (64-bit pointer)
  uint64_t ivars;          // const ivar_list_t * (64-bit pointer)
  uint64_t weakIvarLayout; // const uint8_t * (64-bit pointer)
  uint64_t baseProperties; // const struct objc_property_list (64-bit pointer)
};

struct class_ro32_t {
  uint32_t flags;
  uint32_t instanceStart;
  uint32_t instanceSize;
  uint32_t ivarLayout;     /* const uint8_t * (32-bit pointer) */
  uint32_t name;           /* const char * (32-bit pointer) */
  uint32_t baseMethods;    /* const method_list_t * (32-bit pointer) */
  uint32_t baseProtocols;  /* const protocol_list_t * (32-bit pointer) */
  uint32_t ivars;          /* const ivar_list_t * (32-bit pointer) */
  uint32_t weakIvarLayout; /* const uint8_t * (32-bit pointer) */
  uint32_t baseProperties; /* const struct objc_property_list *
                                                   (32-bit pointer) */
};

/* Values for class_ro{64,32}_t->flags */
#define RO_META (1 << 0)
#define RO_ROOT (1 << 1)
#define RO_HAS_CXX_STRUCTORS (1 << 2)

struct method_list64_t {
  uint32_t entsize;
  uint32_t count;
  /* struct method64_t first;  These structures follow inline */
};

struct method_list32_t {
  uint32_t entsize;
  uint32_t count;
  /* struct method32_t first;  These structures follow inline */
};

struct method64_t {
  uint64_t name;  /* SEL (64-bit pointer) */
  uint64_t types; /* const char * (64-bit pointer) */
  uint64_t imp;   /* IMP (64-bit pointer) */
};

struct method32_t {
  uint32_t name;  /* SEL (32-bit pointer) */
  uint32_t types; /* const char * (32-bit pointer) */
  uint32_t imp;   /* IMP (32-bit pointer) */
};

struct protocol_list64_t {
  uint64_t count; /* uintptr_t (a 64-bit value) */
  /* struct protocol64_t * list[0];  These pointers follow inline */
};

struct protocol_list32_t {
  uint32_t count; /* uintptr_t (a 32-bit value) */
  /* struct protocol32_t * list[0];  These pointers follow inline */
};

struct protocol64_t {
  uint64_t isa;                     /* id * (64-bit pointer) */
  uint64_t name;                    /* const char * (64-bit pointer) */
  uint64_t protocols;               /* struct protocol_list64_t *
                                                    (64-bit pointer) */
  uint64_t instanceMethods;         /* method_list_t * (64-bit pointer) */
  uint64_t classMethods;            /* method_list_t * (64-bit pointer) */
  uint64_t optionalInstanceMethods; /* method_list_t * (64-bit pointer) */
  uint64_t optionalClassMethods;    /* method_list_t * (64-bit pointer) */
  uint64_t instanceProperties;      /* struct objc_property_list *
                                                       (64-bit pointer) */
};

struct protocol32_t {
  uint32_t isa;                     /* id * (32-bit pointer) */
  uint32_t name;                    /* const char * (32-bit pointer) */
  uint32_t protocols;               /* struct protocol_list_t *
                                                    (32-bit pointer) */
  uint32_t instanceMethods;         /* method_list_t * (32-bit pointer) */
  uint32_t classMethods;            /* method_list_t * (32-bit pointer) */
  uint32_t optionalInstanceMethods; /* method_list_t * (32-bit pointer) */
  uint32_t optionalClassMethods;    /* method_list_t * (32-bit pointer) */
  uint32_t instanceProperties;      /* struct objc_property_list *
                                                       (32-bit pointer) */
};

struct ivar_list64_t {
  uint32_t entsize;
  uint32_t count;
  /* struct ivar64_t first;  These structures follow inline */
};

struct ivar_list32_t {
  uint32_t entsize;
  uint32_t count;
  /* struct ivar32_t first;  These structures follow inline */
};

struct ivar64_t {
  uint64_t offset; /* uintptr_t * (64-bit pointer) */
  uint64_t name;   /* const char * (64-bit pointer) */
  uint64_t type;   /* const char * (64-bit pointer) */
  uint32_t alignment;
  uint32_t size;
};

struct ivar32_t {
  uint32_t offset; /* uintptr_t * (32-bit pointer) */
  uint32_t name;   /* const char * (32-bit pointer) */
  uint32_t type;   /* const char * (32-bit pointer) */
  uint32_t alignment;
  uint32_t size;
};

struct objc_property_list64 {
  uint32_t entsize;
  uint32_t count;
  /* struct objc_property64 first;  These structures follow inline */
};

struct objc_property_list32 {
  uint32_t entsize;
  uint32_t count;
  /* struct objc_property32 first;  These structures follow inline */
};

struct objc_property64 {
  uint64_t name;       /* const char * (64-bit pointer) */
  uint64_t attributes; /* const char * (64-bit pointer) */
};

struct objc_property32 {
  uint32_t name;       /* const char * (32-bit pointer) */
  uint32_t attributes; /* const char * (32-bit pointer) */
};

struct category64_t {
  uint64_t name;               /* const char * (64-bit pointer) */
  uint64_t cls;                /* struct class_t * (64-bit pointer) */
  uint64_t instanceMethods;    /* struct method_list_t * (64-bit pointer) */
  uint64_t classMethods;       /* struct method_list_t * (64-bit pointer) */
  uint64_t protocols;          /* struct protocol_list_t * (64-bit pointer) */
  uint64_t instanceProperties; /* struct objc_property_list *
                                  (64-bit pointer) */
};

struct category32_t {
  uint32_t name;               /* const char * (32-bit pointer) */
  uint32_t cls;                /* struct class_t * (32-bit pointer) */
  uint32_t instanceMethods;    /* struct method_list_t * (32-bit pointer) */
  uint32_t classMethods;       /* struct method_list_t * (32-bit pointer) */
  uint32_t protocols;          /* struct protocol_list_t * (32-bit pointer) */
  uint32_t instanceProperties; /* struct objc_property_list *
                                  (32-bit pointer) */
};

struct objc_image_info64 {
  uint32_t version;
  uint32_t flags;
};
struct objc_image_info32 {
  uint32_t version;
  uint32_t flags;
};
struct imageInfo_t {
  uint32_t version;
  uint32_t flags;
};
/* masks for objc_image_info.flags */
#define OBJC_IMAGE_IS_REPLACEMENT (1 << 0)
#define OBJC_IMAGE_SUPPORTS_GC (1 << 1)

struct message_ref64 {
  uint64_t imp; /* IMP (64-bit pointer) */
  uint64_t sel; /* SEL (64-bit pointer) */
};

struct message_ref32 {
  uint32_t imp; /* IMP (32-bit pointer) */
  uint32_t sel; /* SEL (32-bit pointer) */
};

// Objective-C 1 (32-bit only) meta data structs.

struct objc_module_t {
  uint32_t version;
  uint32_t size;
  uint32_t name;   /* char * (32-bit pointer) */
  uint32_t symtab; /* struct objc_symtab * (32-bit pointer) */
};

struct objc_symtab_t {
  uint32_t sel_ref_cnt;
  uint32_t refs; /* SEL * (32-bit pointer) */
  uint16_t cls_def_cnt;
  uint16_t cat_def_cnt;
  // uint32_t defs[1];        /* void * (32-bit pointer) variable size */
};

struct objc_class_t {
  uint32_t isa;         /* struct objc_class * (32-bit pointer) */
  uint32_t super_class; /* struct objc_class * (32-bit pointer) */
  uint32_t name;        /* const char * (32-bit pointer) */
  int32_t version;
  int32_t info;
  int32_t instance_size;
  uint32_t ivars;       /* struct objc_ivar_list * (32-bit pointer) */
  uint32_t methodLists; /* struct objc_method_list ** (32-bit pointer) */
  uint32_t cache;       /* struct objc_cache * (32-bit pointer) */
  uint32_t protocols;   /* struct objc_protocol_list * (32-bit pointer) */
};

#define CLS_GETINFO(cls, infomask) ((cls)->info & (infomask))
// class is not a metaclass
#define CLS_CLASS 0x1
// class is a metaclass
#define CLS_META 0x2

struct objc_category_t {
  uint32_t category_name;    /* char * (32-bit pointer) */
  uint32_t class_name;       /* char * (32-bit pointer) */
  uint32_t instance_methods; /* struct objc_method_list * (32-bit pointer) */
  uint32_t class_methods;    /* struct objc_method_list * (32-bit pointer) */
  uint32_t protocols;        /* struct objc_protocol_list * (32-bit ptr) */
};

struct objc_ivar_t {
  uint32_t ivar_name; /* char * (32-bit pointer) */
  uint32_t ivar_type; /* char * (32-bit pointer) */
  int32_t ivar_offset;
};

struct objc_ivar_list_t {
  int32_t ivar_count;
  // struct objc_ivar_t ivar_list[1];          /* variable length structure */
};

struct objc_method_list_t {
  uint32_t obsolete; /* struct objc_method_list * (32-bit pointer) */
  int32_t method_count;
  // struct objc_method_t method_list[1];      /* variable length structure */
};

struct objc_method_t {
  uint32_t method_name;  /* SEL, aka struct objc_selector * (32-bit pointer) */
  uint32_t method_types; /* char * (32-bit pointer) */
  uint32_t method_imp;   /* IMP, aka function pointer, (*IMP)(id, SEL, ...)
                            (32-bit pointer) */
};

struct objc_protocol_list_t {
  uint32_t next; /* struct objc_protocol_list * (32-bit pointer) */
  int32_t count;
  // uint32_t list[1];   /* Protocol *, aka struct objc_protocol_t *
  //                        (32-bit pointer) */
};

struct objc_protocol_t {
  uint32_t isa;              /* struct objc_class * (32-bit pointer) */
  uint32_t protocol_name;    /* char * (32-bit pointer) */
  uint32_t protocol_list;    /* struct objc_protocol_list * (32-bit pointer) */
  uint32_t instance_methods; /* struct objc_method_description_list *
                                (32-bit pointer) */
  uint32_t class_methods;    /* struct objc_method_description_list *
                                (32-bit pointer) */
};

struct objc_method_description_list_t {
  int32_t count;
  // struct objc_method_description_t list[1];
};

struct objc_method_description_t {
  uint32_t name;  /* SEL, aka struct objc_selector * (32-bit pointer) */
  uint32_t types; /* char * (32-bit pointer) */
};

inline void swapStruct(struct cfstring64_t &cfs) {
  sys::swapByteOrder(cfs.isa);
  sys::swapByteOrder(cfs.flags);
  sys::swapByteOrder(cfs.characters);
  sys::swapByteOrder(cfs.length);
}

inline void swapStruct(struct class64_t &c) {
  sys::swapByteOrder(c.isa);
  sys::swapByteOrder(c.superclass);
  sys::swapByteOrder(c.cache);
  sys::swapByteOrder(c.vtable);
  sys::swapByteOrder(c.data);
}

inline void swapStruct(struct class32_t &c) {
  sys::swapByteOrder(c.isa);
  sys::swapByteOrder(c.superclass);
  sys::swapByteOrder(c.cache);
  sys::swapByteOrder(c.vtable);
  sys::swapByteOrder(c.data);
}

inline void swapStruct(struct class_ro64_t &cro) {
  sys::swapByteOrder(cro.flags);
  sys::swapByteOrder(cro.instanceStart);
  sys::swapByteOrder(cro.instanceSize);
  sys::swapByteOrder(cro.reserved);
  sys::swapByteOrder(cro.ivarLayout);
  sys::swapByteOrder(cro.name);
  sys::swapByteOrder(cro.baseMethods);
  sys::swapByteOrder(cro.baseProtocols);
  sys::swapByteOrder(cro.ivars);
  sys::swapByteOrder(cro.weakIvarLayout);
  sys::swapByteOrder(cro.baseProperties);
}

inline void swapStruct(struct class_ro32_t &cro) {
  sys::swapByteOrder(cro.flags);
  sys::swapByteOrder(cro.instanceStart);
  sys::swapByteOrder(cro.instanceSize);
  sys::swapByteOrder(cro.ivarLayout);
  sys::swapByteOrder(cro.name);
  sys::swapByteOrder(cro.baseMethods);
  sys::swapByteOrder(cro.baseProtocols);
  sys::swapByteOrder(cro.ivars);
  sys::swapByteOrder(cro.weakIvarLayout);
  sys::swapByteOrder(cro.baseProperties);
}

inline void swapStruct(struct method_list64_t &ml) {
  sys::swapByteOrder(ml.entsize);
  sys::swapByteOrder(ml.count);
}

inline void swapStruct(struct method_list32_t &ml) {
  sys::swapByteOrder(ml.entsize);
  sys::swapByteOrder(ml.count);
}

inline void swapStruct(struct method64_t &m) {
  sys::swapByteOrder(m.name);
  sys::swapByteOrder(m.types);
  sys::swapByteOrder(m.imp);
}

inline void swapStruct(struct method32_t &m) {
  sys::swapByteOrder(m.name);
  sys::swapByteOrder(m.types);
  sys::swapByteOrder(m.imp);
}

inline void swapStruct(struct protocol_list64_t &pl) {
  sys::swapByteOrder(pl.count);
}

inline void swapStruct(struct protocol_list32_t &pl) {
  sys::swapByteOrder(pl.count);
}

inline void swapStruct(struct protocol64_t &p) {
  sys::swapByteOrder(p.isa);
  sys::swapByteOrder(p.name);
  sys::swapByteOrder(p.protocols);
  sys::swapByteOrder(p.instanceMethods);
  sys::swapByteOrder(p.classMethods);
  sys::swapByteOrder(p.optionalInstanceMethods);
  sys::swapByteOrder(p.optionalClassMethods);
  sys::swapByteOrder(p.instanceProperties);
}

inline void swapStruct(struct protocol32_t &p) {
  sys::swapByteOrder(p.isa);
  sys::swapByteOrder(p.name);
  sys::swapByteOrder(p.protocols);
  sys::swapByteOrder(p.instanceMethods);
  sys::swapByteOrder(p.classMethods);
  sys::swapByteOrder(p.optionalInstanceMethods);
  sys::swapByteOrder(p.optionalClassMethods);
  sys::swapByteOrder(p.instanceProperties);
}

inline void swapStruct(struct ivar_list64_t &il) {
  sys::swapByteOrder(il.entsize);
  sys::swapByteOrder(il.count);
}

inline void swapStruct(struct ivar_list32_t &il) {
  sys::swapByteOrder(il.entsize);
  sys::swapByteOrder(il.count);
}

inline void swapStruct(struct ivar64_t &i) {
  sys::swapByteOrder(i.offset);
  sys::swapByteOrder(i.name);
  sys::swapByteOrder(i.type);
  sys::swapByteOrder(i.alignment);
  sys::swapByteOrder(i.size);
}

inline void swapStruct(struct ivar32_t &i) {
  sys::swapByteOrder(i.offset);
  sys::swapByteOrder(i.name);
  sys::swapByteOrder(i.type);
  sys::swapByteOrder(i.alignment);
  sys::swapByteOrder(i.size);
}

inline void swapStruct(struct objc_property_list64 &pl) {
  sys::swapByteOrder(pl.entsize);
  sys::swapByteOrder(pl.count);
}

inline void swapStruct(struct objc_property_list32 &pl) {
  sys::swapByteOrder(pl.entsize);
  sys::swapByteOrder(pl.count);
}

inline void swapStruct(struct objc_property64 &op) {
  sys::swapByteOrder(op.name);
  sys::swapByteOrder(op.attributes);
}

inline void swapStruct(struct objc_property32 &op) {
  sys::swapByteOrder(op.name);
  sys::swapByteOrder(op.attributes);
}

inline void swapStruct(struct category64_t &c) {
  sys::swapByteOrder(c.name);
  sys::swapByteOrder(c.cls);
  sys::swapByteOrder(c.instanceMethods);
  sys::swapByteOrder(c.classMethods);
  sys::swapByteOrder(c.protocols);
  sys::swapByteOrder(c.instanceProperties);
}

inline void swapStruct(struct category32_t &c) {
  sys::swapByteOrder(c.name);
  sys::swapByteOrder(c.cls);
  sys::swapByteOrder(c.instanceMethods);
  sys::swapByteOrder(c.classMethods);
  sys::swapByteOrder(c.protocols);
  sys::swapByteOrder(c.instanceProperties);
}

inline void swapStruct(struct objc_image_info64 &o) {
  sys::swapByteOrder(o.version);
  sys::swapByteOrder(o.flags);
}

inline void swapStruct(struct objc_image_info32 &o) {
  sys::swapByteOrder(o.version);
  sys::swapByteOrder(o.flags);
}

inline void swapStruct(struct imageInfo_t &o) {
  sys::swapByteOrder(o.version);
  sys::swapByteOrder(o.flags);
}

inline void swapStruct(struct message_ref64 &mr) {
  sys::swapByteOrder(mr.imp);
  sys::swapByteOrder(mr.sel);
}

inline void swapStruct(struct message_ref32 &mr) {
  sys::swapByteOrder(mr.imp);
  sys::swapByteOrder(mr.sel);
}

inline void swapStruct(struct objc_module_t &module) {
  sys::swapByteOrder(module.version);
  sys::swapByteOrder(module.size);
  sys::swapByteOrder(module.name);
  sys::swapByteOrder(module.symtab);
}

inline void swapStruct(struct objc_symtab_t &symtab) {
  sys::swapByteOrder(symtab.sel_ref_cnt);
  sys::swapByteOrder(symtab.refs);
  sys::swapByteOrder(symtab.cls_def_cnt);
  sys::swapByteOrder(symtab.cat_def_cnt);
}

inline void swapStruct(struct objc_class_t &objc_class) {
  sys::swapByteOrder(objc_class.isa);
  sys::swapByteOrder(objc_class.super_class);
  sys::swapByteOrder(objc_class.name);
  sys::swapByteOrder(objc_class.version);
  sys::swapByteOrder(objc_class.info);
  sys::swapByteOrder(objc_class.instance_size);
  sys::swapByteOrder(objc_class.ivars);
  sys::swapByteOrder(objc_class.methodLists);
  sys::swapByteOrder(objc_class.cache);
  sys::swapByteOrder(objc_class.protocols);
}

inline void swapStruct(struct objc_category_t &objc_category) {
  sys::swapByteOrder(objc_category.category_name);
  sys::swapByteOrder(objc_category.class_name);
  sys::swapByteOrder(objc_category.instance_methods);
  sys::swapByteOrder(objc_category.class_methods);
  sys::swapByteOrder(objc_category.protocols);
}

inline void swapStruct(struct objc_ivar_list_t &objc_ivar_list) {
  sys::swapByteOrder(objc_ivar_list.ivar_count);
}

inline void swapStruct(struct objc_ivar_t &objc_ivar) {
  sys::swapByteOrder(objc_ivar.ivar_name);
  sys::swapByteOrder(objc_ivar.ivar_type);
  sys::swapByteOrder(objc_ivar.ivar_offset);
}

inline void swapStruct(struct objc_method_list_t &method_list) {
  sys::swapByteOrder(method_list.obsolete);
  sys::swapByteOrder(method_list.method_count);
}

inline void swapStruct(struct objc_method_t &method) {
  sys::swapByteOrder(method.method_name);
  sys::swapByteOrder(method.method_types);
  sys::swapByteOrder(method.method_imp);
}

inline void swapStruct(struct objc_protocol_list_t &protocol_list) {
  sys::swapByteOrder(protocol_list.next);
  sys::swapByteOrder(protocol_list.count);
}

inline void swapStruct(struct objc_protocol_t &protocol) {
  sys::swapByteOrder(protocol.isa);
  sys::swapByteOrder(protocol.protocol_name);
  sys::swapByteOrder(protocol.protocol_list);
  sys::swapByteOrder(protocol.instance_methods);
  sys::swapByteOrder(protocol.class_methods);
}

inline void swapStruct(struct objc_method_description_list_t &mdl) {
  sys::swapByteOrder(mdl.count);
}

inline void swapStruct(struct objc_method_description_t &md) {
  sys::swapByteOrder(md.name);
  sys::swapByteOrder(md.types);
}

static const char *get_dyld_bind_info_symbolname(uint64_t ReferenceValue,
                                                 struct DisassembleInfo *info);

// get_objc2_64bit_class_name() is used for disassembly and is passed a pointer
// to an Objective-C class and returns the class name.  It is also passed the
// address of the pointer, so when the pointer is zero as it can be in an .o
// file, that is used to look for an external relocation entry with a symbol
// name.
static const char *get_objc2_64bit_class_name(uint64_t pointer_value,
                                              uint64_t ReferenceValue,
                                              struct DisassembleInfo *info) {
  const char *r;
  uint32_t offset, left;
  SectionRef S;

  // The pointer_value can be 0 in an object file and have a relocation
  // entry for the class symbol at the ReferenceValue (the address of the
  // pointer).
  if (pointer_value == 0) {
    r = get_pointer_64(ReferenceValue, offset, left, S, info);
    if (r == nullptr || left < sizeof(uint64_t))
      return nullptr;
    uint64_t n_value;
    const char *symbol_name = get_symbol_64(offset, S, info, n_value);
    if (symbol_name == nullptr)
      return nullptr;
    const char *class_name = strrchr(symbol_name, '$');
    if (class_name != nullptr && class_name[1] == '_' && class_name[2] != '\0')
      return class_name + 2;
    else
      return nullptr;
  }

  // The case were the pointer_value is non-zero and points to a class defined
  // in this Mach-O file.
  r = get_pointer_64(pointer_value, offset, left, S, info);
  if (r == nullptr || left < sizeof(struct class64_t))
    return nullptr;
  struct class64_t c;
  memcpy(&c, r, sizeof(struct class64_t));
  if (info->O->isLittleEndian() != sys::IsLittleEndianHost)
    swapStruct(c);
  if (c.data == 0)
    return nullptr;
  r = get_pointer_64(c.data, offset, left, S, info);
  if (r == nullptr || left < sizeof(struct class_ro64_t))
    return nullptr;
  struct class_ro64_t cro;
  memcpy(&cro, r, sizeof(struct class_ro64_t));
  if (info->O->isLittleEndian() != sys::IsLittleEndianHost)
    swapStruct(cro);
  if (cro.name == 0)
    return nullptr;
  const char *name = get_pointer_64(cro.name, offset, left, S, info);
  return name;
}

// get_objc2_64bit_cfstring_name is used for disassembly and is passed a
// pointer to a cfstring and returns its name or nullptr.
static const char *get_objc2_64bit_cfstring_name(uint64_t ReferenceValue,
                                                 struct DisassembleInfo *info) {
  const char *r, *name;
  uint32_t offset, left;
  SectionRef S;
  struct cfstring64_t cfs;
  uint64_t cfs_characters;

  r = get_pointer_64(ReferenceValue, offset, left, S, info);
  if (r == nullptr || left < sizeof(struct cfstring64_t))
    return nullptr;
  memcpy(&cfs, r, sizeof(struct cfstring64_t));
  if (info->O->isLittleEndian() != sys::IsLittleEndianHost)
    swapStruct(cfs);
  if (cfs.characters == 0) {
    uint64_t n_value;
    const char *symbol_name = get_symbol_64(
        offset + offsetof(struct cfstring64_t, characters), S, info, n_value);
    if (symbol_name == nullptr)
      return nullptr;
    cfs_characters = n_value;
  } else
    cfs_characters = cfs.characters;
  name = get_pointer_64(cfs_characters, offset, left, S, info);

  return name;
}

// get_objc2_64bit_selref() is used for disassembly and is passed a the address
// of a pointer to an Objective-C selector reference when the pointer value is
// zero as in a .o file and is likely to have a external relocation entry with
// who's symbol's n_value is the real pointer to the selector name.  If that is
// the case the real pointer to the selector name is returned else 0 is
// returned
static uint64_t get_objc2_64bit_selref(uint64_t ReferenceValue,
                                       struct DisassembleInfo *info) {
  uint32_t offset, left;
  SectionRef S;

  const char *r = get_pointer_64(ReferenceValue, offset, left, S, info);
  if (r == nullptr || left < sizeof(uint64_t))
    return 0;
  uint64_t n_value;
  const char *symbol_name = get_symbol_64(offset, S, info, n_value);
  if (symbol_name == nullptr)
    return 0;
  return n_value;
}

static void print_indent(uint32_t indent) {
  for (uint32_t i = 0; i < indent;) {
    if (indent - i >= 8) {
      outs() << "\t";
      i += 8;
    } else {
      for (uint32_t j = i; j < indent; j++)
        outs() << " ";
      return;
    }
  }
}

static bool print_method_description_list(uint32_t p, uint32_t indent,
                                          struct DisassembleInfo *info) {
  uint32_t offset, left, xleft;
  SectionRef S;
  struct objc_method_description_list_t mdl;
  struct objc_method_description_t md;
  const char *r, *list, *name;
  int32_t i;

  r = get_pointer_32(p, offset, left, S, info, true);
  if (r == nullptr)
    return true;

  outs() << "\n";
  if (left > sizeof(struct objc_method_description_list_t)) {
    memcpy(&mdl, r, sizeof(struct objc_method_description_list_t));
  } else {
    print_indent(indent);
    outs() << " objc_method_description_list extends past end of the section\n";
    memset(&mdl, '\0', sizeof(struct objc_method_description_list_t));
    memcpy(&mdl, r, left);
  }
  if (info->O->isLittleEndian() != sys::IsLittleEndianHost)
    swapStruct(mdl);

  print_indent(indent);
  outs() << "        count " << mdl.count << "\n";

  list = r + sizeof(struct objc_method_description_list_t);
  for (i = 0; i < mdl.count; i++) {
    if ((i + 1) * sizeof(struct objc_method_description_t) > left) {
      print_indent(indent);
      outs() << " remaining list entries extend past the of the section\n";
      break;
    }
    print_indent(indent);
    outs() << "        list[" << i << "]\n";
    memcpy(&md, list + i * sizeof(struct objc_method_description_t),
           sizeof(struct objc_method_description_t));
    if (info->O->isLittleEndian() != sys::IsLittleEndianHost)
      swapStruct(md);

    print_indent(indent);
    outs() << "             name " << format("0x%08" PRIx32, md.name);
    if (info->verbose) {
      name = get_pointer_32(md.name, offset, xleft, S, info, true);
      if (name != nullptr)
        outs() << format(" %.*s", xleft, name);
      else
        outs() << " (not in an __OBJC section)";
    }
    outs() << "\n";

    print_indent(indent);
    outs() << "            types " << format("0x%08" PRIx32, md.types);
    if (info->verbose) {
      name = get_pointer_32(md.types, offset, xleft, S, info, true);
      if (name != nullptr)
        outs() << format(" %.*s", xleft, name);
      else
        outs() << " (not in an __OBJC section)";
    }
    outs() << "\n";
  }
  return false;
}

static bool print_protocol_list(uint32_t p, uint32_t indent,
                                struct DisassembleInfo *info);

static bool print_protocol(uint32_t p, uint32_t indent,
                           struct DisassembleInfo *info) {
  uint32_t offset, left;
  SectionRef S;
  struct objc_protocol_t protocol;
  const char *r, *name;

  r = get_pointer_32(p, offset, left, S, info, true);
  if (r == nullptr)
    return true;

  outs() << "\n";
  if (left >= sizeof(struct objc_protocol_t)) {
    memcpy(&protocol, r, sizeof(struct objc_protocol_t));
  } else {
    print_indent(indent);
    outs() << "            Protocol extends past end of the section\n";
    memset(&protocol, '\0', sizeof(struct objc_protocol_t));
    memcpy(&protocol, r, left);
  }
  if (info->O->isLittleEndian() != sys::IsLittleEndianHost)
    swapStruct(protocol);

  print_indent(indent);
  outs() << "              isa " << format("0x%08" PRIx32, protocol.isa)
         << "\n";

  print_indent(indent);
  outs() << "    protocol_name "
         << format("0x%08" PRIx32, protocol.protocol_name);
  if (info->verbose) {
    name = get_pointer_32(protocol.protocol_name, offset, left, S, info, true);
    if (name != nullptr)
      outs() << format(" %.*s", left, name);
    else
      outs() << " (not in an __OBJC section)";
  }
  outs() << "\n";

  print_indent(indent);
  outs() << "    protocol_list "
         << format("0x%08" PRIx32, protocol.protocol_list);
  if (print_protocol_list(protocol.protocol_list, indent + 4, info))
    outs() << " (not in an __OBJC section)\n";

  print_indent(indent);
  outs() << " instance_methods "
         << format("0x%08" PRIx32, protocol.instance_methods);
  if (print_method_description_list(protocol.instance_methods, indent, info))
    outs() << " (not in an __OBJC section)\n";

  print_indent(indent);
  outs() << "    class_methods "
         << format("0x%08" PRIx32, protocol.class_methods);
  if (print_method_description_list(protocol.class_methods, indent, info))
    outs() << " (not in an __OBJC section)\n";

  return false;
}

static bool print_protocol_list(uint32_t p, uint32_t indent,
                                struct DisassembleInfo *info) {
  uint32_t offset, left, l;
  SectionRef S;
  struct objc_protocol_list_t protocol_list;
  const char *r, *list;
  int32_t i;

  r = get_pointer_32(p, offset, left, S, info, true);
  if (r == nullptr)
    return true;

  outs() << "\n";
  if (left > sizeof(struct objc_protocol_list_t)) {
    memcpy(&protocol_list, r, sizeof(struct objc_protocol_list_t));
  } else {
    outs() << "\t\t objc_protocol_list_t extends past end of the section\n";
    memset(&protocol_list, '\0', sizeof(struct objc_protocol_list_t));
    memcpy(&protocol_list, r, left);
  }
  if (info->O->isLittleEndian() != sys::IsLittleEndianHost)
    swapStruct(protocol_list);

  print_indent(indent);
  outs() << "         next " << format("0x%08" PRIx32, protocol_list.next)
         << "\n";
  print_indent(indent);
  outs() << "        count " << protocol_list.count << "\n";

  list = r + sizeof(struct objc_protocol_list_t);
  for (i = 0; i < protocol_list.count; i++) {
    if ((i + 1) * sizeof(uint32_t) > left) {
      outs() << "\t\t remaining list entries extend past the of the section\n";
      break;
    }
    memcpy(&l, list + i * sizeof(uint32_t), sizeof(uint32_t));
    if (info->O->isLittleEndian() != sys::IsLittleEndianHost)
      sys::swapByteOrder(l);

    print_indent(indent);
    outs() << "      list[" << i << "] " << format("0x%08" PRIx32, l);
    if (print_protocol(l, indent, info))
      outs() << "(not in an __OBJC section)\n";
  }
  return false;
}

static void DumpProtocolSection(MachOObjectFile *O, const char *sect,
                                uint32_t size, uint32_t addr) {
  SymbolAddressMap AddrMap;
  CreateSymbolAddressMap(O, &AddrMap);

  std::vector<SectionRef> Sections;
  for (const SectionRef &Section : O->sections()) {
    StringRef SectName;
    if (auto NameOrErr = Section.getName())
      SectName = *NameOrErr;
    else
      consumeError(NameOrErr.takeError());

    Sections.push_back(Section);
  }

  struct DisassembleInfo info;
  // Set up the block of info used by the Symbolizer call backs.
  info.verbose = true;
  info.O = O;
  info.AddrMap = &AddrMap;
  info.Sections = &Sections;
  info.class_name = nullptr;
  info.selector_name = nullptr;
  info.method = nullptr;
  info.demangled_name = nullptr;
  info.bindtable = nullptr;
  info.adrp_addr = 0;
  info.adrp_inst = 0;

  const char *p;
  struct objc_protocol_t protocol;
  uint32_t left, paddr;
  for (p = sect; p < sect + size; p += sizeof(struct objc_protocol_t)) {
    memset(&protocol, '\0', sizeof(struct objc_protocol_t));
    left = size - (p - sect);
    if (left < sizeof(struct objc_protocol_t)) {
      outs() << "Protocol extends past end of __protocol section\n";
      memcpy(&protocol, p, left);
    } else
      memcpy(&protocol, p, sizeof(struct objc_protocol_t));
    if (O->isLittleEndian() != sys::IsLittleEndianHost)
      swapStruct(protocol);
    paddr = addr + (p - sect);
    outs() << "Protocol " << format("0x%" PRIx32, paddr);
    if (print_protocol(paddr, 0, &info))
      outs() << "(not in an __OBJC section)\n";
  }
}

#ifdef HAVE_LIBXAR
inline void swapStruct(struct xar_header &xar) {
  sys::swapByteOrder(xar.magic);
  sys::swapByteOrder(xar.size);
  sys::swapByteOrder(xar.version);
  sys::swapByteOrder(xar.toc_length_compressed);
  sys::swapByteOrder(xar.toc_length_uncompressed);
  sys::swapByteOrder(xar.cksum_alg);
}

static void PrintModeVerbose(uint32_t mode) {
  switch (mode & S_IFMT) {
  case S_IFDIR:
    outs() << "d";
    break;
  case S_IFCHR:
    outs() << "c";
    break;
  case S_IFBLK:
    outs() << "b";
    break;
  case S_IFREG:
    outs() << "-";
    break;
  case S_IFLNK:
    outs() << "l";
    break;
  case S_IFSOCK:
    outs() << "s";
    break;
  default:
    outs() << "?";
    break;
  }

  /* owner permissions */
  if (mode & S_IREAD)
    outs() << "r";
  else
    outs() << "-";
  if (mode & S_IWRITE)
    outs() << "w";
  else
    outs() << "-";
  if (mode & S_ISUID)
    outs() << "s";
  else if (mode & S_IEXEC)
    outs() << "x";
  else
    outs() << "-";

  /* group permissions */
  if (mode & (S_IREAD >> 3))
    outs() << "r";
  else
    outs() << "-";
  if (mode & (S_IWRITE >> 3))
    outs() << "w";
  else
    outs() << "-";
  if (mode & S_ISGID)
    outs() << "s";
  else if (mode & (S_IEXEC >> 3))
    outs() << "x";
  else
    outs() << "-";

  /* other permissions */
  if (mode & (S_IREAD >> 6))
    outs() << "r";
  else
    outs() << "-";
  if (mode & (S_IWRITE >> 6))
    outs() << "w";
  else
    outs() << "-";
  if (mode & S_ISVTX)
    outs() << "t";
  else if (mode & (S_IEXEC >> 6))
    outs() << "x";
  else
    outs() << "-";
}

static void PrintXarFilesSummary(const char *XarFilename, xar_t xar) {
  xar_iter_t xi;
  xar_file_t xf;
  xar_iter_t xp;
  const char *key, *type, *mode, *user, *group, *size, *mtime, *name, *m;
  char *endp;
  uint32_t mode_value;

  xi = xar_iter_new();
  if (!xi) {
    errs() << "Can't obtain an xar iterator for xar archive " << XarFilename
           << "\n";
    return;
  }

  // Go through the xar's files.
  for (xf = xar_file_first(xar, xi); xf; xf = xar_file_next(xi)) {
    xp = xar_iter_new();
    if (!xp) {
      errs() << "Can't obtain an xar iterator for xar archive " << XarFilename
             << "\n";
      return;
    }
    type = nullptr;
    mode = nullptr;
    user = nullptr;
    group = nullptr;
    size = nullptr;
    mtime = nullptr;
    name = nullptr;
    for (key = xar_prop_first(xf, xp); key; key = xar_prop_next(xp)) {
      const char *val = nullptr;
      xar_prop_get(xf, key, &val);
#if 0 // Useful for debugging.
      outs() << "key: " << key << " value: " << val << "\n";
#endif
      if (strcmp(key, "type") == 0)
        type = val;
      if (strcmp(key, "mode") == 0)
        mode = val;
      if (strcmp(key, "user") == 0)
        user = val;
      if (strcmp(key, "group") == 0)
        group = val;
      if (strcmp(key, "data/size") == 0)
        size = val;
      if (strcmp(key, "mtime") == 0)
        mtime = val;
      if (strcmp(key, "name") == 0)
        name = val;
    }
    if (mode != nullptr) {
      mode_value = strtoul(mode, &endp, 8);
      if (*endp != '\0')
        outs() << "(mode: \"" << mode << "\" contains non-octal chars) ";
      if (strcmp(type, "file") == 0)
        mode_value |= S_IFREG;
      PrintModeVerbose(mode_value);
      outs() << " ";
    }
    if (user != nullptr)
      outs() << format("%10s/", user);
    if (group != nullptr)
      outs() << format("%-10s ", group);
    if (size != nullptr)
      outs() << format("%7s ", size);
    if (mtime != nullptr) {
      for (m = mtime; *m != 'T' && *m != '\0'; m++)
        outs() << *m;
      if (*m == 'T')
        m++;
      outs() << " ";
      for (; *m != 'Z' && *m != '\0'; m++)
        outs() << *m;
      outs() << " ";
    }
    if (name != nullptr)
      outs() << name;
    outs() << "\n";
  }
}

static void DumpBitcodeSection(MachOObjectFile *O, const char *sect,
                               uint32_t size, bool verbose, bool PrintXarHeader,
                               bool PrintXarFileHeaders,
                               std::string XarMemberName) {
  if (size < sizeof(struct xar_header)) {
    outs() << "size of (__LLVM,__bundle) section too small (smaller than size "
              "of struct xar_header)\n";
    return;
  }
  struct xar_header XarHeader;
  memcpy(&XarHeader, sect, sizeof(struct xar_header));
  if (sys::IsLittleEndianHost)
    swapStruct(XarHeader);
  if (PrintXarHeader) {
    if (!XarMemberName.empty())
      outs() << "In xar member " << XarMemberName << ": ";
    else
      outs() << "For (__LLVM,__bundle) section: ";
    outs() << "xar header\n";
    if (XarHeader.magic == XAR_HEADER_MAGIC)
      outs() << "                  magic XAR_HEADER_MAGIC\n";
    else
      outs() << "                  magic "
             << format_hex(XarHeader.magic, 10, true)
             << " (not XAR_HEADER_MAGIC)\n";
    outs() << "                   size " << XarHeader.size << "\n";
    outs() << "                version " << XarHeader.version << "\n";
    outs() << "  toc_length_compressed " << XarHeader.toc_length_compressed
           << "\n";
    outs() << "toc_length_uncompressed " << XarHeader.toc_length_uncompressed
           << "\n";
    outs() << "              cksum_alg ";
    switch (XarHeader.cksum_alg) {
    case XAR_CKSUM_NONE:
      outs() << "XAR_CKSUM_NONE\n";
      break;
    case XAR_CKSUM_SHA1:
      outs() << "XAR_CKSUM_SHA1\n";
      break;
    case XAR_CKSUM_MD5:
      outs() << "XAR_CKSUM_MD5\n";
      break;
#ifdef XAR_CKSUM_SHA256
    case XAR_CKSUM_SHA256:
      outs() << "XAR_CKSUM_SHA256\n";
      break;
#endif
#ifdef XAR_CKSUM_SHA512
    case XAR_CKSUM_SHA512:
      outs() << "XAR_CKSUM_SHA512\n";
      break;
#endif
    default:
      outs() << XarHeader.cksum_alg << "\n";
    }
  }

  SmallString<128> XarFilename;
  int FD;
  std::error_code XarEC =
      sys::fs::createTemporaryFile("llvm-mctoll", "xar", FD, XarFilename);
  if (XarEC) {
    errs() << XarEC.message() << "\n";
    return;
  }
  ToolOutputFile XarFile(XarFilename, FD);
  raw_fd_ostream &XarOut = XarFile.os();
  StringRef XarContents(sect, size);
  XarOut << XarContents;
  XarOut.close();
  if (XarOut.has_error())
    return;

  xar_t xar = xar_open(XarFilename.c_str(), READ);
  if (!xar) {
    errs() << "Can't create temporary xar archive " << XarFilename << "\n";
    return;
  }

  SmallString<128> TocFilename;
  std::error_code TocEC =
      sys::fs::createTemporaryFile("llvm-mctoll", "toc", TocFilename);
  if (TocEC) {
    errs() << TocEC.message() << "\n";
    return;
  }
  xar_serialize(xar, TocFilename.c_str());

  if (PrintXarFileHeaders) {
    if (!XarMemberName.empty())
      outs() << "In xar member " << XarMemberName << ": ";
    else
      outs() << "For (__LLVM,__bundle) section: ";
    outs() << "xar archive files:\n";
    PrintXarFilesSummary(XarFilename.c_str(), xar);
  }

  ErrorOr<std::unique_ptr<MemoryBuffer>> FileOrErr =
      MemoryBuffer::getFileOrSTDIN(TocFilename.c_str());
  if (std::error_code EC = FileOrErr.getError()) {
    errs() << EC.message() << "\n";
    return;
  }
  std::unique_ptr<MemoryBuffer> &Buffer = FileOrErr.get();

  if (!XarMemberName.empty())
    outs() << "In xar member " << XarMemberName << ": ";
  else
    outs() << "For (__LLVM,__bundle) section: ";
  outs() << "xar table of contents:\n";
  outs() << Buffer->getBuffer() << "\n";

  // TODO: Go through the xar's files.
  xar_iter_t xi = xar_iter_new();
  if (!xi) {
    errs() << "Can't obtain an xar iterator for xar archive "
           << XarFilename.c_str() << "\n";
    xar_close(xar);
    return;
  }
  for (xar_file_t xf = xar_file_first(xar, xi); xf; xf = xar_file_next(xi)) {
    const char *key;
    xar_iter_t xp;
    const char *member_name, *member_type, *member_size_string;
    size_t member_size;

    xp = xar_iter_new();
    if (!xp) {
      errs() << "Can't obtain an xar iterator for xar archive "
             << XarFilename.c_str() << "\n";
      xar_close(xar);
      return;
    }
    member_name = NULL;
    member_type = NULL;
    member_size_string = NULL;
    for (key = xar_prop_first(xf, xp); key; key = xar_prop_next(xp)) {
      const char *val = nullptr;
      xar_prop_get(xf, key, &val);
#if 0 // Useful for debugging.
      outs() << "key: " << key << " value: " << val << "\n";
#endif
      if (strcmp(key, "name") == 0)
        member_name = val;
      if (strcmp(key, "type") == 0)
        member_type = val;
      if (strcmp(key, "data/size") == 0)
        member_size_string = val;
    }
    /*
     * If we find a file with a name, date/size and type properties
     * and with the type being "file" see if that is a xar file.
     */
    if (member_name != NULL && member_type != NULL &&
        strcmp(member_type, "file") == 0 && member_size_string != NULL) {
      // Extract the file into a buffer.
      char *endptr;
      member_size = strtoul(member_size_string, &endptr, 10);
      if (*endptr == '\0' && member_size != 0) {
        char *buffer = (char *)::operator new(member_size);
        if (xar_extract_tobuffersz(xar, xf, &buffer, &member_size) == 0) {
#if 0 // Useful for debugging.
          outs() << "xar member: " << member_name << " extracted\n";
#endif
          // Set the XarMemberName we want to see printed in the header.
          std::string OldXarMemberName;
          // If XarMemberName is already set this is nested. So
          // save the old name and create the nested name.
          if (!XarMemberName.empty()) {
            OldXarMemberName = XarMemberName;
            XarMemberName =
                (Twine("[") + XarMemberName + "]" + member_name).str();
          } else {
            OldXarMemberName = "";
            XarMemberName = member_name;
          }
          // See if this is could be a xar file (nested).
          if (member_size >= sizeof(struct xar_header)) {
#if 0 // Useful for debugging.
            outs() << "could be a xar file: " << member_name << "\n";
#endif
            memcpy((char *)&XarHeader, buffer, sizeof(struct xar_header));
            if (sys::IsLittleEndianHost)
              swapStruct(XarHeader);
            if (XarHeader.magic == XAR_HEADER_MAGIC)
              DumpBitcodeSection(O, buffer, member_size, verbose,
                                 PrintXarHeader, PrintXarFileHeaders,
                                 XarMemberName);
          }
          XarMemberName = OldXarMemberName;
        }
        delete buffer;
      }
    }
    xar_iter_free(xp);
  }
  xar_close(xar);
}
#endif // defined(HAVE_LIBXAR)

// GuessLiteralPointer returns a string which for the item in the Mach-O file
// for the address passed in as ReferenceValue for printing as a comment with
// the instruction and also returns the corresponding type of that item
// indirectly through ReferenceType.
//
// If ReferenceValue is an address of literal cstring then a pointer to the
// cstring is returned and ReferenceType is set to
// LLVMDisassembler_ReferenceType_Out_LitPool_CstrAddr .
//
// If ReferenceValue is an address of an Objective-C CFString, Selector ref or
// Class ref that name is returned and the ReferenceType is set accordingly.
//
// Lastly, literals which are Symbol address in a literal pool are looked for
// and if found the symbol name is returned and ReferenceType is set to
// LLVMDisassembler_ReferenceType_Out_LitPool_SymAddr .
//
// If there is no item in the Mach-O file for the address passed in as
// ReferenceValue nullptr is returned and ReferenceType is unchanged.
static const char *GuessLiteralPointer(uint64_t ReferenceValue,
                                       uint64_t ReferencePC,
                                       uint64_t *ReferenceType,
                                       struct DisassembleInfo *info) {
  // First see if there is an external relocation entry at the ReferencePC.
  if (info->O->getHeader().filetype == MachO::MH_OBJECT) {
    uint64_t sect_addr = info->S.getAddress();
    uint64_t sect_offset = ReferencePC - sect_addr;
    bool reloc_found = false;
    DataRefImpl Rel;
    MachO::any_relocation_info RE;
    bool isExtern = false;
    SymbolRef Symbol;
    for (const RelocationRef &Reloc : info->S.relocations()) {
      uint64_t RelocOffset = Reloc.getOffset();
      if (RelocOffset == sect_offset) {
        Rel = Reloc.getRawDataRefImpl();
        RE = info->O->getRelocation(Rel);
        if (info->O->isRelocationScattered(RE))
          continue;
        isExtern = info->O->getPlainRelocationExternal(RE);
        if (isExtern) {
          symbol_iterator RelocSym = Reloc.getSymbol();
          Symbol = *RelocSym;
        }
        reloc_found = true;
        break;
      }
    }
    // If there is an external relocation entry for a symbol in a section
    // then used that symbol's value for the value of the reference.
    if (reloc_found && isExtern) {
      if (info->O->getAnyRelocationPCRel(RE)) {
        unsigned Type = info->O->getAnyRelocationType(RE);
        if (Type == MachO::X86_64_RELOC_SIGNED) {
          auto SymOrErr = Symbol.getValue();
          if (!SymOrErr)
            report_error(SymOrErr.takeError(),
                         Symbol.getObject()->getFileName());
          ReferenceValue = *SymOrErr;
        }
      }
    }
  }

  // Look for literals such as Objective-C CFStrings refs, Selector refs,
  // Message refs and Class refs.
  bool classref, selref, msgref, cfstring;
  uint64_t pointer_value = GuessPointerPointer(ReferenceValue, info, classref,
                                               selref, msgref, cfstring);
  if (classref && pointer_value == 0) {
    // Note the ReferenceValue is a pointer into the __objc_classrefs section.
    // And the pointer_value in that section is typically zero as it will be
    // set by dyld as part of the "bind information".
    const char *name = get_dyld_bind_info_symbolname(ReferenceValue, info);
    if (name != nullptr) {
      *ReferenceType = LLVMDisassembler_ReferenceType_Out_Objc_Class_Ref;
      const char *class_name = strrchr(name, '$');
      if (class_name != nullptr && class_name[1] == '_' &&
          class_name[2] != '\0') {
        info->class_name = class_name + 2;
        return name;
      }
    }
  }

  if (classref) {
    *ReferenceType = LLVMDisassembler_ReferenceType_Out_Objc_Class_Ref;
    const char *name =
        get_objc2_64bit_class_name(pointer_value, ReferenceValue, info);
    if (name != nullptr)
      info->class_name = name;
    else
      name = "bad class ref";
    return name;
  }

  if (cfstring) {
    *ReferenceType = LLVMDisassembler_ReferenceType_Out_Objc_CFString_Ref;
    const char *name = get_objc2_64bit_cfstring_name(ReferenceValue, info);
    return name;
  }

  if (selref && pointer_value == 0)
    pointer_value = get_objc2_64bit_selref(ReferenceValue, info);

  if (pointer_value != 0)
    ReferenceValue = pointer_value;

  const char *name = GuessCstringPointer(ReferenceValue, info);
  if (name) {
    if (pointer_value != 0 && selref) {
      *ReferenceType = LLVMDisassembler_ReferenceType_Out_Objc_Selector_Ref;
      info->selector_name = name;
    } else if (pointer_value != 0 && msgref) {
      info->class_name = nullptr;
      *ReferenceType = LLVMDisassembler_ReferenceType_Out_Objc_Message_Ref;
      info->selector_name = name;
    } else
      *ReferenceType = LLVMDisassembler_ReferenceType_Out_LitPool_CstrAddr;
    return name;
  }

  // Lastly look for an indirect symbol with this ReferenceValue which is in
  // a literal pool.  If found return that symbol name.
  name = GuessIndirectSymbol(ReferenceValue, info);
  if (name) {
    *ReferenceType = LLVMDisassembler_ReferenceType_Out_LitPool_SymAddr;
    return name;
  }

  return nullptr;
}

// SymbolizerSymbolLookUp is the symbol lookup function passed when creating
// the Symbolizer.  It looks up the ReferenceValue using the info passed via the
// pointer to the struct DisassembleInfo that was passed when MCSymbolizer
// is created and returns the symbol name that matches the ReferenceValue or
// nullptr if none.  The ReferenceType is passed in for the IN type of
// reference the instruction is making from the values in defined in the header
// "llvm-c/Disassembler.h".  On return the ReferenceType can set to a specific
// Out type and the ReferenceName will also be set which is added as a comment
// to the disassembled instruction.
//
// If the symbol name is a C++ mangled name then the demangled name is
// returned through ReferenceName and ReferenceType is set to
// LLVMDisassembler_ReferenceType_DeMangled_Name .
//
// When this is called to get a symbol name for a branch target then the
// ReferenceType will be LLVMDisassembler_ReferenceType_In_Branch and then
// SymbolValue will be looked for in the indirect symbol table to determine if
// it is an address for a symbol stub.  If so then the symbol name for that
// stub is returned indirectly through ReferenceName and then ReferenceType is
// set to LLVMDisassembler_ReferenceType_Out_SymbolStub.
//
// When this is called with an value loaded via a PC relative load then
// ReferenceType will be LLVMDisassembler_ReferenceType_In_PCrel_Load then the
// SymbolValue is checked to be an address of literal pointer, symbol pointer,
// or an Objective-C meta data reference.  If so the output ReferenceType is
// set to correspond to that as well as setting the ReferenceName.
static const char *SymbolizerSymbolLookUp(void *DisInfo,
                                          uint64_t ReferenceValue,
                                          uint64_t *ReferenceType,
                                          uint64_t ReferencePC,
                                          const char **ReferenceName) {
  struct DisassembleInfo *info = (struct DisassembleInfo *)DisInfo;
  // If no verbose symbolic information is wanted then just return nullptr.
  if (!info->verbose) {
    *ReferenceName = nullptr;
    *ReferenceType = LLVMDisassembler_ReferenceType_InOut_None;
    return nullptr;
  }

  const char *SymbolName = GuessSymbolName(ReferenceValue, info->AddrMap);

  if (*ReferenceType == LLVMDisassembler_ReferenceType_In_Branch) {
    *ReferenceName = GuessIndirectSymbol(ReferenceValue, info);
    if (*ReferenceName != nullptr) {
      method_reference(info, ReferenceType, ReferenceName);
      if (*ReferenceType != LLVMDisassembler_ReferenceType_Out_Objc_Message)
        *ReferenceType = LLVMDisassembler_ReferenceType_Out_SymbolStub;
    } else if (SymbolName != nullptr && strncmp(SymbolName, "__Z", 3) == 0) {
      if (info->demangled_name != nullptr)
        free(info->demangled_name);
      int status;
      info->demangled_name =
          itaniumDemangle(SymbolName + 1, nullptr, nullptr, &status);
      if (info->demangled_name != nullptr) {
        *ReferenceName = info->demangled_name;
        *ReferenceType = LLVMDisassembler_ReferenceType_DeMangled_Name;
      } else
        *ReferenceType = LLVMDisassembler_ReferenceType_InOut_None;
    } else
      *ReferenceType = LLVMDisassembler_ReferenceType_InOut_None;
  } else if (*ReferenceType == LLVMDisassembler_ReferenceType_In_PCrel_Load) {
    *ReferenceName =
        GuessLiteralPointer(ReferenceValue, ReferencePC, ReferenceType, info);
    if (*ReferenceName)
      method_reference(info, ReferenceType, ReferenceName);
    else
      *ReferenceType = LLVMDisassembler_ReferenceType_InOut_None;
    // If this is arm64 and the reference is an adrp instruction save the
    // instruction, passed in ReferenceValue and the address of the instruction
    // for use later if we see and add immediate instruction.
  } else if (info->O->getArch() == Triple::aarch64 &&
             *ReferenceType == LLVMDisassembler_ReferenceType_In_ARM64_ADRP) {
    info->adrp_inst = ReferenceValue;
    info->adrp_addr = ReferencePC;
    SymbolName = nullptr;
    *ReferenceName = nullptr;
    *ReferenceType = LLVMDisassembler_ReferenceType_InOut_None;
    // If this is arm64 and reference is an add immediate instruction and we
    // have
    // seen an adrp instruction just before it and the adrp's Xd register
    // matches
    // this add's Xn register reconstruct the value being referenced and look to
    // see if it is a literal pointer.  Note the add immediate instruction is
    // passed in ReferenceValue.
  } else if (info->O->getArch() == Triple::aarch64 &&
             *ReferenceType == LLVMDisassembler_ReferenceType_In_ARM64_ADDXri &&
             ReferencePC - 4 == info->adrp_addr &&
             (info->adrp_inst & 0x9f000000) == 0x90000000 &&
             (info->adrp_inst & 0x1f) == ((ReferenceValue >> 5) & 0x1f)) {
    uint32_t addxri_inst;
    uint64_t adrp_imm, addxri_imm;

    adrp_imm =
        ((info->adrp_inst & 0x00ffffe0) >> 3) | ((info->adrp_inst >> 29) & 0x3);
    if (info->adrp_inst & 0x0200000)
      adrp_imm |= 0xfffffffffc000000LL;

    addxri_inst = ReferenceValue;
    addxri_imm = (addxri_inst >> 10) & 0xfff;
    if (((addxri_inst >> 22) & 0x3) == 1)
      addxri_imm <<= 12;

    ReferenceValue = (info->adrp_addr & 0xfffffffffffff000LL) +
                     (adrp_imm << 12) + addxri_imm;

    *ReferenceName =
        GuessLiteralPointer(ReferenceValue, ReferencePC, ReferenceType, info);
    if (*ReferenceName == nullptr)
      *ReferenceType = LLVMDisassembler_ReferenceType_InOut_None;
    // If this is arm64 and the reference is a load register instruction and we
    // have seen an adrp instruction just before it and the adrp's Xd register
    // matches this add's Xn register reconstruct the value being referenced and
    // look to see if it is a literal pointer.  Note the load register
    // instruction is passed in ReferenceValue.
  } else if (info->O->getArch() == Triple::aarch64 &&
             *ReferenceType == LLVMDisassembler_ReferenceType_In_ARM64_LDRXui &&
             ReferencePC - 4 == info->adrp_addr &&
             (info->adrp_inst & 0x9f000000) == 0x90000000 &&
             (info->adrp_inst & 0x1f) == ((ReferenceValue >> 5) & 0x1f)) {
    uint32_t ldrxui_inst;
    uint64_t adrp_imm, ldrxui_imm;

    adrp_imm =
        ((info->adrp_inst & 0x00ffffe0) >> 3) | ((info->adrp_inst >> 29) & 0x3);
    if (info->adrp_inst & 0x0200000)
      adrp_imm |= 0xfffffffffc000000LL;

    ldrxui_inst = ReferenceValue;
    ldrxui_imm = (ldrxui_inst >> 10) & 0xfff;

    ReferenceValue = (info->adrp_addr & 0xfffffffffffff000LL) +
                     (adrp_imm << 12) + (ldrxui_imm << 3);

    *ReferenceName =
        GuessLiteralPointer(ReferenceValue, ReferencePC, ReferenceType, info);
    if (*ReferenceName == nullptr)
      *ReferenceType = LLVMDisassembler_ReferenceType_InOut_None;
  }
  // If this arm64 and is an load register (PC-relative) instruction the
  // ReferenceValue is the PC plus the immediate value.
  else if (info->O->getArch() == Triple::aarch64 &&
           (*ReferenceType == LLVMDisassembler_ReferenceType_In_ARM64_LDRXl ||
            *ReferenceType == LLVMDisassembler_ReferenceType_In_ARM64_ADR)) {
    *ReferenceName =
        GuessLiteralPointer(ReferenceValue, ReferencePC, ReferenceType, info);
    if (*ReferenceName == nullptr)
      *ReferenceType = LLVMDisassembler_ReferenceType_InOut_None;
  } else if (SymbolName != nullptr && strncmp(SymbolName, "__Z", 3) == 0) {
    if (info->demangled_name != nullptr)
      free(info->demangled_name);
    int status;
    info->demangled_name =
        itaniumDemangle(SymbolName + 1, nullptr, nullptr, &status);
    if (info->demangled_name != nullptr) {
      *ReferenceName = info->demangled_name;
      *ReferenceType = LLVMDisassembler_ReferenceType_DeMangled_Name;
    }
  } else {
    *ReferenceName = nullptr;
    *ReferenceType = LLVMDisassembler_ReferenceType_InOut_None;
  }

  return SymbolName;
}

/// \brief Emits the comments that are stored in the CommentStream.
/// Each comment in the CommentStream must end with a newline.
static void emitComments(raw_svector_ostream &CommentStream,
                         SmallString<128> &CommentsToEmit,
                         formatted_raw_ostream &FormattedOS,
                         const MCAsmInfo &MAI) {
  // Flush the stream before taking its content.
  StringRef Comments = CommentsToEmit.str();
  // Get the default information for printing a comment.
  StringRef CommentBegin = MAI.getCommentString();
  unsigned CommentColumn = MAI.getCommentColumn();
  bool IsFirst = true;
  while (!Comments.empty()) {
    if (!IsFirst)
      FormattedOS << '\n';
    // Emit a line of comments.
    FormattedOS.PadToColumn(CommentColumn);
    size_t Position = Comments.find('\n');
    FormattedOS << CommentBegin << ' ' << Comments.substr(0, Position);
    // Move after the newline character.
    Comments = Comments.substr(Position + 1);
    IsFirst = false;
  }
  FormattedOS.flush();

  // Tell the comment stream that the vector changed underneath it.
  CommentsToEmit.clear();
}

static void DisassembleMachO(StringRef Filename, MachOObjectFile *MachOOF,
                             StringRef DisSegName, StringRef DisSectName) {
  const char *McpuDefault = nullptr;
  const Target *ThumbTarget = nullptr;
  const Target *TheTarget = GetTarget(MachOOF, &McpuDefault, &ThumbTarget);
  if (!TheTarget) {
    // GetTarget prints out stuff.
    return;
  }
  if (MCPU.empty() && McpuDefault)
    MCPU = McpuDefault;

  std::unique_ptr<const MCInstrInfo> InstrInfo(TheTarget->createMCInstrInfo());
  std::unique_ptr<const MCInstrInfo> ThumbInstrInfo;
  if (ThumbTarget)
    ThumbInstrInfo.reset(ThumbTarget->createMCInstrInfo());

  // Package up features to be passed to target/subtarget
  std::string FeaturesStr;
  if (MAttrs.size()) {
    SubtargetFeatures Features;
    for (unsigned i = 0; i != MAttrs.size(); ++i)
      Features.AddFeature(MAttrs[i]);
    FeaturesStr = Features.getString();
  }

  MCTargetOptions MCOptions;
  // Set up disassembler.
  std::unique_ptr<const MCRegisterInfo> MRI(
      TheTarget->createMCRegInfo(TripleName));
  std::unique_ptr<const MCAsmInfo> AsmInfo(
      TheTarget->createMCAsmInfo(*MRI, TripleName, MCOptions));
  std::unique_ptr<const MCSubtargetInfo> STI(
      TheTarget->createMCSubtargetInfo(TripleName, MCPU, FeaturesStr));
  MCContext Ctx(AsmInfo.get(), MRI.get(), nullptr);
  std::unique_ptr<MCDisassembler> DisAsm(
      TheTarget->createMCDisassembler(*STI, Ctx));
  std::unique_ptr<MCSymbolizer> Symbolizer;
  struct DisassembleInfo SymbolizerInfo;
  std::unique_ptr<MCRelocationInfo> RelInfo(
      TheTarget->createMCRelocationInfo(TripleName, Ctx));
  if (RelInfo) {
    Symbolizer.reset(TheTarget->createMCSymbolizer(
        TripleName, SymbolizerGetOpInfo, SymbolizerSymbolLookUp,
        &SymbolizerInfo, &Ctx, std::move(RelInfo)));
    DisAsm->setSymbolizer(std::move(Symbolizer));
  }
  int AsmPrinterVariant = AsmInfo->getAssemblerDialect();
  std::unique_ptr<MCInstPrinter> IP(TheTarget->createMCInstPrinter(
      Triple(TripleName), AsmPrinterVariant, *AsmInfo, *InstrInfo, *MRI));
  // Set the display preference for hex vs. decimal immediates.
  IP->setPrintImmHex(PrintImmHex);
  // Comment stream and backing vector.
  SmallString<128> CommentsToEmit;
  raw_svector_ostream CommentStream(CommentsToEmit);
  // FIXME: Setting the CommentStream in the InstPrinter is problematic in that
  // if it is done then arm64 comments for string literals don't get printed
  // and some constant get printed instead and not setting it causes intel
  // (32-bit and 64-bit) comments printed with different spacing before the
  // comment causing different diffs with the 'C' disassembler library API.
  // IP->setCommentStream(CommentStream);

  if (!AsmInfo || !STI || !DisAsm || !IP) {
    errs() << "error: couldn't initialize disassembler for target "
           << TripleName << '\n';
    return;
  }

  // Set up separate thumb disassembler if needed.
  std::unique_ptr<const MCRegisterInfo> ThumbMRI;
  std::unique_ptr<const MCAsmInfo> ThumbAsmInfo;
  std::unique_ptr<const MCSubtargetInfo> ThumbSTI;
  std::unique_ptr<MCDisassembler> ThumbDisAsm;
  std::unique_ptr<MCInstPrinter> ThumbIP;
  std::unique_ptr<MCContext> ThumbCtx;
  std::unique_ptr<MCSymbolizer> ThumbSymbolizer;
  struct DisassembleInfo ThumbSymbolizerInfo;
  std::unique_ptr<MCRelocationInfo> ThumbRelInfo;
  if (ThumbTarget) {
    ThumbMRI.reset(ThumbTarget->createMCRegInfo(ThumbTripleName));
    ThumbAsmInfo.reset(
        ThumbTarget->createMCAsmInfo(*ThumbMRI, ThumbTripleName, MCOptions));
    ThumbSTI.reset(
        ThumbTarget->createMCSubtargetInfo(ThumbTripleName, MCPU, FeaturesStr));
    ThumbCtx.reset(new MCContext(ThumbAsmInfo.get(), ThumbMRI.get(), nullptr));
    ThumbDisAsm.reset(ThumbTarget->createMCDisassembler(*ThumbSTI, *ThumbCtx));
    MCContext *PtrThumbCtx = ThumbCtx.get();
    ThumbRelInfo.reset(
        ThumbTarget->createMCRelocationInfo(ThumbTripleName, *PtrThumbCtx));
    if (ThumbRelInfo) {
      ThumbSymbolizer.reset(ThumbTarget->createMCSymbolizer(
          ThumbTripleName, SymbolizerGetOpInfo, SymbolizerSymbolLookUp,
          &ThumbSymbolizerInfo, PtrThumbCtx, std::move(ThumbRelInfo)));
      ThumbDisAsm->setSymbolizer(std::move(ThumbSymbolizer));
    }
    int ThumbAsmPrinterVariant = ThumbAsmInfo->getAssemblerDialect();
    ThumbIP.reset(ThumbTarget->createMCInstPrinter(
        Triple(ThumbTripleName), ThumbAsmPrinterVariant, *ThumbAsmInfo,
        *ThumbInstrInfo, *ThumbMRI));
    // Set the display preference for hex vs. decimal immediates.
    ThumbIP->setPrintImmHex(PrintImmHex);
  }

  if (ThumbTarget && (!ThumbAsmInfo || !ThumbSTI || !ThumbDisAsm || !ThumbIP)) {
    errs() << "error: couldn't initialize disassembler for target "
           << ThumbTripleName << '\n';
    return;
  }

  MachO::mach_header Header = MachOOF->getHeader();

  // FIXME: Using the -cfg command line option, this code used to be able to
  // annotate relocations with the referenced symbol's name, and if this was
  // inside a __[cf]string section, the data it points to. This is now replaced
  // by the upcoming MCSymbolizer, which needs the appropriate setup done above.
  std::vector<SectionRef> Sections;
  std::vector<SymbolRef> Symbols;
  SmallVector<uint64_t, 8> FoundFns;
  uint64_t BaseSegmentAddress;

  getSectionsAndSymbols(MachOOF, Sections, Symbols, FoundFns,
                        BaseSegmentAddress);

  // Sort the symbols by address, just in case they didn't come in that way.
  std::sort(Symbols.begin(), Symbols.end(), SymbolSorter());

  // Build a data in code table that is sorted on by the address of each entry.
  uint64_t BaseAddress = 0;
  if (Header.filetype == MachO::MH_OBJECT)
    BaseAddress = Sections[0].getAddress();
  else
    BaseAddress = BaseSegmentAddress;
  DiceTable Dices;
  for (dice_iterator DI = MachOOF->begin_dices(), DE = MachOOF->end_dices();
       DI != DE; ++DI) {
    uint32_t Offset;
    DI->getOffset(Offset);
    Dices.push_back(std::make_pair(BaseAddress + Offset, *DI));
  }
  array_pod_sort(Dices.begin(), Dices.end());

  std::unique_ptr<DIContext> diContext;
  ObjectFile *DbgObj = MachOOF;
  // Try to find debug info and set up the DIContext for it.
  if (UseDbg) {
    // A separate DSym file path was specified, parse it as a macho file,
    // get the sections and supply it to the section name parsing machinery.
    if (!DSYMFile.empty()) {
      ErrorOr<std::unique_ptr<MemoryBuffer>> BufOrErr =
          MemoryBuffer::getFileOrSTDIN(DSYMFile);
      if (std::error_code EC = BufOrErr.getError()) {
        errs() << "llvm-mctoll: " << Filename << ": " << EC.message() << '\n';
        return;
      }
      DbgObj =
          ObjectFile::createMachOObjectFile(BufOrErr.get()->getMemBufferRef())
              .get()
              .release();
    }

    // Setup the DIContext
    diContext = DWARFContext::create(*DbgObj);
  }

  if (FilterSections.size() == 0)
    outs() << "(" << DisSegName << "," << DisSectName << ") section\n";

  for (unsigned SectIdx = 0; SectIdx != Sections.size(); SectIdx++) {
    Expected<StringRef> SecNameOrErr = Sections[SectIdx].getName();
    if (!SecNameOrErr) {
      consumeError(SecNameOrErr.takeError());
      continue;
    }
    if (*SecNameOrErr != DisSectName)
      continue;

    DataRefImpl DR = Sections[SectIdx].getRawDataRefImpl();

    StringRef SegmentName = MachOOF->getSectionFinalSegmentName(DR);
    if (SegmentName != DisSegName)
      continue;

    StringRef BytesStr =
        unwrapOrError(Sections[SectIdx].getContents(), Filename);
    ArrayRef<uint8_t> Bytes(reinterpret_cast<const uint8_t *>(BytesStr.data()),
                            BytesStr.size());
    uint64_t SectAddress = Sections[SectIdx].getAddress();

    bool symbolTableWorked = false;

    // Create a map of symbol addresses to symbol names for use by
    // the SymbolizerSymbolLookUp() routine.
    SymbolAddressMap AddrMap;
    bool DisSymNameFound = false;
    for (const SymbolRef &Symbol : MachOOF->symbols()) {
      Expected<SymbolRef::Type> STOrErr = Symbol.getType();
      if (!STOrErr)
        report_error(STOrErr.takeError(), MachOOF->getFileName());
      SymbolRef::Type ST = *STOrErr;
      if (ST == SymbolRef::ST_Function || ST == SymbolRef::ST_Data ||
          ST == SymbolRef::ST_Other) {
        auto SymOrErr = Symbol.getValue();
        if (!SymOrErr)
          report_error(SymOrErr.takeError(), Symbol.getObject()->getFileName());

        uint64_t Address = *SymOrErr;
        Expected<StringRef> SymNameOrErr = Symbol.getName();
        if (!SymNameOrErr)
          report_error(SymNameOrErr.takeError(), MachOOF->getFileName());
        StringRef SymName = *SymNameOrErr;
        AddrMap[Address] = SymName;
        if (!DisSymName.empty() && DisSymName == SymName)
          DisSymNameFound = true;
      }
    }
    if (!DisSymName.empty() && !DisSymNameFound) {
      outs() << "Can't find -dis-symname: " << DisSymName << "\n";
      return;
    }
    // Set up the block of info used by the Symbolizer call backs.
    SymbolizerInfo.verbose = !NoSymbolicOperands;
    SymbolizerInfo.O = MachOOF;
    SymbolizerInfo.S = Sections[SectIdx];
    SymbolizerInfo.AddrMap = &AddrMap;
    SymbolizerInfo.Sections = &Sections;
    SymbolizerInfo.class_name = nullptr;
    SymbolizerInfo.selector_name = nullptr;
    SymbolizerInfo.method = nullptr;
    SymbolizerInfo.demangled_name = nullptr;
    SymbolizerInfo.bindtable = nullptr;
    SymbolizerInfo.adrp_addr = 0;
    SymbolizerInfo.adrp_inst = 0;
    // Same for the ThumbSymbolizer
    ThumbSymbolizerInfo.verbose = !NoSymbolicOperands;
    ThumbSymbolizerInfo.O = MachOOF;
    ThumbSymbolizerInfo.S = Sections[SectIdx];
    ThumbSymbolizerInfo.AddrMap = &AddrMap;
    ThumbSymbolizerInfo.Sections = &Sections;
    ThumbSymbolizerInfo.class_name = nullptr;
    ThumbSymbolizerInfo.selector_name = nullptr;
    ThumbSymbolizerInfo.method = nullptr;
    ThumbSymbolizerInfo.demangled_name = nullptr;
    ThumbSymbolizerInfo.bindtable = nullptr;
    ThumbSymbolizerInfo.adrp_addr = 0;
    ThumbSymbolizerInfo.adrp_inst = 0;

    unsigned int Arch = MachOOF->getArch();

    // Skip all symbols if this is a stubs file.
    if (Bytes.size() == 0)
      return;

    // If the section has symbols but no symbol at the start of the section
    // these are used to make sure the bytes before the first symbol are
    // disassembled.
    bool FirstSymbol = true;
    bool FirstSymbolAtSectionStart = true;

    // Disassemble symbol by symbol.
    for (unsigned SymIdx = 0; SymIdx != Symbols.size(); SymIdx++) {
      Expected<StringRef> SymNameOrErr = Symbols[SymIdx].getName();
      if (!SymNameOrErr)
        report_error(SymNameOrErr.takeError(), MachOOF->getFileName());
      StringRef SymName = *SymNameOrErr;

      Expected<SymbolRef::Type> STOrErr = Symbols[SymIdx].getType();
      if (!STOrErr)
        report_error(STOrErr.takeError(), MachOOF->getFileName());
      SymbolRef::Type ST = *STOrErr;
      if (ST != SymbolRef::ST_Function && ST != SymbolRef::ST_Data)
        continue;

      // Make sure the symbol is defined in this section.
      bool containsSym = Sections[SectIdx].containsSymbol(Symbols[SymIdx]);
      if (!containsSym) {
        if (!DisSymName.empty() && DisSymName == SymName) {
          outs() << "-dis-symname: " << DisSymName << " not in the section\n";
          return;
        }
        continue;
      }
      // The __mh_execute_header is special and we need to deal with that fact
      // this symbol is before the start of the (__TEXT,__text) section and at
      // the address of the start of the __TEXT segment.  This is because this
      // symbol is an N_SECT symbol in the (__TEXT,__text) but its address is
      // before the start of the section in a standard MH_EXECUTE filetype.
      if (!DisSymName.empty() && DisSymName == "__mh_execute_header") {
        outs() << "-dis-symname: __mh_execute_header not in any section\n";
        return;
      }
      // When this code is trying to disassemble a symbol at a time and in the
      // case there is only the __mh_execute_header symbol left as in a stripped
      // executable, we need to deal with this by ignoring this symbol so the
      // whole section is disassembled and this symbol is then not displayed.
      if (SymName == "__mh_execute_header" || SymName == "__mh_dylib_header" ||
          SymName == "__mh_bundle_header" || SymName == "__mh_object_header" ||
          SymName == "__mh_preload_header" || SymName == "__mh_dylinker_header")
        continue;

      // If we are only disassembling one symbol see if this is that symbol.
      if (!DisSymName.empty() && DisSymName != SymName)
        continue;

      // Start at the address of the symbol relative to the section's address.
      uint64_t SectSize = Sections[SectIdx].getSize();
      auto SymOrErr = Symbols[SymIdx].getValue();
      if (!SymOrErr)
        report_error(SymOrErr.takeError(),
                     Symbols[SymIdx].getObject()->getFileName());
      uint64_t Start = *SymOrErr;
      uint64_t SectionAddress = Sections[SectIdx].getAddress();
      Start -= SectionAddress;

      if (Start > SectSize) {
        outs() << "section data ends, " << SymName
               << " lies outside valid range\n";
        return;
      }

      // Stop disassembling either at the beginning of the next symbol or at
      // the end of the section.
      bool containsNextSym = false;
      uint64_t NextSym = 0;
      uint64_t NextSymIdx = SymIdx + 1;
      while (Symbols.size() > NextSymIdx) {
        Expected<SymbolRef::Type> STOrErr = Symbols[NextSymIdx].getType();
        if (!STOrErr)
          report_error(STOrErr.takeError(), MachOOF->getFileName());
        SymbolRef::Type NextSymType = *STOrErr;
        if (NextSymType == SymbolRef::ST_Function) {
          containsNextSym =
              Sections[SectIdx].containsSymbol(Symbols[NextSymIdx]);
          auto SymOrErr = Symbols[NextSymIdx].getValue();
          if (!SymOrErr)
            report_error(SymOrErr.takeError(),
                         Symbols[NextSymIdx].getObject()->getFileName());

          NextSym = *SymOrErr;
          NextSym -= SectionAddress;
          break;
        }
        ++NextSymIdx;
      }

      uint64_t End = containsNextSym ? std::min(NextSym, SectSize) : SectSize;
      uint64_t Size;

      symbolTableWorked = true;

      DataRefImpl Symb = Symbols[SymIdx].getRawDataRefImpl();
      uint32_t SymbolFlags = cantFail(MachOOF->getSymbolFlags(Symb));
      bool IsThumb = SymbolFlags & SymbolRef::SF_Thumb;

      // We only need the dedicated Thumb target if there's a real choice
      // (i.e. we're not targeting M-class) and the function is Thumb.
      bool UseThumbTarget = IsThumb && ThumbTarget;

      // If we are not specifying a symbol to start disassembly with and this
      // is the first symbol in the section but not at the start of the section
      // then move the disassembly index to the start of the section and
      // don't print the symbol name just yet.  This is so the bytes before the
      // first symbol are disassembled.
      uint64_t SymbolStart = Start;
      if (DisSymName.empty() && FirstSymbol && Start != 0) {
        FirstSymbolAtSectionStart = false;
        Start = 0;
      } else
        outs() << SymName << ":\n";

      DILineInfo lastLine;
      for (uint64_t Index = Start; Index < End; Index += Size) {
        MCInst Inst;

        // If this is the first symbol in the section and it was not at the
        // start of the section, see if we are at its Index now and if so print
        // the symbol name.
        if (FirstSymbol && !FirstSymbolAtSectionStart && Index == SymbolStart)
          outs() << SymName << ":\n";

        uint64_t PC = SectAddress + Index;
        if (FullLeadingAddr) {
          if (MachOOF->is64Bit())
            outs() << format("%016" PRIx64, PC);
          else
            outs() << format("%08" PRIx64, PC);
        } else {
          outs() << format("%8" PRIx64 ":", PC);
        }
        if (Arch == Triple::arm)
          outs() << "\t";

        // Check the data in code table here to see if this is data not an
        // instruction to be disassembled.
        DiceTable Dice;
        Dice.push_back(std::make_pair(PC, DiceRef()));
        dice_table_iterator DTI =
            std::search(Dices.begin(), Dices.end(), Dice.begin(), Dice.end(),
                        compareDiceTableEntries);
        if (DTI != Dices.end()) {
          uint16_t Length;
          DTI->second.getLength(Length);
          uint16_t Kind;
          DTI->second.getKind(Kind);
          Size = DumpDataInCode(Bytes.data() + Index, Length, Kind);
          if ((Kind == MachO::DICE_KIND_JUMP_TABLE8) &&
              (PC == (DTI->first + Length - 1)) && (Length & 1))
            Size++;
          continue;
        }

        SmallVector<char, 64> AnnotationsBytes;
        raw_svector_ostream Annotations(AnnotationsBytes);

        bool gotInst;
        if (UseThumbTarget)
          gotInst = ThumbDisAsm->getInstruction(Inst, Size, Bytes.slice(Index),
                                                PC, Annotations);
        else
          gotInst = DisAsm->getInstruction(Inst, Size, Bytes.slice(Index), PC,
                                           Annotations);
        if (gotInst) {
          if (Arch == Triple::arm) {
            dumpBytes(makeArrayRef(Bytes.data() + Index, Size), outs());
          }
          formatted_raw_ostream FormattedOS(outs());
          StringRef AnnotationsStr = Annotations.str();
          if (UseThumbTarget)
            ThumbIP->printInst(&Inst, PC, AnnotationsStr, *ThumbSTI,
                               FormattedOS);
          else
            IP->printInst(&Inst, PC, AnnotationsStr, *STI, FormattedOS);

          emitComments(CommentStream, CommentsToEmit, FormattedOS, *AsmInfo);

          // Print debug info.
          if (diContext) {
            DILineInfo dli = diContext->getLineInfoForAddress({PC, SectIdx});
            // Print valid line info if it changed.
            if (dli != lastLine && dli.Line != 0)
              outs() << "\t## " << dli.FileName << ':' << dli.Line << ':'
                     << dli.Column;
            lastLine = dli;
          }
          outs() << "\n";
        } else {
          unsigned int Arch = MachOOF->getArch();
          if (Arch == Triple::x86_64 || Arch == Triple::x86) {
            outs() << format("\t.byte 0x%02x #bad opcode\n",
                             *(Bytes.data() + Index) & 0xff);
            Size = 1; // skip exactly one illegible byte and move on.
          } else if (Arch == Triple::aarch64 ||
                     (Arch == Triple::arm && !IsThumb)) {
            uint32_t opcode = (*(Bytes.data() + Index) & 0xff) |
                              (*(Bytes.data() + Index + 1) & 0xff) << 8 |
                              (*(Bytes.data() + Index + 2) & 0xff) << 16 |
                              (*(Bytes.data() + Index + 3) & 0xff) << 24;
            outs() << format("\t.long\t0x%08x\n", opcode);
            Size = 4;
          } else if (Arch == Triple::arm) {
            assert(IsThumb && "ARM mode should have been dealt with above");
            uint32_t opcode = (*(Bytes.data() + Index) & 0xff) |
                              (*(Bytes.data() + Index + 1) & 0xff) << 8;
            outs() << format("\t.short\t0x%04x\n", opcode);
            Size = 2;
          } else {
            errs() << "llvm-mctoll: warning: invalid instruction encoding\n";
            if (Size == 0)
              Size = 1; // skip illegible bytes
          }
        }
      }
      // Now that we are done disassembled the first symbol set the bool that
      // were doing this to false.
      FirstSymbol = false;
    }
    if (!symbolTableWorked) {
      // Reading the symbol table didn't work, disassemble the whole section.
      uint64_t SectAddress = Sections[SectIdx].getAddress();
      uint64_t SectSize = Sections[SectIdx].getSize();
      uint64_t InstSize;
      for (uint64_t Index = 0; Index < SectSize; Index += InstSize) {
        MCInst Inst;

        uint64_t PC = SectAddress + Index;
        SmallVector<char, 64> AnnotationsBytes;
        raw_svector_ostream Annotations(AnnotationsBytes);
        if (DisAsm->getInstruction(Inst, InstSize, Bytes.slice(Index), PC,
                                   Annotations)) {
          if (FullLeadingAddr) {
            if (MachOOF->is64Bit())
              outs() << format("%016" PRIx64, PC);
            else
              outs() << format("%08" PRIx64, PC);
          } else {
            outs() << format("%8" PRIx64 ":", PC);
          }
          if (Arch == Triple::arm) {
            outs() << "\t";
            dumpBytes(makeArrayRef(Bytes.data() + Index, InstSize), outs());
          }
          StringRef AnnotationsStr = Annotations.str();
          IP->printInst(&Inst, PC, AnnotationsStr, *STI, outs());
          outs() << "\n";
        } else {
          unsigned int Arch = MachOOF->getArch();
          if (Arch == Triple::x86_64 || Arch == Triple::x86) {
            outs() << format("\t.byte 0x%02x #bad opcode\n",
                             *(Bytes.data() + Index) & 0xff);
            InstSize = 1; // skip exactly one illegible byte and move on.
          } else {
            errs() << "llvm-mctoll: warning: invalid instruction encoding\n";
            if (InstSize == 0)
              InstSize = 1; // skip illegible bytes
          }
        }
      }
    }
    // The TripleName's need to be reset if we are called again for a different
    // archtecture.
    TripleName = "";
    ThumbTripleName = "";

    if (SymbolizerInfo.method != nullptr)
      free(SymbolizerInfo.method);
    if (SymbolizerInfo.demangled_name != nullptr)
      free(SymbolizerInfo.demangled_name);
    if (ThumbSymbolizerInfo.method != nullptr)
      free(ThumbSymbolizerInfo.method);
    if (ThumbSymbolizerInfo.demangled_name != nullptr)
      free(ThumbSymbolizerInfo.demangled_name);
  }
}

//===----------------------------------------------------------------------===//
// __compact_unwind section dumping
//===----------------------------------------------------------------------===//

namespace {

template <typename T> static uint64_t readNext(const char *&Buf) {
  using llvm::support::little;
  using llvm::support::unaligned;

  uint64_t Val = support::endian::read<T, little, unaligned>(Buf);
  Buf += sizeof(T);
  return Val;
}

struct CompactUnwindEntry {
  uint32_t OffsetInSection;

  uint64_t FunctionAddr;
  uint32_t Length;
  uint32_t CompactEncoding;
  uint64_t PersonalityAddr;
  uint64_t LSDAAddr;

  RelocationRef FunctionReloc;
  RelocationRef PersonalityReloc;
  RelocationRef LSDAReloc;

  CompactUnwindEntry(StringRef Contents, unsigned Offset, bool Is64)
      : OffsetInSection(Offset) {
    if (Is64)
      read<uint64_t>(Contents.data() + Offset);
    else
      read<uint32_t>(Contents.data() + Offset);
  }

private:
  template <typename UIntPtr> void read(const char *Buf) {
    FunctionAddr = readNext<UIntPtr>(Buf);
    Length = readNext<uint32_t>(Buf);
    CompactEncoding = readNext<uint32_t>(Buf);
    PersonalityAddr = readNext<UIntPtr>(Buf);
    LSDAAddr = readNext<UIntPtr>(Buf);
  }
};
} // namespace

static void PrintMachHeader(uint32_t magic, uint32_t cputype,
                            uint32_t cpusubtype, uint32_t filetype,
                            uint32_t ncmds, uint32_t sizeofcmds, uint32_t flags,
                            bool verbose) {
  outs() << "Mach header\n";
  outs() << "      magic cputype cpusubtype  caps    filetype ncmds "
            "sizeofcmds      flags\n";
  if (verbose) {
    if (magic == MachO::MH_MAGIC)
      outs() << "   MH_MAGIC";
    else if (magic == MachO::MH_MAGIC_64)
      outs() << "MH_MAGIC_64";
    else
      outs() << format(" 0x%08" PRIx32, magic);
    switch (cputype) {
    case MachO::CPU_TYPE_I386:
      outs() << "    I386";
      switch (cpusubtype & ~MachO::CPU_SUBTYPE_MASK) {
      case MachO::CPU_SUBTYPE_I386_ALL:
        outs() << "        ALL";
        break;
      default:
        outs() << format(" %10d", cpusubtype & ~MachO::CPU_SUBTYPE_MASK);
        break;
      }
      break;
    case MachO::CPU_TYPE_X86_64:
      outs() << "  X86_64";
      switch (cpusubtype & ~MachO::CPU_SUBTYPE_MASK) {
      case MachO::CPU_SUBTYPE_X86_64_ALL:
        outs() << "        ALL";
        break;
      case MachO::CPU_SUBTYPE_X86_64_H:
        outs() << "    Haswell";
        break;
      default:
        outs() << format(" %10d", cpusubtype & ~MachO::CPU_SUBTYPE_MASK);
        break;
      }
      break;
    case MachO::CPU_TYPE_ARM:
      outs() << "     ARM";
      switch (cpusubtype & ~MachO::CPU_SUBTYPE_MASK) {
      case MachO::CPU_SUBTYPE_ARM_ALL:
        outs() << "        ALL";
        break;
      case MachO::CPU_SUBTYPE_ARM_V4T:
        outs() << "        V4T";
        break;
      case MachO::CPU_SUBTYPE_ARM_V5TEJ:
        outs() << "      V5TEJ";
        break;
      case MachO::CPU_SUBTYPE_ARM_XSCALE:
        outs() << "     XSCALE";
        break;
      case MachO::CPU_SUBTYPE_ARM_V6:
        outs() << "         V6";
        break;
      case MachO::CPU_SUBTYPE_ARM_V6M:
        outs() << "        V6M";
        break;
      case MachO::CPU_SUBTYPE_ARM_V7:
        outs() << "         V7";
        break;
      case MachO::CPU_SUBTYPE_ARM_V7EM:
        outs() << "       V7EM";
        break;
      case MachO::CPU_SUBTYPE_ARM_V7K:
        outs() << "        V7K";
        break;
      case MachO::CPU_SUBTYPE_ARM_V7M:
        outs() << "        V7M";
        break;
      case MachO::CPU_SUBTYPE_ARM_V7S:
        outs() << "        V7S";
        break;
      default:
        outs() << format(" %10d", cpusubtype & ~MachO::CPU_SUBTYPE_MASK);
        break;
      }
      break;
    case MachO::CPU_TYPE_ARM64:
      outs() << "   ARM64";
      switch (cpusubtype & ~MachO::CPU_SUBTYPE_MASK) {
      case MachO::CPU_SUBTYPE_ARM64_ALL:
        outs() << "        ALL";
        break;
      default:
        outs() << format(" %10d", cpusubtype & ~MachO::CPU_SUBTYPE_MASK);
        break;
      }
      break;
    case MachO::CPU_TYPE_POWERPC:
      outs() << "     PPC";
      switch (cpusubtype & ~MachO::CPU_SUBTYPE_MASK) {
      case MachO::CPU_SUBTYPE_POWERPC_ALL:
        outs() << "        ALL";
        break;
      default:
        outs() << format(" %10d", cpusubtype & ~MachO::CPU_SUBTYPE_MASK);
        break;
      }
      break;
    case MachO::CPU_TYPE_POWERPC64:
      outs() << "   PPC64";
      switch (cpusubtype & ~MachO::CPU_SUBTYPE_MASK) {
      case MachO::CPU_SUBTYPE_POWERPC_ALL:
        outs() << "        ALL";
        break;
      default:
        outs() << format(" %10d", cpusubtype & ~MachO::CPU_SUBTYPE_MASK);
        break;
      }
      break;
    default:
      outs() << format(" %7d", cputype);
      outs() << format(" %10d", cpusubtype & ~MachO::CPU_SUBTYPE_MASK);
      break;
    }
    if ((cpusubtype & MachO::CPU_SUBTYPE_MASK) == MachO::CPU_SUBTYPE_LIB64) {
      outs() << " LIB64";
    } else {
      outs() << format("  0x%02" PRIx32,
                       (cpusubtype & MachO::CPU_SUBTYPE_MASK) >> 24);
    }
    switch (filetype) {
    case MachO::MH_OBJECT:
      outs() << "      OBJECT";
      break;
    case MachO::MH_EXECUTE:
      outs() << "     EXECUTE";
      break;
    case MachO::MH_FVMLIB:
      outs() << "      FVMLIB";
      break;
    case MachO::MH_CORE:
      outs() << "        CORE";
      break;
    case MachO::MH_PRELOAD:
      outs() << "     PRELOAD";
      break;
    case MachO::MH_DYLIB:
      outs() << "       DYLIB";
      break;
    case MachO::MH_DYLIB_STUB:
      outs() << "  DYLIB_STUB";
      break;
    case MachO::MH_DYLINKER:
      outs() << "    DYLINKER";
      break;
    case MachO::MH_BUNDLE:
      outs() << "      BUNDLE";
      break;
    case MachO::MH_DSYM:
      outs() << "        DSYM";
      break;
    case MachO::MH_KEXT_BUNDLE:
      outs() << "  KEXTBUNDLE";
      break;
    default:
      outs() << format("  %10u", filetype);
      break;
    }
    outs() << format(" %5u", ncmds);
    outs() << format(" %10u", sizeofcmds);
    uint32_t f = flags;
    if (f & MachO::MH_NOUNDEFS) {
      outs() << "   NOUNDEFS";
      f &= ~MachO::MH_NOUNDEFS;
    }
    if (f & MachO::MH_INCRLINK) {
      outs() << " INCRLINK";
      f &= ~MachO::MH_INCRLINK;
    }
    if (f & MachO::MH_DYLDLINK) {
      outs() << " DYLDLINK";
      f &= ~MachO::MH_DYLDLINK;
    }
    if (f & MachO::MH_BINDATLOAD) {
      outs() << " BINDATLOAD";
      f &= ~MachO::MH_BINDATLOAD;
    }
    if (f & MachO::MH_PREBOUND) {
      outs() << " PREBOUND";
      f &= ~MachO::MH_PREBOUND;
    }
    if (f & MachO::MH_SPLIT_SEGS) {
      outs() << " SPLIT_SEGS";
      f &= ~MachO::MH_SPLIT_SEGS;
    }
    if (f & MachO::MH_LAZY_INIT) {
      outs() << " LAZY_INIT";
      f &= ~MachO::MH_LAZY_INIT;
    }
    if (f & MachO::MH_TWOLEVEL) {
      outs() << " TWOLEVEL";
      f &= ~MachO::MH_TWOLEVEL;
    }
    if (f & MachO::MH_FORCE_FLAT) {
      outs() << " FORCE_FLAT";
      f &= ~MachO::MH_FORCE_FLAT;
    }
    if (f & MachO::MH_NOMULTIDEFS) {
      outs() << " NOMULTIDEFS";
      f &= ~MachO::MH_NOMULTIDEFS;
    }
    if (f & MachO::MH_NOFIXPREBINDING) {
      outs() << " NOFIXPREBINDING";
      f &= ~MachO::MH_NOFIXPREBINDING;
    }
    if (f & MachO::MH_PREBINDABLE) {
      outs() << " PREBINDABLE";
      f &= ~MachO::MH_PREBINDABLE;
    }
    if (f & MachO::MH_ALLMODSBOUND) {
      outs() << " ALLMODSBOUND";
      f &= ~MachO::MH_ALLMODSBOUND;
    }
    if (f & MachO::MH_SUBSECTIONS_VIA_SYMBOLS) {
      outs() << " SUBSECTIONS_VIA_SYMBOLS";
      f &= ~MachO::MH_SUBSECTIONS_VIA_SYMBOLS;
    }
    if (f & MachO::MH_CANONICAL) {
      outs() << " CANONICAL";
      f &= ~MachO::MH_CANONICAL;
    }
    if (f & MachO::MH_WEAK_DEFINES) {
      outs() << " WEAK_DEFINES";
      f &= ~MachO::MH_WEAK_DEFINES;
    }
    if (f & MachO::MH_BINDS_TO_WEAK) {
      outs() << " BINDS_TO_WEAK";
      f &= ~MachO::MH_BINDS_TO_WEAK;
    }
    if (f & MachO::MH_ALLOW_STACK_EXECUTION) {
      outs() << " ALLOW_STACK_EXECUTION";
      f &= ~MachO::MH_ALLOW_STACK_EXECUTION;
    }
    if (f & MachO::MH_DEAD_STRIPPABLE_DYLIB) {
      outs() << " DEAD_STRIPPABLE_DYLIB";
      f &= ~MachO::MH_DEAD_STRIPPABLE_DYLIB;
    }
    if (f & MachO::MH_PIE) {
      outs() << " PIE";
      f &= ~MachO::MH_PIE;
    }
    if (f & MachO::MH_NO_REEXPORTED_DYLIBS) {
      outs() << " NO_REEXPORTED_DYLIBS";
      f &= ~MachO::MH_NO_REEXPORTED_DYLIBS;
    }
    if (f & MachO::MH_HAS_TLV_DESCRIPTORS) {
      outs() << " MH_HAS_TLV_DESCRIPTORS";
      f &= ~MachO::MH_HAS_TLV_DESCRIPTORS;
    }
    if (f & MachO::MH_NO_HEAP_EXECUTION) {
      outs() << " MH_NO_HEAP_EXECUTION";
      f &= ~MachO::MH_NO_HEAP_EXECUTION;
    }
    if (f & MachO::MH_APP_EXTENSION_SAFE) {
      outs() << " APP_EXTENSION_SAFE";
      f &= ~MachO::MH_APP_EXTENSION_SAFE;
    }
    if (f & MachO::MH_NLIST_OUTOFSYNC_WITH_DYLDINFO) {
      outs() << " NLIST_OUTOFSYNC_WITH_DYLDINFO";
      f &= ~MachO::MH_NLIST_OUTOFSYNC_WITH_DYLDINFO;
    }
    if (f != 0 || flags == 0)
      outs() << format(" 0x%08" PRIx32, f);
  } else {
    outs() << format(" 0x%08" PRIx32, magic);
    outs() << format(" %7d", cputype);
    outs() << format(" %10d", cpusubtype & ~MachO::CPU_SUBTYPE_MASK);
    outs() << format("  0x%02" PRIx32,
                     (cpusubtype & MachO::CPU_SUBTYPE_MASK) >> 24);
    outs() << format("  %10u", filetype);
    outs() << format(" %5u", ncmds);
    outs() << format(" %10u", sizeofcmds);
    outs() << format(" 0x%08" PRIx32, flags);
  }
  outs() << "\n";
}

static void PrintSegmentCommand(uint32_t cmd, uint32_t cmdsize,
                                StringRef SegName, uint64_t vmaddr,
                                uint64_t vmsize, uint64_t fileoff,
                                uint64_t filesize, uint32_t maxprot,
                                uint32_t initprot, uint32_t nsects,
                                uint32_t flags, uint32_t object_size,
                                bool verbose) {
  uint64_t expected_cmdsize;
  if (cmd == MachO::LC_SEGMENT) {
    outs() << "      cmd LC_SEGMENT\n";
    expected_cmdsize = nsects;
    expected_cmdsize *= sizeof(struct MachO::section);
    expected_cmdsize += sizeof(struct MachO::segment_command);
  } else {
    outs() << "      cmd LC_SEGMENT_64\n";
    expected_cmdsize = nsects;
    expected_cmdsize *= sizeof(struct MachO::section_64);
    expected_cmdsize += sizeof(struct MachO::segment_command_64);
  }
  outs() << "  cmdsize " << cmdsize;
  if (cmdsize != expected_cmdsize)
    outs() << " Inconsistent size\n";
  else
    outs() << "\n";
  outs() << "  segname " << SegName << "\n";
  if (cmd == MachO::LC_SEGMENT_64) {
    outs() << "   vmaddr " << format("0x%016" PRIx64, vmaddr) << "\n";
    outs() << "   vmsize " << format("0x%016" PRIx64, vmsize) << "\n";
  } else {
    outs() << "   vmaddr " << format("0x%08" PRIx64, vmaddr) << "\n";
    outs() << "   vmsize " << format("0x%08" PRIx64, vmsize) << "\n";
  }
  outs() << "  fileoff " << fileoff;
  if (fileoff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << " filesize " << filesize;
  if (fileoff + filesize > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  if (verbose) {
    if ((maxprot & ~(MachO::VM_PROT_READ | MachO::VM_PROT_WRITE |
                     MachO::VM_PROT_EXECUTE)) != 0)
      outs() << "  maxprot ?" << format("0x%08" PRIx32, maxprot) << "\n";
    else {
      outs() << "  maxprot ";
      outs() << ((maxprot & MachO::VM_PROT_READ) ? "r" : "-");
      outs() << ((maxprot & MachO::VM_PROT_WRITE) ? "w" : "-");
      outs() << ((maxprot & MachO::VM_PROT_EXECUTE) ? "x\n" : "-\n");
    }
    if ((initprot & ~(MachO::VM_PROT_READ | MachO::VM_PROT_WRITE |
                      MachO::VM_PROT_EXECUTE)) != 0)
      outs() << " initprot ?" << format("0x%08" PRIx32, initprot) << "\n";
    else {
      outs() << " initprot ";
      outs() << ((initprot & MachO::VM_PROT_READ) ? "r" : "-");
      outs() << ((initprot & MachO::VM_PROT_WRITE) ? "w" : "-");
      outs() << ((initprot & MachO::VM_PROT_EXECUTE) ? "x\n" : "-\n");
    }
  } else {
    outs() << "  maxprot " << format("0x%08" PRIx32, maxprot) << "\n";
    outs() << " initprot " << format("0x%08" PRIx32, initprot) << "\n";
  }
  outs() << "   nsects " << nsects << "\n";
  if (verbose) {
    outs() << "    flags";
    if (flags == 0)
      outs() << " (none)\n";
    else {
      if (flags & MachO::SG_HIGHVM) {
        outs() << " HIGHVM";
        flags &= ~MachO::SG_HIGHVM;
      }
      if (flags & MachO::SG_FVMLIB) {
        outs() << " FVMLIB";
        flags &= ~MachO::SG_FVMLIB;
      }
      if (flags & MachO::SG_NORELOC) {
        outs() << " NORELOC";
        flags &= ~MachO::SG_NORELOC;
      }
      if (flags & MachO::SG_PROTECTED_VERSION_1) {
        outs() << " PROTECTED_VERSION_1";
        flags &= ~MachO::SG_PROTECTED_VERSION_1;
      }
      if (flags)
        outs() << format(" 0x%08" PRIx32, flags) << " (unknown flags)\n";
      else
        outs() << "\n";
    }
  } else {
    outs() << "    flags " << format("0x%" PRIx32, flags) << "\n";
  }
}

static void PrintSection(const char *sectname, const char *segname,
                         uint64_t addr, uint64_t size, uint32_t offset,
                         uint32_t align, uint32_t reloff, uint32_t nreloc,
                         uint32_t flags, uint32_t reserved1, uint32_t reserved2,
                         uint32_t cmd, const char *sg_segname,
                         uint32_t filetype, uint32_t object_size,
                         bool verbose) {
  outs() << "Section\n";
  outs() << "  sectname " << format("%.16s\n", sectname);
  outs() << "   segname " << format("%.16s", segname);
  if (filetype != MachO::MH_OBJECT && strncmp(sg_segname, segname, 16) != 0)
    outs() << " (does not match segment)\n";
  else
    outs() << "\n";
  if (cmd == MachO::LC_SEGMENT_64) {
    outs() << "      addr " << format("0x%016" PRIx64, addr) << "\n";
    outs() << "      size " << format("0x%016" PRIx64, size);
  } else {
    outs() << "      addr " << format("0x%08" PRIx64, addr) << "\n";
    outs() << "      size " << format("0x%08" PRIx64, size);
  }
  if ((flags & MachO::S_ZEROFILL) != 0 && offset + size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "    offset " << offset;
  if (offset > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  uint32_t align_shifted = 1 << align;
  outs() << "     align 2^" << align << " (" << align_shifted << ")\n";
  outs() << "    reloff " << reloff;
  if (reloff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "    nreloc " << nreloc;
  if (reloff + nreloc * sizeof(struct MachO::relocation_info) > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  uint32_t section_type = flags & MachO::SECTION_TYPE;
  if (verbose) {
    outs() << "      type";
    if (section_type == MachO::S_REGULAR)
      outs() << " S_REGULAR\n";
    else if (section_type == MachO::S_ZEROFILL)
      outs() << " S_ZEROFILL\n";
    else if (section_type == MachO::S_CSTRING_LITERALS)
      outs() << " S_CSTRING_LITERALS\n";
    else if (section_type == MachO::S_4BYTE_LITERALS)
      outs() << " S_4BYTE_LITERALS\n";
    else if (section_type == MachO::S_8BYTE_LITERALS)
      outs() << " S_8BYTE_LITERALS\n";
    else if (section_type == MachO::S_16BYTE_LITERALS)
      outs() << " S_16BYTE_LITERALS\n";
    else if (section_type == MachO::S_LITERAL_POINTERS)
      outs() << " S_LITERAL_POINTERS\n";
    else if (section_type == MachO::S_NON_LAZY_SYMBOL_POINTERS)
      outs() << " S_NON_LAZY_SYMBOL_POINTERS\n";
    else if (section_type == MachO::S_LAZY_SYMBOL_POINTERS)
      outs() << " S_LAZY_SYMBOL_POINTERS\n";
    else if (section_type == MachO::S_SYMBOL_STUBS)
      outs() << " S_SYMBOL_STUBS\n";
    else if (section_type == MachO::S_MOD_INIT_FUNC_POINTERS)
      outs() << " S_MOD_INIT_FUNC_POINTERS\n";
    else if (section_type == MachO::S_MOD_TERM_FUNC_POINTERS)
      outs() << " S_MOD_TERM_FUNC_POINTERS\n";
    else if (section_type == MachO::S_COALESCED)
      outs() << " S_COALESCED\n";
    else if (section_type == MachO::S_INTERPOSING)
      outs() << " S_INTERPOSING\n";
    else if (section_type == MachO::S_DTRACE_DOF)
      outs() << " S_DTRACE_DOF\n";
    else if (section_type == MachO::S_LAZY_DYLIB_SYMBOL_POINTERS)
      outs() << " S_LAZY_DYLIB_SYMBOL_POINTERS\n";
    else if (section_type == MachO::S_THREAD_LOCAL_REGULAR)
      outs() << " S_THREAD_LOCAL_REGULAR\n";
    else if (section_type == MachO::S_THREAD_LOCAL_ZEROFILL)
      outs() << " S_THREAD_LOCAL_ZEROFILL\n";
    else if (section_type == MachO::S_THREAD_LOCAL_VARIABLES)
      outs() << " S_THREAD_LOCAL_VARIABLES\n";
    else if (section_type == MachO::S_THREAD_LOCAL_VARIABLE_POINTERS)
      outs() << " S_THREAD_LOCAL_VARIABLE_POINTERS\n";
    else if (section_type == MachO::S_THREAD_LOCAL_INIT_FUNCTION_POINTERS)
      outs() << " S_THREAD_LOCAL_INIT_FUNCTION_POINTERS\n";
    else
      outs() << format("0x%08" PRIx32, section_type) << "\n";
    outs() << "attributes";
    uint32_t section_attributes = flags & MachO::SECTION_ATTRIBUTES;
    if (section_attributes & MachO::S_ATTR_PURE_INSTRUCTIONS)
      outs() << " PURE_INSTRUCTIONS";
    if (section_attributes & MachO::S_ATTR_NO_TOC)
      outs() << " NO_TOC";
    if (section_attributes & MachO::S_ATTR_STRIP_STATIC_SYMS)
      outs() << " STRIP_STATIC_SYMS";
    if (section_attributes & MachO::S_ATTR_NO_DEAD_STRIP)
      outs() << " NO_DEAD_STRIP";
    if (section_attributes & MachO::S_ATTR_LIVE_SUPPORT)
      outs() << " LIVE_SUPPORT";
    if (section_attributes & MachO::S_ATTR_SELF_MODIFYING_CODE)
      outs() << " SELF_MODIFYING_CODE";
    if (section_attributes & MachO::S_ATTR_DEBUG)
      outs() << " DEBUG";
    if (section_attributes & MachO::S_ATTR_SOME_INSTRUCTIONS)
      outs() << " SOME_INSTRUCTIONS";
    if (section_attributes & MachO::S_ATTR_EXT_RELOC)
      outs() << " EXT_RELOC";
    if (section_attributes & MachO::S_ATTR_LOC_RELOC)
      outs() << " LOC_RELOC";
    if (section_attributes == 0)
      outs() << " (none)";
    outs() << "\n";
  } else
    outs() << "     flags " << format("0x%08" PRIx32, flags) << "\n";
  outs() << " reserved1 " << reserved1;
  if (section_type == MachO::S_SYMBOL_STUBS ||
      section_type == MachO::S_LAZY_SYMBOL_POINTERS ||
      section_type == MachO::S_LAZY_DYLIB_SYMBOL_POINTERS ||
      section_type == MachO::S_NON_LAZY_SYMBOL_POINTERS ||
      section_type == MachO::S_THREAD_LOCAL_VARIABLE_POINTERS)
    outs() << " (index into indirect symbol table)\n";
  else
    outs() << "\n";
  outs() << " reserved2 " << reserved2;
  if (section_type == MachO::S_SYMBOL_STUBS)
    outs() << " (size of stubs)\n";
  else
    outs() << "\n";
}

static void PrintSymtabLoadCommand(MachO::symtab_command st, bool Is64Bit,
                                   uint32_t object_size) {
  outs() << "     cmd LC_SYMTAB\n";
  outs() << " cmdsize " << st.cmdsize;
  if (st.cmdsize != sizeof(struct MachO::symtab_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << "  symoff " << st.symoff;
  if (st.symoff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "   nsyms " << st.nsyms;
  uint64_t big_size;
  if (Is64Bit) {
    big_size = st.nsyms;
    big_size *= sizeof(struct MachO::nlist_64);
    big_size += st.symoff;
    if (big_size > object_size)
      outs() << " (past end of file)\n";
    else
      outs() << "\n";
  } else {
    big_size = st.nsyms;
    big_size *= sizeof(struct MachO::nlist);
    big_size += st.symoff;
    if (big_size > object_size)
      outs() << " (past end of file)\n";
    else
      outs() << "\n";
  }
  outs() << "  stroff " << st.stroff;
  if (st.stroff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << " strsize " << st.strsize;
  big_size = st.stroff;
  big_size += st.strsize;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
}

static void PrintDysymtabLoadCommand(MachO::dysymtab_command dyst,
                                     uint32_t nsyms, uint32_t object_size,
                                     bool Is64Bit) {
  outs() << "            cmd LC_DYSYMTAB\n";
  outs() << "        cmdsize " << dyst.cmdsize;
  if (dyst.cmdsize != sizeof(struct MachO::dysymtab_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << "      ilocalsym " << dyst.ilocalsym;
  if (dyst.ilocalsym > nsyms)
    outs() << " (greater than the number of symbols)\n";
  else
    outs() << "\n";
  outs() << "      nlocalsym " << dyst.nlocalsym;
  uint64_t big_size;
  big_size = dyst.ilocalsym;
  big_size += dyst.nlocalsym;
  if (big_size > nsyms)
    outs() << " (past the end of the symbol table)\n";
  else
    outs() << "\n";
  outs() << "     iextdefsym " << dyst.iextdefsym;
  if (dyst.iextdefsym > nsyms)
    outs() << " (greater than the number of symbols)\n";
  else
    outs() << "\n";
  outs() << "     nextdefsym " << dyst.nextdefsym;
  big_size = dyst.iextdefsym;
  big_size += dyst.nextdefsym;
  if (big_size > nsyms)
    outs() << " (past the end of the symbol table)\n";
  else
    outs() << "\n";
  outs() << "      iundefsym " << dyst.iundefsym;
  if (dyst.iundefsym > nsyms)
    outs() << " (greater than the number of symbols)\n";
  else
    outs() << "\n";
  outs() << "      nundefsym " << dyst.nundefsym;
  big_size = dyst.iundefsym;
  big_size += dyst.nundefsym;
  if (big_size > nsyms)
    outs() << " (past the end of the symbol table)\n";
  else
    outs() << "\n";
  outs() << "         tocoff " << dyst.tocoff;
  if (dyst.tocoff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "           ntoc " << dyst.ntoc;
  big_size = dyst.ntoc;
  big_size *= sizeof(struct MachO::dylib_table_of_contents);
  big_size += dyst.tocoff;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "      modtaboff " << dyst.modtaboff;
  if (dyst.modtaboff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "        nmodtab " << dyst.nmodtab;
  uint64_t modtabend;
  if (Is64Bit) {
    modtabend = dyst.nmodtab;
    modtabend *= sizeof(struct MachO::dylib_module_64);
    modtabend += dyst.modtaboff;
  } else {
    modtabend = dyst.nmodtab;
    modtabend *= sizeof(struct MachO::dylib_module);
    modtabend += dyst.modtaboff;
  }
  if (modtabend > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "   extrefsymoff " << dyst.extrefsymoff;
  if (dyst.extrefsymoff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "    nextrefsyms " << dyst.nextrefsyms;
  big_size = dyst.nextrefsyms;
  big_size *= sizeof(struct MachO::dylib_reference);
  big_size += dyst.extrefsymoff;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << " indirectsymoff " << dyst.indirectsymoff;
  if (dyst.indirectsymoff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "  nindirectsyms " << dyst.nindirectsyms;
  big_size = dyst.nindirectsyms;
  big_size *= sizeof(uint32_t);
  big_size += dyst.indirectsymoff;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "      extreloff " << dyst.extreloff;
  if (dyst.extreloff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "        nextrel " << dyst.nextrel;
  big_size = dyst.nextrel;
  big_size *= sizeof(struct MachO::relocation_info);
  big_size += dyst.extreloff;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "      locreloff " << dyst.locreloff;
  if (dyst.locreloff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "        nlocrel " << dyst.nlocrel;
  big_size = dyst.nlocrel;
  big_size *= sizeof(struct MachO::relocation_info);
  big_size += dyst.locreloff;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
}

static void PrintDyldInfoLoadCommand(MachO::dyld_info_command dc,
                                     uint32_t object_size) {
  if (dc.cmd == MachO::LC_DYLD_INFO)
    outs() << "            cmd LC_DYLD_INFO\n";
  else
    outs() << "            cmd LC_DYLD_INFO_ONLY\n";
  outs() << "        cmdsize " << dc.cmdsize;
  if (dc.cmdsize != sizeof(struct MachO::dyld_info_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << "     rebase_off " << dc.rebase_off;
  if (dc.rebase_off > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "    rebase_size " << dc.rebase_size;
  uint64_t big_size;
  big_size = dc.rebase_off;
  big_size += dc.rebase_size;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "       bind_off " << dc.bind_off;
  if (dc.bind_off > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "      bind_size " << dc.bind_size;
  big_size = dc.bind_off;
  big_size += dc.bind_size;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "  weak_bind_off " << dc.weak_bind_off;
  if (dc.weak_bind_off > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << " weak_bind_size " << dc.weak_bind_size;
  big_size = dc.weak_bind_off;
  big_size += dc.weak_bind_size;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "  lazy_bind_off " << dc.lazy_bind_off;
  if (dc.lazy_bind_off > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << " lazy_bind_size " << dc.lazy_bind_size;
  big_size = dc.lazy_bind_off;
  big_size += dc.lazy_bind_size;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "     export_off " << dc.export_off;
  if (dc.export_off > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "    export_size " << dc.export_size;
  big_size = dc.export_off;
  big_size += dc.export_size;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
}

static void PrintDyldLoadCommand(MachO::dylinker_command dyld,
                                 const char *Ptr) {
  if (dyld.cmd == MachO::LC_ID_DYLINKER)
    outs() << "          cmd LC_ID_DYLINKER\n";
  else if (dyld.cmd == MachO::LC_LOAD_DYLINKER)
    outs() << "          cmd LC_LOAD_DYLINKER\n";
  else if (dyld.cmd == MachO::LC_DYLD_ENVIRONMENT)
    outs() << "          cmd LC_DYLD_ENVIRONMENT\n";
  else
    outs() << "          cmd ?(" << dyld.cmd << ")\n";
  outs() << "      cmdsize " << dyld.cmdsize;
  if (dyld.cmdsize < sizeof(struct MachO::dylinker_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  if (dyld.name >= dyld.cmdsize)
    outs() << "         name ?(bad offset " << dyld.name << ")\n";
  else {
    const char *P = (const char *)(Ptr) + dyld.name;
    outs() << "         name " << P << " (offset " << dyld.name << ")\n";
  }
}

static void PrintUuidLoadCommand(MachO::uuid_command uuid) {
  outs() << "     cmd LC_UUID\n";
  outs() << " cmdsize " << uuid.cmdsize;
  if (uuid.cmdsize != sizeof(struct MachO::uuid_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << "    uuid ";
  for (int i = 0; i < 16; ++i) {
    outs() << format("%02" PRIX32, uuid.uuid[i]);
    if (i == 3 || i == 5 || i == 7 || i == 9)
      outs() << "-";
  }
  outs() << "\n";
}

static void PrintRpathLoadCommand(MachO::rpath_command rpath, const char *Ptr) {
  outs() << "          cmd LC_RPATH\n";
  outs() << "      cmdsize " << rpath.cmdsize;
  if (rpath.cmdsize < sizeof(struct MachO::rpath_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  if (rpath.path >= rpath.cmdsize)
    outs() << "         path ?(bad offset " << rpath.path << ")\n";
  else {
    const char *P = (const char *)(Ptr) + rpath.path;
    outs() << "         path " << P << " (offset " << rpath.path << ")\n";
  }
}

static void PrintVersionMinLoadCommand(MachO::version_min_command vd) {
  StringRef LoadCmdName;
  switch (vd.cmd) {
  case MachO::LC_VERSION_MIN_MACOSX:
    LoadCmdName = "LC_VERSION_MIN_MACOSX";
    break;
  case MachO::LC_VERSION_MIN_IPHONEOS:
    LoadCmdName = "LC_VERSION_MIN_IPHONEOS";
    break;
  case MachO::LC_VERSION_MIN_TVOS:
    LoadCmdName = "LC_VERSION_MIN_TVOS";
    break;
  case MachO::LC_VERSION_MIN_WATCHOS:
    LoadCmdName = "LC_VERSION_MIN_WATCHOS";
    break;
  default:
    llvm_unreachable("Unknown version min load command");
  }

  outs() << "      cmd " << LoadCmdName << '\n';
  outs() << "  cmdsize " << vd.cmdsize;
  if (vd.cmdsize != sizeof(struct MachO::version_min_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << "  version " << MachOObjectFile::getVersionMinMajor(vd, false)
         << "." << MachOObjectFile::getVersionMinMinor(vd, false);
  uint32_t Update = MachOObjectFile::getVersionMinUpdate(vd, false);
  if (Update != 0)
    outs() << "." << Update;
  outs() << "\n";
  if (vd.sdk == 0)
    outs() << "      sdk n/a";
  else {
    outs() << "      sdk " << MachOObjectFile::getVersionMinMajor(vd, true)
           << "." << MachOObjectFile::getVersionMinMinor(vd, true);
  }
  Update = MachOObjectFile::getVersionMinUpdate(vd, true);
  if (Update != 0)
    outs() << "." << Update;
  outs() << "\n";
}

static void PrintNoteLoadCommand(MachO::note_command Nt) {
  outs() << "       cmd LC_NOTE\n";
  outs() << "   cmdsize " << Nt.cmdsize;
  if (Nt.cmdsize != sizeof(struct MachO::note_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  const char *d = Nt.data_owner;
  outs() << "data_owner " << format("%.16s\n", d);
  outs() << "    offset " << Nt.offset << "\n";
  outs() << "      size " << Nt.size << "\n";
}

static void PrintBuildToolVersion(MachO::build_tool_version bv) {
  outs() << "      tool " << MachOObjectFile::getBuildTool(bv.tool) << "\n";
  outs() << "   version " << MachOObjectFile::getVersionString(bv.version)
         << "\n";
}

static void PrintBuildVersionLoadCommand(const MachOObjectFile *obj,
                                         MachO::build_version_command bd) {
  outs() << "       cmd LC_BUILD_VERSION\n";
  outs() << "   cmdsize " << bd.cmdsize;
  if (bd.cmdsize != sizeof(struct MachO::build_version_command) +
                        bd.ntools * sizeof(struct MachO::build_tool_version))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << "  platform " << MachOObjectFile::getBuildPlatform(bd.platform)
         << "\n";
  if (bd.sdk)
    outs() << "       sdk " << MachOObjectFile::getVersionString(bd.sdk)
           << "\n";
  else
    outs() << "       sdk n/a\n";
  outs() << "     minos " << MachOObjectFile::getVersionString(bd.minos)
         << "\n";
  outs() << "    ntools " << bd.ntools << "\n";
  for (unsigned i = 0; i < bd.ntools; ++i) {
    MachO::build_tool_version bv = obj->getBuildToolVersion(i);
    PrintBuildToolVersion(bv);
  }
}

static void PrintSourceVersionCommand(MachO::source_version_command sd) {
  outs() << "      cmd LC_SOURCE_VERSION\n";
  outs() << "  cmdsize " << sd.cmdsize;
  if (sd.cmdsize != sizeof(struct MachO::source_version_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  uint64_t a = (sd.version >> 40) & 0xffffff;
  uint64_t b = (sd.version >> 30) & 0x3ff;
  uint64_t c = (sd.version >> 20) & 0x3ff;
  uint64_t d = (sd.version >> 10) & 0x3ff;
  uint64_t e = sd.version & 0x3ff;
  outs() << "  version " << a << "." << b;
  if (e != 0)
    outs() << "." << c << "." << d << "." << e;
  else if (d != 0)
    outs() << "." << c << "." << d;
  else if (c != 0)
    outs() << "." << c;
  outs() << "\n";
}

static void PrintEntryPointCommand(MachO::entry_point_command ep) {
  outs() << "       cmd LC_MAIN\n";
  outs() << "   cmdsize " << ep.cmdsize;
  if (ep.cmdsize != sizeof(struct MachO::entry_point_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << "  entryoff " << ep.entryoff << "\n";
  outs() << " stacksize " << ep.stacksize << "\n";
}

static void PrintEncryptionInfoCommand(MachO::encryption_info_command ec,
                                       uint32_t object_size) {
  outs() << "          cmd LC_ENCRYPTION_INFO\n";
  outs() << "      cmdsize " << ec.cmdsize;
  if (ec.cmdsize != sizeof(struct MachO::encryption_info_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << "     cryptoff " << ec.cryptoff;
  if (ec.cryptoff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "    cryptsize " << ec.cryptsize;
  if (ec.cryptsize > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "      cryptid " << ec.cryptid << "\n";
}

static void PrintEncryptionInfoCommand64(MachO::encryption_info_command_64 ec,
                                         uint32_t object_size) {
  outs() << "          cmd LC_ENCRYPTION_INFO_64\n";
  outs() << "      cmdsize " << ec.cmdsize;
  if (ec.cmdsize != sizeof(struct MachO::encryption_info_command_64))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << "     cryptoff " << ec.cryptoff;
  if (ec.cryptoff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "    cryptsize " << ec.cryptsize;
  if (ec.cryptsize > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << "      cryptid " << ec.cryptid << "\n";
  outs() << "          pad " << ec.pad << "\n";
}

static void PrintLinkerOptionCommand(MachO::linker_option_command lo,
                                     const char *Ptr) {
  outs() << "     cmd LC_LINKER_OPTION\n";
  outs() << " cmdsize " << lo.cmdsize;
  if (lo.cmdsize < sizeof(struct MachO::linker_option_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << "   count " << lo.count << "\n";
  const char *string = Ptr + sizeof(struct MachO::linker_option_command);
  uint32_t left = lo.cmdsize - sizeof(struct MachO::linker_option_command);
  uint32_t i = 0;
  while (left > 0) {
    while (*string == '\0' && left > 0) {
      string++;
      left--;
    }
    if (left > 0) {
      i++;
      outs() << "  string #" << i << " " << format("%.*s\n", left, string);
      uint32_t NullPos = StringRef(string, left).find('\0');
      uint32_t len = std::min(NullPos, left) + 1;
      string += len;
      left -= len;
    }
  }
  if (lo.count != i)
    outs() << "   count " << lo.count << " does not match number of strings "
           << i << "\n";
}

static void PrintSubFrameworkCommand(MachO::sub_framework_command sub,
                                     const char *Ptr) {
  outs() << "          cmd LC_SUB_FRAMEWORK\n";
  outs() << "      cmdsize " << sub.cmdsize;
  if (sub.cmdsize < sizeof(struct MachO::sub_framework_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  if (sub.umbrella < sub.cmdsize) {
    const char *P = Ptr + sub.umbrella;
    outs() << "     umbrella " << P << " (offset " << sub.umbrella << ")\n";
  } else {
    outs() << "     umbrella ?(bad offset " << sub.umbrella << ")\n";
  }
}

static void PrintSubUmbrellaCommand(MachO::sub_umbrella_command sub,
                                    const char *Ptr) {
  outs() << "          cmd LC_SUB_UMBRELLA\n";
  outs() << "      cmdsize " << sub.cmdsize;
  if (sub.cmdsize < sizeof(struct MachO::sub_umbrella_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  if (sub.sub_umbrella < sub.cmdsize) {
    const char *P = Ptr + sub.sub_umbrella;
    outs() << " sub_umbrella " << P << " (offset " << sub.sub_umbrella << ")\n";
  } else {
    outs() << " sub_umbrella ?(bad offset " << sub.sub_umbrella << ")\n";
  }
}

static void PrintSubLibraryCommand(MachO::sub_library_command sub,
                                   const char *Ptr) {
  outs() << "          cmd LC_SUB_LIBRARY\n";
  outs() << "      cmdsize " << sub.cmdsize;
  if (sub.cmdsize < sizeof(struct MachO::sub_library_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  if (sub.sub_library < sub.cmdsize) {
    const char *P = Ptr + sub.sub_library;
    outs() << "  sub_library " << P << " (offset " << sub.sub_library << ")\n";
  } else {
    outs() << "  sub_library ?(bad offset " << sub.sub_library << ")\n";
  }
}

static void PrintSubClientCommand(MachO::sub_client_command sub,
                                  const char *Ptr) {
  outs() << "          cmd LC_SUB_CLIENT\n";
  outs() << "      cmdsize " << sub.cmdsize;
  if (sub.cmdsize < sizeof(struct MachO::sub_client_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  if (sub.client < sub.cmdsize) {
    const char *P = Ptr + sub.client;
    outs() << "       client " << P << " (offset " << sub.client << ")\n";
  } else {
    outs() << "       client ?(bad offset " << sub.client << ")\n";
  }
}

static void PrintRoutinesCommand(MachO::routines_command r) {
  outs() << "          cmd LC_ROUTINES\n";
  outs() << "      cmdsize " << r.cmdsize;
  if (r.cmdsize != sizeof(struct MachO::routines_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << " init_address " << format("0x%08" PRIx32, r.init_address) << "\n";
  outs() << "  init_module " << r.init_module << "\n";
  outs() << "    reserved1 " << r.reserved1 << "\n";
  outs() << "    reserved2 " << r.reserved2 << "\n";
  outs() << "    reserved3 " << r.reserved3 << "\n";
  outs() << "    reserved4 " << r.reserved4 << "\n";
  outs() << "    reserved5 " << r.reserved5 << "\n";
  outs() << "    reserved6 " << r.reserved6 << "\n";
}

static void PrintRoutinesCommand64(MachO::routines_command_64 r) {
  outs() << "          cmd LC_ROUTINES_64\n";
  outs() << "      cmdsize " << r.cmdsize;
  if (r.cmdsize != sizeof(struct MachO::routines_command_64))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << " init_address " << format("0x%016" PRIx64, r.init_address) << "\n";
  outs() << "  init_module " << r.init_module << "\n";
  outs() << "    reserved1 " << r.reserved1 << "\n";
  outs() << "    reserved2 " << r.reserved2 << "\n";
  outs() << "    reserved3 " << r.reserved3 << "\n";
  outs() << "    reserved4 " << r.reserved4 << "\n";
  outs() << "    reserved5 " << r.reserved5 << "\n";
  outs() << "    reserved6 " << r.reserved6 << "\n";
}

static void Print_x86_thread_state32_t(MachO::x86_thread_state32_t &cpu32) {
  outs() << "\t    eax " << format("0x%08" PRIx32, cpu32.eax);
  outs() << " ebx    " << format("0x%08" PRIx32, cpu32.ebx);
  outs() << " ecx " << format("0x%08" PRIx32, cpu32.ecx);
  outs() << " edx " << format("0x%08" PRIx32, cpu32.edx) << "\n";
  outs() << "\t    edi " << format("0x%08" PRIx32, cpu32.edi);
  outs() << " esi    " << format("0x%08" PRIx32, cpu32.esi);
  outs() << " ebp " << format("0x%08" PRIx32, cpu32.ebp);
  outs() << " esp " << format("0x%08" PRIx32, cpu32.esp) << "\n";
  outs() << "\t    ss  " << format("0x%08" PRIx32, cpu32.ss);
  outs() << " eflags " << format("0x%08" PRIx32, cpu32.eflags);
  outs() << " eip " << format("0x%08" PRIx32, cpu32.eip);
  outs() << " cs  " << format("0x%08" PRIx32, cpu32.cs) << "\n";
  outs() << "\t    ds  " << format("0x%08" PRIx32, cpu32.ds);
  outs() << " es     " << format("0x%08" PRIx32, cpu32.es);
  outs() << " fs  " << format("0x%08" PRIx32, cpu32.fs);
  outs() << " gs  " << format("0x%08" PRIx32, cpu32.gs) << "\n";
}

static void Print_x86_thread_state64_t(MachO::x86_thread_state64_t &cpu64) {
  outs() << "   rax  " << format("0x%016" PRIx64, cpu64.rax);
  outs() << " rbx " << format("0x%016" PRIx64, cpu64.rbx);
  outs() << " rcx  " << format("0x%016" PRIx64, cpu64.rcx) << "\n";
  outs() << "   rdx  " << format("0x%016" PRIx64, cpu64.rdx);
  outs() << " rdi " << format("0x%016" PRIx64, cpu64.rdi);
  outs() << " rsi  " << format("0x%016" PRIx64, cpu64.rsi) << "\n";
  outs() << "   rbp  " << format("0x%016" PRIx64, cpu64.rbp);
  outs() << " rsp " << format("0x%016" PRIx64, cpu64.rsp);
  outs() << " r8   " << format("0x%016" PRIx64, cpu64.r8) << "\n";
  outs() << "    r9  " << format("0x%016" PRIx64, cpu64.r9);
  outs() << " r10 " << format("0x%016" PRIx64, cpu64.r10);
  outs() << " r11  " << format("0x%016" PRIx64, cpu64.r11) << "\n";
  outs() << "   r12  " << format("0x%016" PRIx64, cpu64.r12);
  outs() << " r13 " << format("0x%016" PRIx64, cpu64.r13);
  outs() << " r14  " << format("0x%016" PRIx64, cpu64.r14) << "\n";
  outs() << "   r15  " << format("0x%016" PRIx64, cpu64.r15);
  outs() << " rip " << format("0x%016" PRIx64, cpu64.rip) << "\n";
  outs() << "rflags  " << format("0x%016" PRIx64, cpu64.rflags);
  outs() << " cs  " << format("0x%016" PRIx64, cpu64.cs);
  outs() << " fs   " << format("0x%016" PRIx64, cpu64.fs) << "\n";
  outs() << "    gs  " << format("0x%016" PRIx64, cpu64.gs) << "\n";
}

static void Print_mmst_reg(MachO::mmst_reg_t &r) {
  uint32_t f;
  outs() << "\t      mmst_reg  ";
  for (f = 0; f < 10; f++)
    outs() << format("%02" PRIx32, (r.mmst_reg[f] & 0xff)) << " ";
  outs() << "\n";
  outs() << "\t      mmst_rsrv ";
  for (f = 0; f < 6; f++)
    outs() << format("%02" PRIx32, (r.mmst_rsrv[f] & 0xff)) << " ";
  outs() << "\n";
}

static void Print_xmm_reg(MachO::xmm_reg_t &r) {
  uint32_t f;
  outs() << "\t      xmm_reg ";
  for (f = 0; f < 16; f++)
    outs() << format("%02" PRIx32, (r.xmm_reg[f] & 0xff)) << " ";
  outs() << "\n";
}

static void Print_x86_float_state_t(MachO::x86_float_state64_t &fpu) {
  outs() << "\t    fpu_reserved[0] " << fpu.fpu_reserved[0];
  outs() << " fpu_reserved[1] " << fpu.fpu_reserved[1] << "\n";
  outs() << "\t    control: invalid " << fpu.fpu_fcw.invalid;
  outs() << " denorm " << fpu.fpu_fcw.denorm;
  outs() << " zdiv " << fpu.fpu_fcw.zdiv;
  outs() << " ovrfl " << fpu.fpu_fcw.ovrfl;
  outs() << " undfl " << fpu.fpu_fcw.undfl;
  outs() << " precis " << fpu.fpu_fcw.precis << "\n";
  outs() << "\t\t     pc ";
  if (fpu.fpu_fcw.pc == MachO::x86_FP_PREC_24B)
    outs() << "FP_PREC_24B ";
  else if (fpu.fpu_fcw.pc == MachO::x86_FP_PREC_53B)
    outs() << "FP_PREC_53B ";
  else if (fpu.fpu_fcw.pc == MachO::x86_FP_PREC_64B)
    outs() << "FP_PREC_64B ";
  else
    outs() << fpu.fpu_fcw.pc << " ";
  outs() << "rc ";
  if (fpu.fpu_fcw.rc == MachO::x86_FP_RND_NEAR)
    outs() << "FP_RND_NEAR ";
  else if (fpu.fpu_fcw.rc == MachO::x86_FP_RND_DOWN)
    outs() << "FP_RND_DOWN ";
  else if (fpu.fpu_fcw.rc == MachO::x86_FP_RND_UP)
    outs() << "FP_RND_UP ";
  else if (fpu.fpu_fcw.rc == MachO::x86_FP_CHOP)
    outs() << "FP_CHOP ";
  outs() << "\n";
  outs() << "\t    status: invalid " << fpu.fpu_fsw.invalid;
  outs() << " denorm " << fpu.fpu_fsw.denorm;
  outs() << " zdiv " << fpu.fpu_fsw.zdiv;
  outs() << " ovrfl " << fpu.fpu_fsw.ovrfl;
  outs() << " undfl " << fpu.fpu_fsw.undfl;
  outs() << " precis " << fpu.fpu_fsw.precis;
  outs() << " stkflt " << fpu.fpu_fsw.stkflt << "\n";
  outs() << "\t            errsumm " << fpu.fpu_fsw.errsumm;
  outs() << " c0 " << fpu.fpu_fsw.c0;
  outs() << " c1 " << fpu.fpu_fsw.c1;
  outs() << " c2 " << fpu.fpu_fsw.c2;
  outs() << " tos " << fpu.fpu_fsw.tos;
  outs() << " c3 " << fpu.fpu_fsw.c3;
  outs() << " busy " << fpu.fpu_fsw.busy << "\n";
  outs() << "\t    fpu_ftw " << format("0x%02" PRIx32, fpu.fpu_ftw);
  outs() << " fpu_rsrv1 " << format("0x%02" PRIx32, fpu.fpu_rsrv1);
  outs() << " fpu_fop " << format("0x%04" PRIx32, fpu.fpu_fop);
  outs() << " fpu_ip " << format("0x%08" PRIx32, fpu.fpu_ip) << "\n";
  outs() << "\t    fpu_cs " << format("0x%04" PRIx32, fpu.fpu_cs);
  outs() << " fpu_rsrv2 " << format("0x%04" PRIx32, fpu.fpu_rsrv2);
  outs() << " fpu_dp " << format("0x%08" PRIx32, fpu.fpu_dp);
  outs() << " fpu_ds " << format("0x%04" PRIx32, fpu.fpu_ds) << "\n";
  outs() << "\t    fpu_rsrv3 " << format("0x%04" PRIx32, fpu.fpu_rsrv3);
  outs() << " fpu_mxcsr " << format("0x%08" PRIx32, fpu.fpu_mxcsr);
  outs() << " fpu_mxcsrmask " << format("0x%08" PRIx32, fpu.fpu_mxcsrmask);
  outs() << "\n";
  outs() << "\t    fpu_stmm0:\n";
  Print_mmst_reg(fpu.fpu_stmm0);
  outs() << "\t    fpu_stmm1:\n";
  Print_mmst_reg(fpu.fpu_stmm1);
  outs() << "\t    fpu_stmm2:\n";
  Print_mmst_reg(fpu.fpu_stmm2);
  outs() << "\t    fpu_stmm3:\n";
  Print_mmst_reg(fpu.fpu_stmm3);
  outs() << "\t    fpu_stmm4:\n";
  Print_mmst_reg(fpu.fpu_stmm4);
  outs() << "\t    fpu_stmm5:\n";
  Print_mmst_reg(fpu.fpu_stmm5);
  outs() << "\t    fpu_stmm6:\n";
  Print_mmst_reg(fpu.fpu_stmm6);
  outs() << "\t    fpu_stmm7:\n";
  Print_mmst_reg(fpu.fpu_stmm7);
  outs() << "\t    fpu_xmm0:\n";
  Print_xmm_reg(fpu.fpu_xmm0);
  outs() << "\t    fpu_xmm1:\n";
  Print_xmm_reg(fpu.fpu_xmm1);
  outs() << "\t    fpu_xmm2:\n";
  Print_xmm_reg(fpu.fpu_xmm2);
  outs() << "\t    fpu_xmm3:\n";
  Print_xmm_reg(fpu.fpu_xmm3);
  outs() << "\t    fpu_xmm4:\n";
  Print_xmm_reg(fpu.fpu_xmm4);
  outs() << "\t    fpu_xmm5:\n";
  Print_xmm_reg(fpu.fpu_xmm5);
  outs() << "\t    fpu_xmm6:\n";
  Print_xmm_reg(fpu.fpu_xmm6);
  outs() << "\t    fpu_xmm7:\n";
  Print_xmm_reg(fpu.fpu_xmm7);
  outs() << "\t    fpu_xmm8:\n";
  Print_xmm_reg(fpu.fpu_xmm8);
  outs() << "\t    fpu_xmm9:\n";
  Print_xmm_reg(fpu.fpu_xmm9);
  outs() << "\t    fpu_xmm10:\n";
  Print_xmm_reg(fpu.fpu_xmm10);
  outs() << "\t    fpu_xmm11:\n";
  Print_xmm_reg(fpu.fpu_xmm11);
  outs() << "\t    fpu_xmm12:\n";
  Print_xmm_reg(fpu.fpu_xmm12);
  outs() << "\t    fpu_xmm13:\n";
  Print_xmm_reg(fpu.fpu_xmm13);
  outs() << "\t    fpu_xmm14:\n";
  Print_xmm_reg(fpu.fpu_xmm14);
  outs() << "\t    fpu_xmm15:\n";
  Print_xmm_reg(fpu.fpu_xmm15);
  outs() << "\t    fpu_rsrv4:\n";
  for (uint32_t f = 0; f < 6; f++) {
    outs() << "\t            ";
    for (uint32_t g = 0; g < 16; g++)
      outs() << format("%02" PRIx32, fpu.fpu_rsrv4[f * g]) << " ";
    outs() << "\n";
  }
  outs() << "\t    fpu_reserved1 " << format("0x%08" PRIx32, fpu.fpu_reserved1);
  outs() << "\n";
}

static void Print_x86_exception_state_t(MachO::x86_exception_state64_t &exc64) {
  outs() << "\t    trapno " << format("0x%08" PRIx32, exc64.trapno);
  outs() << " err " << format("0x%08" PRIx32, exc64.err);
  outs() << " faultvaddr " << format("0x%016" PRIx64, exc64.faultvaddr) << "\n";
}

static void Print_arm_thread_state32_t(MachO::arm_thread_state32_t &cpu32) {
  outs() << "\t    r0  " << format("0x%08" PRIx32, cpu32.r[0]);
  outs() << " r1     " << format("0x%08" PRIx32, cpu32.r[1]);
  outs() << " r2  " << format("0x%08" PRIx32, cpu32.r[2]);
  outs() << " r3  " << format("0x%08" PRIx32, cpu32.r[3]) << "\n";
  outs() << "\t    r4  " << format("0x%08" PRIx32, cpu32.r[4]);
  outs() << " r5     " << format("0x%08" PRIx32, cpu32.r[5]);
  outs() << " r6  " << format("0x%08" PRIx32, cpu32.r[6]);
  outs() << " r7  " << format("0x%08" PRIx32, cpu32.r[7]) << "\n";
  outs() << "\t    r8  " << format("0x%08" PRIx32, cpu32.r[8]);
  outs() << " r9     " << format("0x%08" PRIx32, cpu32.r[9]);
  outs() << " r10 " << format("0x%08" PRIx32, cpu32.r[10]);
  outs() << " r11 " << format("0x%08" PRIx32, cpu32.r[11]) << "\n";
  outs() << "\t    r12 " << format("0x%08" PRIx32, cpu32.r[12]);
  outs() << " sp     " << format("0x%08" PRIx32, cpu32.sp);
  outs() << " lr  " << format("0x%08" PRIx32, cpu32.lr);
  outs() << " pc  " << format("0x%08" PRIx32, cpu32.pc) << "\n";
  outs() << "\t   cpsr " << format("0x%08" PRIx32, cpu32.cpsr) << "\n";
}

static void Print_arm_thread_state64_t(MachO::arm_thread_state64_t &cpu64) {
  outs() << "\t    x0  " << format("0x%016" PRIx64, cpu64.x[0]);
  outs() << " x1  " << format("0x%016" PRIx64, cpu64.x[1]);
  outs() << " x2  " << format("0x%016" PRIx64, cpu64.x[2]) << "\n";
  outs() << "\t    x3  " << format("0x%016" PRIx64, cpu64.x[3]);
  outs() << " x4  " << format("0x%016" PRIx64, cpu64.x[4]);
  outs() << " x5  " << format("0x%016" PRIx64, cpu64.x[5]) << "\n";
  outs() << "\t    x6  " << format("0x%016" PRIx64, cpu64.x[6]);
  outs() << " x7  " << format("0x%016" PRIx64, cpu64.x[7]);
  outs() << " x8  " << format("0x%016" PRIx64, cpu64.x[8]) << "\n";
  outs() << "\t    x9  " << format("0x%016" PRIx64, cpu64.x[9]);
  outs() << " x10 " << format("0x%016" PRIx64, cpu64.x[10]);
  outs() << " x11 " << format("0x%016" PRIx64, cpu64.x[11]) << "\n";
  outs() << "\t    x12 " << format("0x%016" PRIx64, cpu64.x[12]);
  outs() << " x13 " << format("0x%016" PRIx64, cpu64.x[13]);
  outs() << " x14 " << format("0x%016" PRIx64, cpu64.x[14]) << "\n";
  outs() << "\t    x15 " << format("0x%016" PRIx64, cpu64.x[15]);
  outs() << " x16 " << format("0x%016" PRIx64, cpu64.x[16]);
  outs() << " x17 " << format("0x%016" PRIx64, cpu64.x[17]) << "\n";
  outs() << "\t    x18 " << format("0x%016" PRIx64, cpu64.x[18]);
  outs() << " x19 " << format("0x%016" PRIx64, cpu64.x[19]);
  outs() << " x20 " << format("0x%016" PRIx64, cpu64.x[20]) << "\n";
  outs() << "\t    x21 " << format("0x%016" PRIx64, cpu64.x[21]);
  outs() << " x22 " << format("0x%016" PRIx64, cpu64.x[22]);
  outs() << " x23 " << format("0x%016" PRIx64, cpu64.x[23]) << "\n";
  outs() << "\t    x24 " << format("0x%016" PRIx64, cpu64.x[24]);
  outs() << " x25 " << format("0x%016" PRIx64, cpu64.x[25]);
  outs() << " x26 " << format("0x%016" PRIx64, cpu64.x[26]) << "\n";
  outs() << "\t    x27 " << format("0x%016" PRIx64, cpu64.x[27]);
  outs() << " x28 " << format("0x%016" PRIx64, cpu64.x[28]);
  outs() << "  fp " << format("0x%016" PRIx64, cpu64.fp) << "\n";
  outs() << "\t     lr " << format("0x%016" PRIx64, cpu64.lr);
  outs() << " sp  " << format("0x%016" PRIx64, cpu64.sp);
  outs() << "  pc " << format("0x%016" PRIx64, cpu64.pc) << "\n";
  outs() << "\t   cpsr " << format("0x%08" PRIx32, cpu64.cpsr) << "\n";
}

static void PrintThreadCommand(MachO::thread_command t, const char *Ptr,
                               bool isLittleEndian, uint32_t cputype) {
  if (t.cmd == MachO::LC_THREAD)
    outs() << "        cmd LC_THREAD\n";
  else if (t.cmd == MachO::LC_UNIXTHREAD)
    outs() << "        cmd LC_UNIXTHREAD\n";
  else
    outs() << "        cmd " << t.cmd << " (unknown)\n";
  outs() << "    cmdsize " << t.cmdsize;
  if (t.cmdsize < sizeof(struct MachO::thread_command) + 2 * sizeof(uint32_t))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";

  const char *begin = Ptr + sizeof(struct MachO::thread_command);
  const char *end = Ptr + t.cmdsize;
  uint32_t flavor, count, left;
  if (cputype == MachO::CPU_TYPE_I386) {
    while (begin < end) {
      if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
        memcpy((char *)&flavor, begin, sizeof(uint32_t));
        begin += sizeof(uint32_t);
      } else {
        flavor = 0;
        begin = end;
      }
      if (isLittleEndian != sys::IsLittleEndianHost)
        sys::swapByteOrder(flavor);
      if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
        memcpy((char *)&count, begin, sizeof(uint32_t));
        begin += sizeof(uint32_t);
      } else {
        count = 0;
        begin = end;
      }
      if (isLittleEndian != sys::IsLittleEndianHost)
        sys::swapByteOrder(count);
      if (flavor == MachO::x86_THREAD_STATE32) {
        outs() << "     flavor i386_THREAD_STATE\n";
        if (count == MachO::x86_THREAD_STATE32_COUNT)
          outs() << "      count i386_THREAD_STATE_COUNT\n";
        else
          outs() << "      count " << count
                 << " (not x86_THREAD_STATE32_COUNT)\n";
        MachO::x86_thread_state32_t cpu32;
        left = end - begin;
        if (left >= sizeof(MachO::x86_thread_state32_t)) {
          memcpy(&cpu32, begin, sizeof(MachO::x86_thread_state32_t));
          begin += sizeof(MachO::x86_thread_state32_t);
        } else {
          memset(&cpu32, '\0', sizeof(MachO::x86_thread_state32_t));
          memcpy(&cpu32, begin, left);
          begin += left;
        }
        if (isLittleEndian != sys::IsLittleEndianHost)
          swapStruct(cpu32);
        Print_x86_thread_state32_t(cpu32);
      } else if (flavor == MachO::x86_THREAD_STATE) {
        outs() << "     flavor x86_THREAD_STATE\n";
        if (count == MachO::x86_THREAD_STATE_COUNT)
          outs() << "      count x86_THREAD_STATE_COUNT\n";
        else
          outs() << "      count " << count
                 << " (not x86_THREAD_STATE_COUNT)\n";
        struct MachO::x86_thread_state_t ts;
        left = end - begin;
        if (left >= sizeof(MachO::x86_thread_state_t)) {
          memcpy(&ts, begin, sizeof(MachO::x86_thread_state_t));
          begin += sizeof(MachO::x86_thread_state_t);
        } else {
          memset(&ts, '\0', sizeof(MachO::x86_thread_state_t));
          memcpy(&ts, begin, left);
          begin += left;
        }
        if (isLittleEndian != sys::IsLittleEndianHost)
          swapStruct(ts);
        if (ts.tsh.flavor == MachO::x86_THREAD_STATE32) {
          outs() << "\t    tsh.flavor x86_THREAD_STATE32 ";
          if (ts.tsh.count == MachO::x86_THREAD_STATE32_COUNT)
            outs() << "tsh.count x86_THREAD_STATE32_COUNT\n";
          else
            outs() << "tsh.count " << ts.tsh.count
                   << " (not x86_THREAD_STATE32_COUNT\n";
          Print_x86_thread_state32_t(ts.uts.ts32);
        } else {
          outs() << "\t    tsh.flavor " << ts.tsh.flavor << "  tsh.count "
                 << ts.tsh.count << "\n";
        }
      } else {
        outs() << "     flavor " << flavor << " (unknown)\n";
        outs() << "      count " << count << "\n";
        outs() << "      state (unknown)\n";
        begin += count * sizeof(uint32_t);
      }
    }
  } else if (cputype == MachO::CPU_TYPE_X86_64) {
    while (begin < end) {
      if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
        memcpy((char *)&flavor, begin, sizeof(uint32_t));
        begin += sizeof(uint32_t);
      } else {
        flavor = 0;
        begin = end;
      }
      if (isLittleEndian != sys::IsLittleEndianHost)
        sys::swapByteOrder(flavor);
      if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
        memcpy((char *)&count, begin, sizeof(uint32_t));
        begin += sizeof(uint32_t);
      } else {
        count = 0;
        begin = end;
      }
      if (isLittleEndian != sys::IsLittleEndianHost)
        sys::swapByteOrder(count);
      if (flavor == MachO::x86_THREAD_STATE64) {
        outs() << "     flavor x86_THREAD_STATE64\n";
        if (count == MachO::x86_THREAD_STATE64_COUNT)
          outs() << "      count x86_THREAD_STATE64_COUNT\n";
        else
          outs() << "      count " << count
                 << " (not x86_THREAD_STATE64_COUNT)\n";
        MachO::x86_thread_state64_t cpu64;
        left = end - begin;
        if (left >= sizeof(MachO::x86_thread_state64_t)) {
          memcpy(&cpu64, begin, sizeof(MachO::x86_thread_state64_t));
          begin += sizeof(MachO::x86_thread_state64_t);
        } else {
          memset(&cpu64, '\0', sizeof(MachO::x86_thread_state64_t));
          memcpy(&cpu64, begin, left);
          begin += left;
        }
        if (isLittleEndian != sys::IsLittleEndianHost)
          swapStruct(cpu64);
        Print_x86_thread_state64_t(cpu64);
      } else if (flavor == MachO::x86_THREAD_STATE) {
        outs() << "     flavor x86_THREAD_STATE\n";
        if (count == MachO::x86_THREAD_STATE_COUNT)
          outs() << "      count x86_THREAD_STATE_COUNT\n";
        else
          outs() << "      count " << count
                 << " (not x86_THREAD_STATE_COUNT)\n";
        struct MachO::x86_thread_state_t ts;
        left = end - begin;
        if (left >= sizeof(MachO::x86_thread_state_t)) {
          memcpy(&ts, begin, sizeof(MachO::x86_thread_state_t));
          begin += sizeof(MachO::x86_thread_state_t);
        } else {
          memset(&ts, '\0', sizeof(MachO::x86_thread_state_t));
          memcpy(&ts, begin, left);
          begin += left;
        }
        if (isLittleEndian != sys::IsLittleEndianHost)
          swapStruct(ts);
        if (ts.tsh.flavor == MachO::x86_THREAD_STATE64) {
          outs() << "\t    tsh.flavor x86_THREAD_STATE64 ";
          if (ts.tsh.count == MachO::x86_THREAD_STATE64_COUNT)
            outs() << "tsh.count x86_THREAD_STATE64_COUNT\n";
          else
            outs() << "tsh.count " << ts.tsh.count
                   << " (not x86_THREAD_STATE64_COUNT\n";
          Print_x86_thread_state64_t(ts.uts.ts64);
        } else {
          outs() << "\t    tsh.flavor " << ts.tsh.flavor << "  tsh.count "
                 << ts.tsh.count << "\n";
        }
      } else if (flavor == MachO::x86_FLOAT_STATE) {
        outs() << "     flavor x86_FLOAT_STATE\n";
        if (count == MachO::x86_FLOAT_STATE_COUNT)
          outs() << "      count x86_FLOAT_STATE_COUNT\n";
        else
          outs() << "      count " << count << " (not x86_FLOAT_STATE_COUNT)\n";
        struct MachO::x86_float_state_t fs;
        left = end - begin;
        if (left >= sizeof(MachO::x86_float_state_t)) {
          memcpy(&fs, begin, sizeof(MachO::x86_float_state_t));
          begin += sizeof(MachO::x86_float_state_t);
        } else {
          memset(&fs, '\0', sizeof(MachO::x86_float_state_t));
          memcpy(&fs, begin, left);
          begin += left;
        }
        if (isLittleEndian != sys::IsLittleEndianHost)
          swapStruct(fs);
        if (fs.fsh.flavor == MachO::x86_FLOAT_STATE64) {
          outs() << "\t    fsh.flavor x86_FLOAT_STATE64 ";
          if (fs.fsh.count == MachO::x86_FLOAT_STATE64_COUNT)
            outs() << "fsh.count x86_FLOAT_STATE64_COUNT\n";
          else
            outs() << "fsh.count " << fs.fsh.count
                   << " (not x86_FLOAT_STATE64_COUNT\n";
          Print_x86_float_state_t(fs.ufs.fs64);
        } else {
          outs() << "\t    fsh.flavor " << fs.fsh.flavor << "  fsh.count "
                 << fs.fsh.count << "\n";
        }
      } else if (flavor == MachO::x86_EXCEPTION_STATE) {
        outs() << "     flavor x86_EXCEPTION_STATE\n";
        if (count == MachO::x86_EXCEPTION_STATE_COUNT)
          outs() << "      count x86_EXCEPTION_STATE_COUNT\n";
        else
          outs() << "      count " << count
                 << " (not x86_EXCEPTION_STATE_COUNT)\n";
        struct MachO::x86_exception_state_t es;
        left = end - begin;
        if (left >= sizeof(MachO::x86_exception_state_t)) {
          memcpy(&es, begin, sizeof(MachO::x86_exception_state_t));
          begin += sizeof(MachO::x86_exception_state_t);
        } else {
          memset(&es, '\0', sizeof(MachO::x86_exception_state_t));
          memcpy(&es, begin, left);
          begin += left;
        }
        if (isLittleEndian != sys::IsLittleEndianHost)
          swapStruct(es);
        if (es.esh.flavor == MachO::x86_EXCEPTION_STATE64) {
          outs() << "\t    esh.flavor x86_EXCEPTION_STATE64\n";
          if (es.esh.count == MachO::x86_EXCEPTION_STATE64_COUNT)
            outs() << "\t    esh.count x86_EXCEPTION_STATE64_COUNT\n";
          else
            outs() << "\t    esh.count " << es.esh.count
                   << " (not x86_EXCEPTION_STATE64_COUNT\n";
          Print_x86_exception_state_t(es.ues.es64);
        } else {
          outs() << "\t    esh.flavor " << es.esh.flavor << "  esh.count "
                 << es.esh.count << "\n";
        }
      } else {
        outs() << "     flavor " << flavor << " (unknown)\n";
        outs() << "      count " << count << "\n";
        outs() << "      state (unknown)\n";
        begin += count * sizeof(uint32_t);
      }
    }
  } else if (cputype == MachO::CPU_TYPE_ARM) {
    while (begin < end) {
      if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
        memcpy((char *)&flavor, begin, sizeof(uint32_t));
        begin += sizeof(uint32_t);
      } else {
        flavor = 0;
        begin = end;
      }
      if (isLittleEndian != sys::IsLittleEndianHost)
        sys::swapByteOrder(flavor);
      if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
        memcpy((char *)&count, begin, sizeof(uint32_t));
        begin += sizeof(uint32_t);
      } else {
        count = 0;
        begin = end;
      }
      if (isLittleEndian != sys::IsLittleEndianHost)
        sys::swapByteOrder(count);
      if (flavor == MachO::ARM_THREAD_STATE) {
        outs() << "     flavor ARM_THREAD_STATE\n";
        if (count == MachO::ARM_THREAD_STATE_COUNT)
          outs() << "      count ARM_THREAD_STATE_COUNT\n";
        else
          outs() << "      count " << count
                 << " (not ARM_THREAD_STATE_COUNT)\n";
        MachO::arm_thread_state32_t cpu32;
        left = end - begin;
        if (left >= sizeof(MachO::arm_thread_state32_t)) {
          memcpy(&cpu32, begin, sizeof(MachO::arm_thread_state32_t));
          begin += sizeof(MachO::arm_thread_state32_t);
        } else {
          memset(&cpu32, '\0', sizeof(MachO::arm_thread_state32_t));
          memcpy(&cpu32, begin, left);
          begin += left;
        }
        if (isLittleEndian != sys::IsLittleEndianHost)
          swapStruct(cpu32);
        Print_arm_thread_state32_t(cpu32);
      } else {
        outs() << "     flavor " << flavor << " (unknown)\n";
        outs() << "      count " << count << "\n";
        outs() << "      state (unknown)\n";
        begin += count * sizeof(uint32_t);
      }
    }
  } else if (cputype == MachO::CPU_TYPE_ARM64) {
    while (begin < end) {
      if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
        memcpy((char *)&flavor, begin, sizeof(uint32_t));
        begin += sizeof(uint32_t);
      } else {
        flavor = 0;
        begin = end;
      }
      if (isLittleEndian != sys::IsLittleEndianHost)
        sys::swapByteOrder(flavor);
      if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
        memcpy((char *)&count, begin, sizeof(uint32_t));
        begin += sizeof(uint32_t);
      } else {
        count = 0;
        begin = end;
      }
      if (isLittleEndian != sys::IsLittleEndianHost)
        sys::swapByteOrder(count);
      if (flavor == MachO::ARM_THREAD_STATE64) {
        outs() << "     flavor ARM_THREAD_STATE64\n";
        if (count == MachO::ARM_THREAD_STATE64_COUNT)
          outs() << "      count ARM_THREAD_STATE64_COUNT\n";
        else
          outs() << "      count " << count
                 << " (not ARM_THREAD_STATE64_COUNT)\n";
        MachO::arm_thread_state64_t cpu64;
        left = end - begin;
        if (left >= sizeof(MachO::arm_thread_state64_t)) {
          memcpy(&cpu64, begin, sizeof(MachO::arm_thread_state64_t));
          begin += sizeof(MachO::arm_thread_state64_t);
        } else {
          memset(&cpu64, '\0', sizeof(MachO::arm_thread_state64_t));
          memcpy(&cpu64, begin, left);
          begin += left;
        }
        if (isLittleEndian != sys::IsLittleEndianHost)
          swapStruct(cpu64);
        Print_arm_thread_state64_t(cpu64);
      } else {
        outs() << "     flavor " << flavor << " (unknown)\n";
        outs() << "      count " << count << "\n";
        outs() << "      state (unknown)\n";
        begin += count * sizeof(uint32_t);
      }
    }
  } else {
    while (begin < end) {
      if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
        memcpy((char *)&flavor, begin, sizeof(uint32_t));
        begin += sizeof(uint32_t);
      } else {
        flavor = 0;
        begin = end;
      }
      if (isLittleEndian != sys::IsLittleEndianHost)
        sys::swapByteOrder(flavor);
      if (end - begin > (ptrdiff_t)sizeof(uint32_t)) {
        memcpy((char *)&count, begin, sizeof(uint32_t));
        begin += sizeof(uint32_t);
      } else {
        count = 0;
        begin = end;
      }
      if (isLittleEndian != sys::IsLittleEndianHost)
        sys::swapByteOrder(count);
      outs() << "     flavor " << flavor << "\n";
      outs() << "      count " << count << "\n";
      outs() << "      state (Unknown cputype/cpusubtype)\n";
      begin += count * sizeof(uint32_t);
    }
  }
}

static void PrintDylibCommand(MachO::dylib_command dl, const char *Ptr) {
  if (dl.cmd == MachO::LC_ID_DYLIB)
    outs() << "          cmd LC_ID_DYLIB\n";
  else if (dl.cmd == MachO::LC_LOAD_DYLIB)
    outs() << "          cmd LC_LOAD_DYLIB\n";
  else if (dl.cmd == MachO::LC_LOAD_WEAK_DYLIB)
    outs() << "          cmd LC_LOAD_WEAK_DYLIB\n";
  else if (dl.cmd == MachO::LC_REEXPORT_DYLIB)
    outs() << "          cmd LC_REEXPORT_DYLIB\n";
  else if (dl.cmd == MachO::LC_LAZY_LOAD_DYLIB)
    outs() << "          cmd LC_LAZY_LOAD_DYLIB\n";
  else if (dl.cmd == MachO::LC_LOAD_UPWARD_DYLIB)
    outs() << "          cmd LC_LOAD_UPWARD_DYLIB\n";
  else
    outs() << "          cmd " << dl.cmd << " (unknown)\n";
  outs() << "      cmdsize " << dl.cmdsize;
  if (dl.cmdsize < sizeof(struct MachO::dylib_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  if (dl.dylib.name < dl.cmdsize) {
    const char *P = (const char *)(Ptr) + dl.dylib.name;
    outs() << "         name " << P << " (offset " << dl.dylib.name << ")\n";
  } else {
    outs() << "         name ?(bad offset " << dl.dylib.name << ")\n";
  }
  outs() << "   time stamp " << dl.dylib.timestamp << " ";
  time_t t = dl.dylib.timestamp;
  outs() << ctime(&t);
  outs() << "      current version ";
  if (dl.dylib.current_version == 0xffffffff)
    outs() << "n/a\n";
  else
    outs() << ((dl.dylib.current_version >> 16) & 0xffff) << "."
           << ((dl.dylib.current_version >> 8) & 0xff) << "."
           << (dl.dylib.current_version & 0xff) << "\n";
  outs() << "compatibility version ";
  if (dl.dylib.compatibility_version == 0xffffffff)
    outs() << "n/a\n";
  else
    outs() << ((dl.dylib.compatibility_version >> 16) & 0xffff) << "."
           << ((dl.dylib.compatibility_version >> 8) & 0xff) << "."
           << (dl.dylib.compatibility_version & 0xff) << "\n";
}

static void PrintLinkEditDataCommand(MachO::linkedit_data_command ld,
                                     uint32_t object_size) {
  if (ld.cmd == MachO::LC_CODE_SIGNATURE)
    outs() << "      cmd LC_CODE_SIGNATURE\n";
  else if (ld.cmd == MachO::LC_SEGMENT_SPLIT_INFO)
    outs() << "      cmd LC_SEGMENT_SPLIT_INFO\n";
  else if (ld.cmd == MachO::LC_FUNCTION_STARTS)
    outs() << "      cmd LC_FUNCTION_STARTS\n";
  else if (ld.cmd == MachO::LC_DATA_IN_CODE)
    outs() << "      cmd LC_DATA_IN_CODE\n";
  else if (ld.cmd == MachO::LC_DYLIB_CODE_SIGN_DRS)
    outs() << "      cmd LC_DYLIB_CODE_SIGN_DRS\n";
  else if (ld.cmd == MachO::LC_LINKER_OPTIMIZATION_HINT)
    outs() << "      cmd LC_LINKER_OPTIMIZATION_HINT\n";
  else
    outs() << "      cmd " << ld.cmd << " (?)\n";
  outs() << "  cmdsize " << ld.cmdsize;
  if (ld.cmdsize != sizeof(struct MachO::linkedit_data_command))
    outs() << " Incorrect size\n";
  else
    outs() << "\n";
  outs() << "  dataoff " << ld.dataoff;
  if (ld.dataoff > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
  outs() << " datasize " << ld.datasize;
  uint64_t big_size = ld.dataoff;
  big_size += ld.datasize;
  if (big_size > object_size)
    outs() << " (past end of file)\n";
  else
    outs() << "\n";
}

static void PrintLoadCommands(const MachOObjectFile *Obj, uint32_t filetype,
                              uint32_t cputype, bool verbose) {
  StringRef Buf = Obj->getData();
  unsigned Index = 0;
  for (const auto &Command : Obj->load_commands()) {
    outs() << "Load command " << Index++ << "\n";
    if (Command.C.cmd == MachO::LC_SEGMENT) {
      MachO::segment_command SLC = Obj->getSegmentLoadCommand(Command);
      const char *sg_segname = SLC.segname;
      PrintSegmentCommand(SLC.cmd, SLC.cmdsize, SLC.segname, SLC.vmaddr,
                          SLC.vmsize, SLC.fileoff, SLC.filesize, SLC.maxprot,
                          SLC.initprot, SLC.nsects, SLC.flags, Buf.size(),
                          verbose);
      for (unsigned j = 0; j < SLC.nsects; j++) {
        MachO::section S = Obj->getSection(Command, j);
        PrintSection(S.sectname, S.segname, S.addr, S.size, S.offset, S.align,
                     S.reloff, S.nreloc, S.flags, S.reserved1, S.reserved2,
                     SLC.cmd, sg_segname, filetype, Buf.size(), verbose);
      }
    } else if (Command.C.cmd == MachO::LC_SEGMENT_64) {
      MachO::segment_command_64 SLC_64 = Obj->getSegment64LoadCommand(Command);
      const char *sg_segname = SLC_64.segname;
      PrintSegmentCommand(SLC_64.cmd, SLC_64.cmdsize, SLC_64.segname,
                          SLC_64.vmaddr, SLC_64.vmsize, SLC_64.fileoff,
                          SLC_64.filesize, SLC_64.maxprot, SLC_64.initprot,
                          SLC_64.nsects, SLC_64.flags, Buf.size(), verbose);
      for (unsigned j = 0; j < SLC_64.nsects; j++) {
        MachO::section_64 S_64 = Obj->getSection64(Command, j);
        PrintSection(S_64.sectname, S_64.segname, S_64.addr, S_64.size,
                     S_64.offset, S_64.align, S_64.reloff, S_64.nreloc,
                     S_64.flags, S_64.reserved1, S_64.reserved2, SLC_64.cmd,
                     sg_segname, filetype, Buf.size(), verbose);
      }
    } else if (Command.C.cmd == MachO::LC_SYMTAB) {
      MachO::symtab_command Symtab = Obj->getSymtabLoadCommand();
      PrintSymtabLoadCommand(Symtab, Obj->is64Bit(), Buf.size());
    } else if (Command.C.cmd == MachO::LC_DYSYMTAB) {
      MachO::dysymtab_command Dysymtab = Obj->getDysymtabLoadCommand();
      MachO::symtab_command Symtab = Obj->getSymtabLoadCommand();
      PrintDysymtabLoadCommand(Dysymtab, Symtab.nsyms, Buf.size(),
                               Obj->is64Bit());
    } else if (Command.C.cmd == MachO::LC_DYLD_INFO ||
               Command.C.cmd == MachO::LC_DYLD_INFO_ONLY) {
      MachO::dyld_info_command DyldInfo = Obj->getDyldInfoLoadCommand(Command);
      PrintDyldInfoLoadCommand(DyldInfo, Buf.size());
    } else if (Command.C.cmd == MachO::LC_LOAD_DYLINKER ||
               Command.C.cmd == MachO::LC_ID_DYLINKER ||
               Command.C.cmd == MachO::LC_DYLD_ENVIRONMENT) {
      MachO::dylinker_command Dyld = Obj->getDylinkerCommand(Command);
      PrintDyldLoadCommand(Dyld, Command.Ptr);
    } else if (Command.C.cmd == MachO::LC_UUID) {
      MachO::uuid_command Uuid = Obj->getUuidCommand(Command);
      PrintUuidLoadCommand(Uuid);
    } else if (Command.C.cmd == MachO::LC_RPATH) {
      MachO::rpath_command Rpath = Obj->getRpathCommand(Command);
      PrintRpathLoadCommand(Rpath, Command.Ptr);
    } else if (Command.C.cmd == MachO::LC_VERSION_MIN_MACOSX ||
               Command.C.cmd == MachO::LC_VERSION_MIN_IPHONEOS ||
               Command.C.cmd == MachO::LC_VERSION_MIN_TVOS ||
               Command.C.cmd == MachO::LC_VERSION_MIN_WATCHOS) {
      MachO::version_min_command Vd = Obj->getVersionMinLoadCommand(Command);
      PrintVersionMinLoadCommand(Vd);
    } else if (Command.C.cmd == MachO::LC_NOTE) {
      MachO::note_command Nt = Obj->getNoteLoadCommand(Command);
      PrintNoteLoadCommand(Nt);
    } else if (Command.C.cmd == MachO::LC_BUILD_VERSION) {
      MachO::build_version_command Bv =
          Obj->getBuildVersionLoadCommand(Command);
      PrintBuildVersionLoadCommand(Obj, Bv);
    } else if (Command.C.cmd == MachO::LC_SOURCE_VERSION) {
      MachO::source_version_command Sd = Obj->getSourceVersionCommand(Command);
      PrintSourceVersionCommand(Sd);
    } else if (Command.C.cmd == MachO::LC_MAIN) {
      MachO::entry_point_command Ep = Obj->getEntryPointCommand(Command);
      PrintEntryPointCommand(Ep);
    } else if (Command.C.cmd == MachO::LC_ENCRYPTION_INFO) {
      MachO::encryption_info_command Ei =
          Obj->getEncryptionInfoCommand(Command);
      PrintEncryptionInfoCommand(Ei, Buf.size());
    } else if (Command.C.cmd == MachO::LC_ENCRYPTION_INFO_64) {
      MachO::encryption_info_command_64 Ei =
          Obj->getEncryptionInfoCommand64(Command);
      PrintEncryptionInfoCommand64(Ei, Buf.size());
    } else if (Command.C.cmd == MachO::LC_LINKER_OPTION) {
      MachO::linker_option_command Lo =
          Obj->getLinkerOptionLoadCommand(Command);
      PrintLinkerOptionCommand(Lo, Command.Ptr);
    } else if (Command.C.cmd == MachO::LC_SUB_FRAMEWORK) {
      MachO::sub_framework_command Sf = Obj->getSubFrameworkCommand(Command);
      PrintSubFrameworkCommand(Sf, Command.Ptr);
    } else if (Command.C.cmd == MachO::LC_SUB_UMBRELLA) {
      MachO::sub_umbrella_command Sf = Obj->getSubUmbrellaCommand(Command);
      PrintSubUmbrellaCommand(Sf, Command.Ptr);
    } else if (Command.C.cmd == MachO::LC_SUB_LIBRARY) {
      MachO::sub_library_command Sl = Obj->getSubLibraryCommand(Command);
      PrintSubLibraryCommand(Sl, Command.Ptr);
    } else if (Command.C.cmd == MachO::LC_SUB_CLIENT) {
      MachO::sub_client_command Sc = Obj->getSubClientCommand(Command);
      PrintSubClientCommand(Sc, Command.Ptr);
    } else if (Command.C.cmd == MachO::LC_ROUTINES) {
      MachO::routines_command Rc = Obj->getRoutinesCommand(Command);
      PrintRoutinesCommand(Rc);
    } else if (Command.C.cmd == MachO::LC_ROUTINES_64) {
      MachO::routines_command_64 Rc = Obj->getRoutinesCommand64(Command);
      PrintRoutinesCommand64(Rc);
    } else if (Command.C.cmd == MachO::LC_THREAD ||
               Command.C.cmd == MachO::LC_UNIXTHREAD) {
      MachO::thread_command Tc = Obj->getThreadCommand(Command);
      PrintThreadCommand(Tc, Command.Ptr, Obj->isLittleEndian(), cputype);
    } else if (Command.C.cmd == MachO::LC_LOAD_DYLIB ||
               Command.C.cmd == MachO::LC_ID_DYLIB ||
               Command.C.cmd == MachO::LC_LOAD_WEAK_DYLIB ||
               Command.C.cmd == MachO::LC_REEXPORT_DYLIB ||
               Command.C.cmd == MachO::LC_LAZY_LOAD_DYLIB ||
               Command.C.cmd == MachO::LC_LOAD_UPWARD_DYLIB) {
      MachO::dylib_command Dl = Obj->getDylibIDLoadCommand(Command);
      PrintDylibCommand(Dl, Command.Ptr);
    } else if (Command.C.cmd == MachO::LC_CODE_SIGNATURE ||
               Command.C.cmd == MachO::LC_SEGMENT_SPLIT_INFO ||
               Command.C.cmd == MachO::LC_FUNCTION_STARTS ||
               Command.C.cmd == MachO::LC_DATA_IN_CODE ||
               Command.C.cmd == MachO::LC_DYLIB_CODE_SIGN_DRS ||
               Command.C.cmd == MachO::LC_LINKER_OPTIMIZATION_HINT) {
      MachO::linkedit_data_command Ld =
          Obj->getLinkeditDataLoadCommand(Command);
      PrintLinkEditDataCommand(Ld, Buf.size());
    } else {
      outs() << "      cmd ?(" << format("0x%08" PRIx32, Command.C.cmd)
             << ")\n";
      outs() << "  cmdsize " << Command.C.cmdsize << "\n";
      // TODO: get and print the raw bytes of the load command.
    }
    // TODO: print all the other kinds of load commands.
  }
}

static void PrintMachHeader(const MachOObjectFile *Obj, bool verbose) {
  if (Obj->is64Bit()) {
    MachO::mach_header_64 H_64;
    H_64 = Obj->getHeader64();
    PrintMachHeader(H_64.magic, H_64.cputype, H_64.cpusubtype, H_64.filetype,
                    H_64.ncmds, H_64.sizeofcmds, H_64.flags, verbose);
  } else {
    MachO::mach_header H;
    H = Obj->getHeader();
    PrintMachHeader(H.magic, H.cputype, H.cpusubtype, H.filetype, H.ncmds,
                    H.sizeofcmds, H.flags, verbose);
  }
}

void llvm::printMachOFileHeader(const object::ObjectFile *Obj) {
  const MachOObjectFile *file = dyn_cast<const MachOObjectFile>(Obj);
  PrintMachHeader(file, !NonVerbose);
}

void llvm::printMachOLoadCommands(const object::ObjectFile *Obj) {
  const MachOObjectFile *file = dyn_cast<const MachOObjectFile>(Obj);
  uint32_t filetype = 0;
  uint32_t cputype = 0;
  if (file->is64Bit()) {
    MachO::mach_header_64 H_64;
    H_64 = file->getHeader64();
    filetype = H_64.filetype;
    cputype = H_64.cputype;
  } else {
    MachO::mach_header H;
    H = file->getHeader();
    filetype = H.filetype;
    cputype = H.cputype;
  }
  PrintLoadCommands(file, filetype, cputype, !NonVerbose);
}

// get_dyld_bind_info_symbolname() is used for disassembly and passed an
// address, ReferenceValue, in the Mach-O file and looks in the dyld bind
// information for that address. If the address is found its binding symbol
// name is returned.  If not nullptr is returned.
static const char *get_dyld_bind_info_symbolname(uint64_t ReferenceValue,
                                                 struct DisassembleInfo *info) {
  if (info->bindtable == nullptr) {
    info->bindtable = std::make_unique<SymbolAddressMap>();
    Error Err = Error::success();
    for (const llvm::object::MachOBindEntry &Entry : info->O->bindTable(Err)) {
      uint64_t Address = Entry.address();
      StringRef name = Entry.symbolName();
      if (!name.empty())
        (*info->bindtable)[Address] = name;
    }
    if (Err)
      report_error(std::move(Err), info->O->getFileName());
  }
  auto name = info->bindtable->lookup(ReferenceValue);
  return !name.empty() ? name.data() : nullptr;
}
