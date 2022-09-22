if(NOT (LLVM_TARGETS_TO_BUILD MATCHES "X86" OR LLVM_TARGETS_TO_BUILD MATCHES "ARM" OR LLVM_TARGETS_TO_BUILD MATCHES "RISCV"))
  return()
endif()

if (MCTOLL_CLANG_TIDY)
 message(STATUS "Enabled clang-tidy checks for llvm-mctoll source files")
 set(CMAKE_CXX_CLANG_TIDY "clang-tidy")
endif()
 
set(LLVM_MCTOLL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(LLVM_MCTOLL_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})

set(LLVM_LINK_COMPONENTS
  BitWriter
  CodeGen
  Core
  BinaryFormat
  DebugInfoDWARF
  DebugInfoPDB
  Demangle
  MC
  MCDisassembler
  Object
  Option
  Support
  Symbolize
  ARM
  X86
  )

add_subdirectory(Raiser)

set(LLVM_MCTOLL_LIB_DEPS ${llvm_libs} mctollRaiser)
set(LLVM_MCTOLL_SUPPORTED_ARCHS "")

if(LLVM_TARGETS_TO_BUILD MATCHES "X86")
  set(LLVM_MCTOLL_SUPPORTED_ARCHS
    "${LLVM_MCTOLL_SUPPORTED_ARCHS}MODULE_RAISER(X86)\n")
  add_subdirectory(X86)
  list(APPEND LLVM_MCTOLL_LIB_DEPS mctollX86Raiser)
endif()

if(LLVM_TARGETS_TO_BUILD MATCHES "RISCV")
  set(LLVM_MCTOLL_SUPPORTED_ARCHS
    "${LLVM_MCTOLL_SUPPORTED_ARCHS}MODULE_RAISER(RISCV)\n")
  add_subdirectory(RISCV)
  list(APPEND LLVM_MCTOLL_LIB_DEPS mctollRISCVRaiser)
endif()

if(LLVM_TARGETS_TO_BUILD MATCHES "ARM")
  set(LLVM_MCTOLL_SUPPORTED_ARCHS
    "${LLVM_MCTOLL_SUPPORTED_ARCHS}MODULE_RAISER(ARM)\n")
  add_subdirectory(ARM)
  list(APPEND LLVM_MCTOLL_LIB_DEPS mctollARMRaiser)
endif()

configure_file(
  ${LLVM_MCTOLL_SOURCE_DIR}/Raisers.def.in
  ${LLVM_INCLUDE_DIR}/Raisers.def
  )

set(LLVM_TARGET_DEFINITIONS Opts.td)
tablegen(LLVM Opts.inc -gen-opt-parser-defs)
add_public_tablegen_target(MctoolOptsTableGen)

add_subdirectory(test)

add_llvm_tool(llvm-mctoll
  llvm-mctoll.cpp
  COFFDump.cpp
  MachODump.cpp
  EmitRaisedOutputPass.cpp
  PeepholeOptimizationPass.cpp
  DEPENDS
  MctoolOptsTableGen
)

# Link against LLVM libraries and target-specific Raiser libraries
target_link_libraries(llvm-mctoll PRIVATE ${LLVM_MCTOLL_LIB_DEPS})

if(HAVE_LIBXAR)
  message(STATUS "Linking xar")
  target_link_libraries(llvm-mctoll PRIVATE ${XAR_LIB})
endif()

