if(NOT (LLVM_TARGETS_TO_BUILD MATCHES "X86" OR LLVM_TARGETS_TO_BUILD MATCHES "ARM" OR LLVM_TARGETS_TO_BUILD MATCHES "RISCV"))
  return()
endif()

set(LLVM_MCTOLL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(LLVM_MCTOLL_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})

llvm_map_components_to_libnames(llvm_libs
  ${LLVM_TARGETS_TO_BUILD}
  Core
  BitWriter
  CodeGen
  DebugInfoDWARF
  DebugInfoPDB
  Demangle
  MC
  MCDisassembler
  Object
  Symbolize
  Support
)

set(LLVM_MCTOLL_LIB_DEPS ${llvm_libs})
set(LLVM_MCTOLL_SUPPORTED_ARCHS "")

if(LLVM_TARGETS_TO_BUILD MATCHES "X86")
  set(LLVM_MCTOLL_SUPPORTED_ARCHS
    "${LLVM_MCTOLL_SUPPORTED_ARCHS}MODULE_RAISER(X86)\n")
  add_subdirectory(X86)
  list(APPEND LLVM_MCTOLL_LIB_DEPS X86Raiser)
endif()

if(LLVM_TARGETS_TO_BUILD MATCHES "RISCV")
  set(LLVM_MCTOLL_SUPPORTED_ARCHS
    "${LLVM_MCTOLL_SUPPORTED_ARCHS}MODULE_RAISER(RISCV)\n")
  add_subdirectory(RISCV)
  list(APPEND LLVM_MCTOLL_LIB_DEPS RISCVRaiser)
endif()

if(LLVM_TARGETS_TO_BUILD MATCHES "ARM")
  set(LLVM_MCTOLL_SUPPORTED_ARCHS
    "${LLVM_MCTOLL_SUPPORTED_ARCHS}MODULE_RAISER(ARM)\n")
  add_subdirectory(ARM)
  list(APPEND LLVM_MCTOLL_LIB_DEPS ARMRaiser)
endif()

configure_file(
  ${LLVM_MCTOLL_SOURCE_DIR}/Raisers.def.in
  ${LLVM_INCLUDE_DIR}/Raisers.def
  )

add_subdirectory(test)

add_llvm_tool(llvm-mctoll
  llvm-mctoll.cpp
  COFFDump.cpp
  ELFDump.cpp
  ExternalFunctions.cpp
  FunctionFilter.cpp
  MachODump.cpp
  MachineFunctionRaiser.cpp
  MCInstOrData.cpp
  MCInstRaiser.cpp
  EmitRaisedOutputPass.cpp
  RuntimeFunction.cpp
)

# Link against LLVM libraries and target-specific Raiser libraries
target_link_libraries(llvm-mctoll PRIVATE ${LLVM_MCTOLL_LIB_DEPS})

if(HAVE_LIBXAR)
  message(STATUS "Linking xar")
  target_link_libraries(llvm-mctoll PRIVATE ${XAR_LIB})
endif()

