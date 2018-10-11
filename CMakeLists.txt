set(LLVM_MCTOLL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(LLVM_MCTOLL_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})

llvm_map_components_to_libnames(llvm_libs
  ${LLVM_TARGETS_TO_BUILD}
  DebugInfoDWARF
  DebugInfoPDB
  Symbolize
)

set(LLVM_MCTOLL_LIB_DEPS ${llvm_libs})

if(LLVM_TARGETS_TO_BUILD MATCHES "X86")
  add_subdirectory(X86)
  list(APPEND LLVM_MCTOLL_LIB_DEPS X86Raiser)
endif()

if(LLVM_TARGETS_TO_BUILD MATCHES "ARM")
  add_subdirectory(ARM)
  list(APPEND LLVM_MCTOLL_LIB_DEPS ARMRaiser)
endif()

add_subdirectory(test)

add_llvm_tool(llvm-mctoll
  llvm-mctoll.cpp
  COFFDump.cpp
  ELFDump.cpp
  ExternalFunctions.cpp
  MachODump.cpp
  WasmDump.cpp
  MachineFunctionRaiser.cpp
  MCInstOrData.cpp
  MCInstRaiser.cpp
  EmitRaisedOutputPass.cpp
)

# Link against LLVM libraries and target-specific Raiser libraries
target_link_libraries(llvm-mctoll PRIVATE ${LLVM_MCTOLL_LIB_DEPS})

if(HAVE_LIBXAR)
  message(STATUS "Linking xar")
  target_link_libraries(llvm-mctoll PRIVATE ${XAR_LIB})
endif()

