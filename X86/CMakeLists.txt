include_directories(
  ${LLVM_MAIN_SRC_DIR}/lib/Target/X86
  ${LLVM_BINARY_DIR}/lib/Target/X86
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

if(NOT LLVM_MCTOLL_BUILT_STANDALONE)
  set(LLVM_MCTOLL_DEPS intrinsics_gen X86CommonTableGen)
endif()

add_llvm_library(X86Raiser
  X86ModuleRaiser.cpp
  X86MachineInstructionRaiser.cpp

  DEPENDS
    ${LLVM_MCTOLL_DEPS}
  )
