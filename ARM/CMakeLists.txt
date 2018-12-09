include_directories(
  ${LLVM_MAIN_SRC_DIR}/lib/Target/ARM
  ${LLVM_BINARY_DIR}/lib/Target/ARM
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

if(NOT LLVM_MCTOLL_BUILT_STANDALONE)
  set(LLVM_MCTOLL_DEPS intrinsics_gen ARMCommonTableGen)
endif()

add_llvm_library(ARMRaiser
  ARMModuleRaiser.cpp
  ARMFunctionPrototype.cpp
  ARMEliminatePrologEpilog.cpp
  ARMMachineInstructionRaiser.cpp

  DEPENDS
    ${LLVM_MCTOLL_DEPS}
  )
