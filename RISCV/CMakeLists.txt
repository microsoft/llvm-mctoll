include_directories(
  ${LLVM_MAIN_SRC_DIR}/lib/Target/RISCV
  ${LLVM_BINARY_DIR}/lib/Target/RISCV
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../Raiser
)

if(NOT LLVM_MCTOLL_BUILT_STANDALONE)
  set(LLVM_MCTOLL_DEPS intrinsics_gen RISCVCommonTableGen)
endif()

add_llvm_component_library(mctollRISCVRaiser
  RISCVModuleRaiser.cpp
  RISCV32ModuleRaiser.cpp
  RISCV32MachineInstructionRaiser.cpp
  RISCV64MachineInstructionRaiser.cpp
  RISCV64ModuleRaiser.cpp
  RISCVCallingConvention.cpp

  DEPENDS
    ${LLVM_MCTOLL_DEPS}
  )

target_link_libraries(mctollRISCVRaiser PRIVATE mctollRaiser)
