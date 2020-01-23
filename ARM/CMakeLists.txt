include_directories(
  ${LLVM_MAIN_SRC_DIR}/lib/Target/ARM
  ${LLVM_BINARY_DIR}/lib/Target/ARM
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/.
  ${CMAKE_CURRENT_SOURCE_DIR}/DAG
)

if(NOT LLVM_MCTOLL_BUILT_STANDALONE)
  set(LLVM_MCTOLL_DEPS intrinsics_gen ARMCommonTableGen)
endif()

add_llvm_library(ARMRaiser
  ARMModuleRaiser.cpp
  ARMFunctionPrototype.cpp
  ARMMIRevising.cpp
  ARMEliminatePrologEpilog.cpp
  ARMCreateJumpTable.cpp
  ARMArgumentRaiser.cpp
  ARMFrameBuilder.cpp
  ARMInstructionSplitting.cpp
  DAG/FunctionRaisingInfo.cpp
  DAG/DAGRaisingInfo.cpp
  DAG/DAGBuilder.cpp
  DAG/InstSelector.cpp
  DAG/IREmitter.cpp
  ARMSelectionDAGISel.cpp
  ARMMachineInstructionRaiser.cpp

  DEPENDS
    ${LLVM_MCTOLL_DEPS}
  )
