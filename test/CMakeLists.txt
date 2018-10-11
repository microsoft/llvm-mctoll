# Test runner infrastructure for LLVM-mctoll. This configures the LLVM-mctoll
# test trees for use by Lit, and delegates to LLVM's lit test handlers.

if (CMAKE_CFG_INTDIR STREQUAL ".")
  set(LLVM_BUILD_MODE ".")
else ()
  set(LLVM_BUILD_MODE "%(build_mode)s")
endif ()

string(REPLACE ${CMAKE_CFG_INTDIR} ${LLVM_BUILD_MODE} LLVM_MCTOLL_TOOLS_DIR ${LLVM_RUNTIME_OUTPUT_INTDIR})

set(LLVM_MCTEST_DEPENDS llvm-mctoll)
if (NOT LLVM_MCTOLL_BUILT_STANDALONE)
  list(APPEND
       LLVM_MCTEST_DEPENDS
       clang count FileCheck llc lli llvm-as llvm-cat llvm-dis llvm-mc not opt)
endif()

configure_lit_site_cfg(
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg
)

add_lit_testsuite(check-mctoll "Running the llvm-mctoll tests"
  ${CMAKE_CURRENT_BINARY_DIR}
  PARAMS llvm_site_config=${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg
         llvm_unit_site_config=${CMAKE_CURRENT_BINARY_DIR}/Unit/lit.site.cfg
  DEPENDS ${LLVM_MCTEST_DEPENDS}
)

set_target_properties(check-mctoll PROPERTIES FOLDER "llvm-mctoll tests")
