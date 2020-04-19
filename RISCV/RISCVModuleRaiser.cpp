#ifdef __cplusplus
extern "C" {
#endif

extern void InitializeRISCV32ModuleRaiser();
extern void InitializeRISCV64ModuleRaiser();

void InitializeRISCVModuleRaiser() {
  InitializeRISCV32ModuleRaiser();
  InitializeRISCV64ModuleRaiser();
}

#ifdef __cplusplus
}
#endif
