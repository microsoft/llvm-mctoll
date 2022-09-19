
#include "RISCVModuleRaiser.h"

void registerRISCVModuleRaiser() {
  registerRISCV32ModuleRaiser();
  registerRISCV64ModuleRaiser();
}
