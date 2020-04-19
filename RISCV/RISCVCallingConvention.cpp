#include "RISCVCallingConvention.h"


using namespace RISCV;

void
RISCVCallingConvention::addIntRegs8() {
  addIntArgRegister(X10);
  addIntArgRegister(X11);
  addIntArgRegister(X12);
  addIntArgRegister(X13);
  addIntArgRegister(X14);
  addIntArgRegister(X15);
  addIntArgRegister(X16);
  addIntArgRegister(X17);
}

void
RISCVCallingConvention::addFloatRegsSingle() {
  addFloatArgRegister(F10_F);
  addFloatArgRegister(F11_F);
  addFloatArgRegister(F12_F);
  addFloatArgRegister(F13_F);
  addFloatArgRegister(F14_F);
  addFloatArgRegister(F15_F);
  addFloatArgRegister(F16_F);
  addFloatArgRegister(F17_F);
}

void
RISCVCallingConvention::addFloatRegsDouble() {
  addFloatArgRegister(F10_D);
  addFloatArgRegister(F11_D);
  addFloatArgRegister(F12_D);
  addFloatArgRegister(F13_D);
  addFloatArgRegister(F14_D);
  addFloatArgRegister(F15_D);
  addFloatArgRegister(F16_D);
  addFloatArgRegister(F17_D);
}

RISCVILP32::RISCVILP32() : RISCVCallingConventionI32() {
  RISCVCallingConvention::addIntRegs8();
}

RISCVILP32F::RISCVILP32F() : RISCVCallingConventionI32(){
  RISCVCallingConvention::addIntRegs8();
  RISCVCallingConvention::addFloatRegsSingle();
}

RISCVILP32D::RISCVILP32D() : RISCVCallingConventionI32() {
  RISCVCallingConvention::addIntRegs8();
  RISCVCallingConvention::addFloatRegsDouble();
}

RISCVILP32E::RISCVILP32E() : RISCVCallingConventionI32() {
  addIntArgRegister(X10);
  addIntArgRegister(X11);
  addIntArgRegister(X12);
  addIntArgRegister(X13);
  addIntArgRegister(X14);
  addIntArgRegister(X15);
}

RISCVLP64::RISCVLP64() : RISCVCallingConventionI64() {
  RISCVCallingConvention::addIntRegs8();
}

RISCVLP64F::RISCVLP64F() : RISCVCallingConventionI64(){
  RISCVCallingConvention::addIntRegs8();
  RISCVCallingConvention::addFloatRegsSingle();
}

RISCVLP64D::RISCVLP64D() : RISCVCallingConventionI64() {
  RISCVCallingConvention::addIntRegs8();
  RISCVCallingConvention::addFloatRegsDouble();
}
