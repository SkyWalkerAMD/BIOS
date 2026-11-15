
uint FUN_180005b1c(longlong param_1)

{
  uint uVar1;
  ulong *puVar2;
  
  if (param_1 == 0) {
    puVar2 = __doserrno();
    *puVar2 = 0x16;
    FUN_180008430();
    uVar1 = 0;
  }
  else {
    uVar1 = *(uint *)(param_1 + 0x18) & 0x10;
  }
  return uVar1;
}

