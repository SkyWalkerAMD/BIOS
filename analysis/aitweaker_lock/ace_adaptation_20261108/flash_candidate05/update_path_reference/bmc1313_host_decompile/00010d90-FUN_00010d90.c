
void FUN_00010d90(void)

{
  code *pcVar1;
  
  if (DAT_00010ddc + 0x10da8 == DAT_00010dd8 + 0x10da4) {
    return;
  }
  pcVar1 = *(code **)(DAT_00010de0 + 0x10db0 + DAT_00010de4);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
    return;
  }
  return;
}

