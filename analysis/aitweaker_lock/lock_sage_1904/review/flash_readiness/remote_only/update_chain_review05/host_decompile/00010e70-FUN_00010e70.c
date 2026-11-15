
void FUN_00010e70(void)

{
  code *pcVar1;
  
  if (DAT_00010ebc + 0x10e88 == DAT_00010eb8 + 0x10e84) {
    return;
  }
  pcVar1 = *(code **)(DAT_00010ec0 + 0x10e90 + DAT_00010ec4);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
    return;
  }
  return;
}

