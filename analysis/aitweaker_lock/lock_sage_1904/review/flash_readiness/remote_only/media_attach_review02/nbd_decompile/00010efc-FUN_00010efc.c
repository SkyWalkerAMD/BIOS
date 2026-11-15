
void FUN_00010efc(void)

{
  code *pcVar1;
  
  if (((DAT_00010f54 + 0x10f10) - (DAT_00010f50 + 0x10f0c) >> 2) / 2 == 0) {
    return;
  }
  pcVar1 = *(code **)(DAT_00010f58 + 0x10f28 + DAT_00010f5c);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
    return;
  }
  return;
}

