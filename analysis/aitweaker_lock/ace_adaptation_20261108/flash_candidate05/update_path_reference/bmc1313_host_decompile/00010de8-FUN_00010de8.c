
void FUN_00010de8(void)

{
  code *pcVar1;
  
  if (((DAT_00010e40 + 0x10dfc) - (DAT_00010e3c + 0x10df8) >> 2) / 2 == 0) {
    return;
  }
  pcVar1 = *(code **)(DAT_00010e44 + 0x10e14 + DAT_00010e48);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
    return;
  }
  return;
}

