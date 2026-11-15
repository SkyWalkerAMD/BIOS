
void FUN_00010ec8(void)

{
  code *pcVar1;
  
  if (((DAT_00010f20 + 0x10edc) - (DAT_00010f1c + 0x10ed8) >> 2) / 2 == 0) {
    return;
  }
  pcVar1 = *(code **)(DAT_00010f24 + 0x10ef4 + DAT_00010f28);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
    return;
  }
  return;
}

