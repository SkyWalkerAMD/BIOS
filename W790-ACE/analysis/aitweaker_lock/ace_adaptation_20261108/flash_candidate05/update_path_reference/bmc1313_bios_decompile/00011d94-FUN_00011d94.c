
void FUN_00011d94(void)

{
  code *pcVar1;
  
  if (((DAT_00011dec + 0x11da8) - (DAT_00011de8 + 0x11da4) >> 2) / 2 == 0) {
    return;
  }
  pcVar1 = *(code **)(DAT_00011df0 + 0x11dc0 + DAT_00011df4);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
    return;
  }
  return;
}

