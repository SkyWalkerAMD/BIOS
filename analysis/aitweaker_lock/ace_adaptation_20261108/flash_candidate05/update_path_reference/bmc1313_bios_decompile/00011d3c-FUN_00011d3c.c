
void FUN_00011d3c(void)

{
  code *pcVar1;
  
  if (DAT_00011d88 + 0x11d54 == DAT_00011d84 + 0x11d50) {
    return;
  }
  pcVar1 = *(code **)(DAT_00011d8c + 0x11d5c + DAT_00011d90);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
    return;
  }
  return;
}

