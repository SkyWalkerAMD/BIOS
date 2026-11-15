
void FUN_00010ea4(void)

{
  code *pcVar1;
  
  if (DAT_00010ef0 + 0x10ebc == DAT_00010eec + 0x10eb8) {
    return;
  }
  pcVar1 = *(code **)(DAT_00010ef4 + 0x10ec4 + DAT_00010ef8);
  if (pcVar1 != (code *)0x0) {
    (*pcVar1)();
    return;
  }
  return;
}

