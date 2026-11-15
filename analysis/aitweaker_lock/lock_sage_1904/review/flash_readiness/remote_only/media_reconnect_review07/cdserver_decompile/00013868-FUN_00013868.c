
undefined4 FUN_00013868(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_000138d8;
  if (param_1 < *(int *)(DAT_000138d8 + 0x10)) {
    if (0 < *(int *)(DAT_000138d8 + param_1 * 4 + 0x70)) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000138e0,DAT_000138dc,0x2e0);
    }
    *(undefined4 *)(iVar1 + param_1 * 4 + 0x70) = 0;
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_000138e8,DAT_000138dc,DAT_000138e4);
  return 1;
}

