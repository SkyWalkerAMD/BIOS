
undefined4 FUN_00013838(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_000138a8;
  if (param_1 < *(int *)(DAT_000138a8 + 0x130)) {
    if (0 < *(int *)(DAT_000138a8 + param_1 * 4 + 0x134)) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000138b4,DAT_000138b0,DAT_000138ac);
    }
    *(undefined4 *)(iVar1 + param_1 * 4 + 0x134) = 0;
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_000138bc,DAT_000138b0,DAT_000138b8);
  return 1;
}

