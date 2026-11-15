
undefined4 FUN_00013b20(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00013c24,DAT_00013c20,0x368,param_1);
  iVar1 = DAT_00013c28;
  iVar2 = DAT_00013c28 + param_1 * 4;
  IDBG_LINUXAPP_Runtime_DbgOut
            (0x87,DAT_00013c30,DAT_00013c20,DAT_00013c2c,3 - *(int *)(iVar2 + 0x134),0x14);
  if (*(int *)(iVar1 + 0x130) <= param_1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00013c44,DAT_00013c20,0x36c);
    return 1;
  }
  iVar1 = *(int *)(iVar2 + 0x134) + 1;
  *(int *)(iVar2 + 0x134) = iVar1;
  if (3 < iVar1) {
    uVar3 = 0x3c;
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00013c38,DAT_00013c20,DAT_00013c34,0x3c);
    iVar1 = FUN_00013770(param_1);
    if (iVar1 == 0) {
      FUN_00012e68(param_1);
      return 1;
    }
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00013c40,DAT_00013c20,DAT_00013c3c,uVar3);
    return 1;
  }
  return 0;
}

