
undefined4 FUN_0001397c(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = DAT_00013a50;
  if (param_1 < *(int *)(DAT_00013a50 + 0x10)) {
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00013a5c,DAT_00013a58,DAT_00013a54,param_1);
    iVar3 = iVar3 + param_1 * 4;
    IDBG_LINUXAPP_Runtime_DbgOut
              (0x87,DAT_00013a60,DAT_00013a58,0x2c0,3 - *(int *)(iVar3 + 0x70),0x14);
    iVar2 = *(int *)(iVar3 + 0x70) + 1;
    *(int *)(iVar3 + 0x70) = iVar2;
    if (iVar2 < 4) {
      uVar1 = 0;
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00013a68,DAT_00013a58,DAT_00013a64,0x3c);
      iVar3 = FUN_000133cc(param_1);
      uVar1 = DAT_00013a6c;
      if (iVar3 != 0) goto LAB_00013a34;
      uVar1 = 1;
    }
    return uVar1;
  }
  uVar1 = 700;
LAB_00013a34:
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00013a70,DAT_00013a58,uVar1);
  return 1;
}

