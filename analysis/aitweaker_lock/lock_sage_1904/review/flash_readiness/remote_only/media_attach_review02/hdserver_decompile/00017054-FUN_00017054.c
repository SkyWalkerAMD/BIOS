
undefined4 FUN_00017054(undefined4 param_1,int param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_0001723c,DAT_00017240,0x4c);
  iVar7 = 0x20;
  iVar5 = 0;
  do {
    iVar2 = FUN_00016fd0(param_1,param_3);
    if (iVar2 < 1) {
      uVar4 = 0x52;
      goto LAB_00017190;
    }
    iVar2 = sigwrap_recv(param_1,param_2 + iVar5,iVar7,0);
    iVar5 = iVar5 + iVar2;
    if (iVar2 < 1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00017258,DAT_00017240,0x5a);
      return 1;
    }
    iVar7 = iVar7 - iVar2;
  } while (iVar5 != 0x20);
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00017244,DAT_00017240,0x62);
  uVar1 = *(uint *)(param_2 + 0xc);
  uVar8 = uVar1;
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00017248,DAT_00017240,0x68,uVar1);
  if (DAT_0001724c < uVar1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_0001725c,DAT_00017240,0x6b);
    return 1;
  }
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00017250,DAT_00017240,0x73,uVar8);
  if (uVar1 != 0) {
    uVar6 = 0;
    uVar8 = uVar1;
    do {
      iVar5 = FUN_00016fd0(param_1,param_3);
      if (iVar5 < 1) {
        uVar4 = 0x79;
LAB_00017190:
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00017254,DAT_00017240,uVar4);
        return 1;
      }
      iVar5 = sigwrap_recv(param_1,param_2 + uVar6 + 0x20,uVar8,0);
      uVar6 = uVar6 + iVar5;
      if (iVar5 < 1) {
        piVar3 = __errno_location();
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00017264,DAT_00017240,0x81,*piVar3,uVar8);
        return 1;
      }
      uVar8 = uVar8 - iVar5;
    } while (uVar1 != uVar6);
  }
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00017260,DAT_00017240,0x89,uVar1 + 0x20);
  return 0;
}

