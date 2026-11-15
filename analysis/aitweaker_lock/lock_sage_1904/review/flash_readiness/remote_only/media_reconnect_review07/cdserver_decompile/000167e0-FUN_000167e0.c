
undefined4 FUN_000167e0(undefined4 param_1,int param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000169ec,DAT_000169f0,0x90);
  iVar7 = 0x20;
  iVar5 = 0;
  do {
    iVar2 = FUN_00016598(param_1,param_3);
    if (iVar2 < 1) {
      uVar4 = 0x96;
      goto LAB_00016964;
    }
    iVar2 = sigwrap_recv(param_1,param_2 + iVar5,iVar7,0);
    iVar5 = iVar5 + iVar2;
    if ((iVar2 < 0) || ((iVar2 == 0 && (piVar3 = __errno_location(), *piVar3 == 2)))) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00016a04,DAT_000169f0,0x9e);
      return 1;
    }
    iVar7 = iVar7 - iVar2;
  } while (iVar5 != 0x20);
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000169f4,DAT_000169f0,0xa6);
  uVar1 = *(uint *)(param_2 + 0xc);
  uVar8 = uVar1;
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000169f8,DAT_000169f0,0xac,uVar1);
  if (DAT_000169fc < uVar1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00016a0c,DAT_000169f0,0xaf);
    return 1;
  }
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00016a00,DAT_000169f0,0xb8,uVar8);
  if (uVar1 != 0) {
    uVar6 = 0;
    uVar8 = uVar1;
    do {
      iVar5 = FUN_00016598(param_1,param_3);
      if (iVar5 < 1) {
        uVar4 = 0xbe;
LAB_00016964:
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00016a08,DAT_000169f0,uVar4);
        return 1;
      }
      iVar5 = sigwrap_recv(param_1,param_2 + uVar6 + 0x20,uVar8,0);
      uVar6 = uVar6 + iVar5;
      if (iVar5 < 0) {
        piVar3 = __errno_location();
        iVar7 = *piVar3;
LAB_000169a8:
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00016a10,DAT_000169f0,0xc6,iVar7,uVar8);
        return 1;
      }
      if (iVar5 == 0) {
        piVar3 = __errno_location();
        iVar7 = *piVar3;
        if (iVar7 == 2) goto LAB_000169a8;
      }
      uVar8 = uVar8 - iVar5;
    } while (uVar1 != uVar6);
  }
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00016a14,DAT_000169f0,0xce,uVar1 + 0x20);
  return 0;
}

