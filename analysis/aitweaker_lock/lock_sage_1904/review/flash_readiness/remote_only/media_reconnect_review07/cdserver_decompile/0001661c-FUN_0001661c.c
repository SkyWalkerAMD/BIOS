
undefined4 FUN_0001661c(undefined4 param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000167bc,DAT_000167b8,0x3e);
  iVar6 = 0x20;
  iVar4 = 0;
  do {
    iVar2 = sigwrap_recv(param_1,param_2 + iVar4,iVar6,0);
    iVar4 = iVar4 + iVar2;
    if (iVar2 < 1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000167d4,DAT_000167b8,0x46);
      return 1;
    }
    iVar6 = iVar6 - iVar2;
  } while (iVar4 != 0x20);
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000167c0,DAT_000167b8,0x4e);
  uVar1 = *(uint *)(param_2 + 0xc);
  uVar7 = uVar1;
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000167c4,DAT_000167b8,0x54,uVar1);
  if (uVar1 <= DAT_000167c8) {
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000167cc,DAT_000167b8,0x60,uVar7);
    if (uVar1 != 0) {
      uVar5 = 0;
      uVar7 = uVar1;
      do {
        iVar4 = sigwrap_recv(param_1,param_2 + uVar5 + 0x20,uVar7,0);
        uVar5 = uVar5 + iVar4;
        if (iVar4 < 1) {
          piVar3 = __errno_location();
          IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000167d0,DAT_000167b8,0x68,*piVar3,uVar7);
          return 1;
        }
        uVar7 = uVar7 - iVar4;
      } while (uVar1 != uVar5);
    }
    IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000167dc,DAT_000167b8,0x70,uVar1 + 0x20);
    return 0;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_000167d8,DAT_000167b8,0x57);
  return 1;
}

