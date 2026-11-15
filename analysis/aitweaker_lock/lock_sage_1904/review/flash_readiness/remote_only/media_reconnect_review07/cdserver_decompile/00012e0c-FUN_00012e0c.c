
undefined4 FUN_00012e0c(void)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int *piVar6;
  
  uVar3 = DAT_00012e78;
  uVar2 = DAT_00012e74;
  uVar1 = DAT_00012e70;
  uVar4 = 1;
  iVar5 = 0;
  piVar6 = DAT_00012e6c;
  do {
    if (*piVar6 == 0x1b) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,uVar3,uVar2,uVar1,iVar5);
      uVar4 = 0;
    }
    iVar5 = iVar5 + 1;
    piVar6 = piVar6 + 1;
  } while (iVar5 != 4);
  return uVar4;
}

