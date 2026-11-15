
undefined4 nbd_server(int param_1)

{
  uint *puVar1;
  int iVar2;
  undefined4 uVar3;
  int *piVar4;
  char *pcVar5;
  
  iVar2 = FUN_0001125c(1,*(undefined4 *)(param_1 + 0x14));
  *(char *)(param_1 + 0xc) = (char)iVar2;
  *(char *)(param_1 + 0xd) = (char)((uint)iVar2 >> 8);
  *(char *)(param_1 + 0xe) = (char)((uint)iVar2 >> 0x10);
  *(char *)(param_1 + 0xf) = (char)((uint)iVar2 >> 0x18);
  puVar1 = DAT_00011614;
  if (iVar2 == -1) {
    uVar3 = 0xffffffff;
    if ((*DAT_00011614 & 1) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011630,DAT_0001161c,DAT_0001162c);
    }
  }
  else {
    if ((*DAT_00011614 & 1) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011628,DAT_0001161c,DAT_00011624,iVar2);
      iVar2 = *(int *)(param_1 + 0xc);
    }
    iVar2 = accept(iVar2,(sockaddr *)0x0,(socklen_t *)0x0);
    *(char *)(param_1 + 8) = (char)iVar2;
    *(char *)(param_1 + 9) = (char)((uint)iVar2 >> 8);
    *(char *)(param_1 + 10) = (char)((uint)iVar2 >> 0x10);
    *(char *)(param_1 + 0xb) = (char)((uint)iVar2 >> 0x18);
    if (iVar2 == -1) {
      piVar4 = __errno_location();
      iVar2 = *piVar4;
      pcVar5 = strerror(iVar2);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011638,DAT_0001161c,DAT_00011634,iVar2,pcVar5);
      uVar3 = 0xffffffff;
    }
    else {
      uVar3 = 0;
      if ((*puVar1 & 1) != 0) {
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011620,DAT_0001161c,DAT_00011618,iVar2);
        return 0;
      }
    }
  }
  return uVar3;
}

