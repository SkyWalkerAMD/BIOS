
undefined4 FUN_00011a3c(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  FILE *__stream;
  int iVar1;
  int *piVar2;
  char *pcVar3;
  undefined4 uVar4;
  char acStack_218 [516];
  
  memset(acStack_218,0,0x200);
  if (param_2 == 1) {
    if ((*DAT_00011bc8 & 2) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011be8,DAT_00011bdc,DAT_00011be4,param_3,param_4);
    }
    snprintf(acStack_218,0x200,DAT_00011bd8,*(undefined4 *)(param_1 + 0x14));
  }
  else {
    if ((*DAT_00011bc8 & 2) != 0) {
      IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00011be0,DAT_00011bdc,0x1c0,param_3,param_4);
    }
    snprintf(acStack_218,0x200,DAT_00011bcc,*(undefined4 *)(param_1 + 0x14));
  }
  __stream = fopen64(acStack_218,DAT_00011bd0);
  if (__stream == (FILE *)0x0) {
    piVar2 = __errno_location();
    iVar1 = *piVar2;
    uVar4 = 0xffffffff;
    pcVar3 = strerror(iVar1);
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011bf4,DAT_00011bdc,0x1dc,iVar1,pcVar3);
  }
  else {
    iVar1 = fprintf(__stream,DAT_00011bd4,param_3,param_4);
    if (iVar1 < 0) {
      piVar2 = __errno_location();
      iVar1 = *piVar2;
      uVar4 = 0xffffffff;
      pcVar3 = strerror(iVar1);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011bf0,DAT_00011bdc,DAT_00011bec,iVar1,pcVar3);
    }
    else {
      uVar4 = 0;
    }
    fclose(__stream);
  }
  return uVar4;
}

