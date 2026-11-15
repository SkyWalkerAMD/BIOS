
int FUN_00018290(int param_1)

{
  int *piVar1;
  char *pcVar2;
  int iVar3;
  
  piVar1 = DAT_00018330;
  if (param_1 != 0) {
    iVar3 = *DAT_00018330;
    if (iVar3 < 0) {
      iVar3 = sigwrap_open(param_1,DAT_00018334);
      *piVar1 = iVar3;
      if (iVar3 < 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0001833c,DAT_00018338,0xa6,param_1);
        piVar1 = __errno_location();
        iVar3 = *piVar1;
        pcVar2 = strerror(iVar3);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00018340,DAT_00018338,0xa7,iVar3,pcVar2);
        iVar3 = -1;
      }
    }
    return iVar3;
  }
  return -1;
}

