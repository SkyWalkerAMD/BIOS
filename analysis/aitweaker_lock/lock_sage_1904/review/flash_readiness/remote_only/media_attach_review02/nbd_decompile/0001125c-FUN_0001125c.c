
int FUN_0001125c(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  char *pcVar4;
  sockaddr local_88 [7];
  
  iVar1 = socket(1,DAT_00011470,0);
  if (iVar1 == -1) {
    piVar3 = __errno_location();
    iVar2 = *piVar3;
    pcVar4 = strerror(iVar2);
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00011488,DAT_0001147c,DAT_00011484,iVar2,pcVar4);
  }
  else if (param_1 == 0) {
    memset(local_88[0].sa_data,0,0x6c);
    local_88[0].sa_family = 1;
    strncpy(local_88[0].sa_data + 1,(char *)(*(int *)(DAT_00011474 + param_2 * 4) + 1),0x6a);
    iVar2 = connect(iVar1,local_88,0x6e);
    if (iVar2 == -1) {
      piVar3 = __errno_location();
      iVar2 = *piVar3;
      pcVar4 = strerror(iVar2);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011480,DAT_0001147c,DAT_00011478,iVar2,pcVar4);
      close(iVar1);
      iVar1 = -1;
    }
  }
  else {
    iVar2 = fchmod(iVar1,0x180);
    if (iVar2 == -1) {
      piVar3 = __errno_location();
      iVar1 = *piVar3;
      pcVar4 = strerror(iVar1);
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00011494,DAT_0001147c,0x128,iVar1,pcVar4);
      iVar1 = -1;
    }
    else {
      memset(local_88[0].sa_data,0,0x6c);
      pcVar4 = *(char **)(DAT_00011474 + param_2 * 4);
      local_88[0].sa_family = 1;
      strncpy(local_88[0].sa_data + 1,pcVar4 + 1,0x6a);
      unlink(pcVar4);
      iVar2 = bind(iVar1,local_88,0x6e);
      if (iVar2 == -1) {
        piVar3 = __errno_location();
        iVar1 = *piVar3;
        pcVar4 = strerror(iVar1);
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00011490,DAT_0001147c,DAT_0001148c,iVar1,pcVar4);
        iVar1 = -1;
      }
      else {
        iVar2 = listen(iVar1,1);
        if (iVar2 == -1) {
          piVar3 = __errno_location();
          iVar1 = *piVar3;
          pcVar4 = strerror(iVar1);
          IDBG_LINUXAPP_DbgOut(0x82,DAT_0001149c,DAT_0001147c,DAT_00011498,iVar1,pcVar4);
          iVar1 = -1;
        }
      }
    }
  }
  return iVar1;
}

