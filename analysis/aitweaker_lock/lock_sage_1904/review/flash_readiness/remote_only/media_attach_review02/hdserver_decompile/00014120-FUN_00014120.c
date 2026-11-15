
void FUN_00014120(int param_1,char *param_2)

{
  int iVar1;
  char *pcVar2;
  socklen_t local_114;
  char acStack_110 [64];
  undefined1 auStack_d0 [64];
  sockaddr local_90 [8];
  
  memset(acStack_110,0,0x40);
  local_114 = 0x80;
  iVar1 = getpeername(param_1,local_90,&local_114);
  if (iVar1 == 0) {
    if (local_90[0].sa_family == 2) {
      inet_ntop(2,local_90[0].sa_data + 2,acStack_110,0x40);
    }
    else {
      inet_ntop(10,local_90[0].sa_data + 6,acStack_110,0x40);
      pcVar2 = strchr(acStack_110,0x3a);
      if ((pcVar2 != (char *)0x0) && (pcVar2 = strchr(acStack_110,0x2e), pcVar2 != (char *)0x0)) {
        __isoc99_sscanf(acStack_110,DAT_00014220,auStack_d0);
        snprintf(acStack_110,0x40,DAT_00014224,auStack_d0);
      }
    }
    memset(param_2,0,0x40);
    snprintf(param_2,0x40,DAT_00014224,acStack_110);
    return;
  }
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00014230,DAT_0001422c,DAT_00014228);
  return;
}

