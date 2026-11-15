
undefined4 FUN_000180b4(uint param_1)

{
  int iVar1;
  char *__s;
  int iVar2;
  
  iVar2 = DAT_000181c4;
  iVar1 = pthread_cancel(*(pthread_t *)(DAT_000181c4 + param_1 * 4 + 0x10));
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000181d4,DAT_000181d0,DAT_000181cc,param_1);
  }
  *(undefined4 *)(iVar2 + param_1 * 4 + 0x10) = 0;
  __s = calloc(0x400,1);
  snprintf(__s,0x400,DAT_000181c8,param_1);
  iVar2 = safe_system(__s);
  free(__s);
  if (iVar2 != 0) {
    iVar2 = FUN_00018290(DAT_000181d8);
    if (iVar2 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000181e0,DAT_000181d0,DAT_000181dc);
    }
    else {
      iVar2 = FUN_000185bc(param_1 & 0xff);
      if (iVar2 == -1) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000181e8,DAT_000181d0,DAT_000181e4,param_1);
      }
      FUN_00018344();
    }
  }
  if (3 < (int)param_1) {
    return 0;
  }
  FUN_000177c8(param_1);
  return 0;
}

