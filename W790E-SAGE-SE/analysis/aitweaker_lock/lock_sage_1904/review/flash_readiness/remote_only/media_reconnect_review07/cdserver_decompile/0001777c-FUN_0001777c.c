
undefined4 FUN_0001777c(uint param_1)

{
  int iVar1;
  char *__s;
  
  iVar1 = pthread_cancel(*(pthread_t *)(DAT_00017884 + param_1 * 4));
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00017894,DAT_00017890,0x278,param_1);
  }
  *(undefined4 *)(DAT_00017888 + param_1 * 4) = 0;
  __s = calloc(0x400,1);
  snprintf(__s,0x400,DAT_0001788c,param_1);
  iVar1 = safe_system(__s);
  free(__s);
  if (iVar1 != 0) {
    iVar1 = FUN_00017950(DAT_00017898);
    if (iVar1 == -1) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000178a0,DAT_00017890,DAT_0001789c);
    }
    else {
      iVar1 = FUN_00017e10(param_1 & 0xff);
      if (iVar1 == -1) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000178a8,DAT_00017890,DAT_000178a4,param_1);
      }
      FUN_00017a04();
    }
  }
  if (3 < (int)param_1) {
    return 0;
  }
  FUN_00016f70(param_1);
  return 0;
}

