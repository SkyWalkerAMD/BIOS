
undefined4 FUN_00017648(uint param_1)

{
  undefined4 uVar1;
  int iVar2;
  char *__s;
  char *__s_00;
  int iVar3;
  int iVar4;
  undefined1 auStack_420 [1028];
  
  memset(auStack_420,0,0x400);
  if (3 < param_1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000177c0,DAT_000177bc,0x5f,param_1);
    return 0;
  }
  sleep(3);
  __s_00 = calloc(0x400,1);
  if (__s_00 == (char *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000177c4,DAT_000177bc,0x69);
    return 0;
  }
  snprintf(__s_00,0x400,DAT_000177ac,param_1);
  iVar3 = sigwrap_open(__s_00,DAT_000177b0);
  __s = DAT_000177b8;
  iVar2 = DAT_000177b4;
  uVar1 = DAT_000177b0;
  iVar4 = *(int *)(DAT_000177b4 + param_1 * 4);
  while (iVar4 == 0) {
    memset(auStack_420,0,0x400);
    iVar4 = sigwrap_read(iVar3,auStack_420,0x400);
    if (iVar4 == -1) {
      perror(__s);
    }
    else if (iVar4 == 0) {
      *(undefined4 *)(iVar2 + param_1 * 4) = 1;
    }
    else {
      sigwrap_close(iVar3);
      iVar3 = sigwrap_open(__s_00,uVar1);
    }
    sleep(3);
    iVar4 = *(int *)(iVar2 + param_1 * 4);
  }
  free(__s_00);
  if (iVar3 != -1) {
    sigwrap_close(iVar3);
  }
  return 0;
}

