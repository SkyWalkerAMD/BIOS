
undefined4 FUN_00016df0(uint param_1)

{
  int __oflag;
  int iVar1;
  char *__s;
  char *__s_00;
  int __fd;
  ssize_t sVar2;
  int iVar3;
  undefined1 auStack_420 [1028];
  
  memset(auStack_420,0,0x400);
  if (3 < param_1) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00016f68,DAT_00016f64,0x41,param_1);
    return 0;
  }
  sleep(3);
  __s_00 = calloc(0x400,1);
  if (__s_00 == (char *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00016f6c,DAT_00016f64,0x4b);
    return 0;
  }
  snprintf(__s_00,0x400,DAT_00016f54,param_1);
  __fd = open(__s_00,DAT_00016f58);
  __s = DAT_00016f60;
  iVar1 = DAT_00016f5c;
  __oflag = DAT_00016f58;
  iVar3 = *(int *)(DAT_00016f5c + param_1 * 4);
  while (iVar3 == 0) {
    memset(auStack_420,0,0x400);
    sVar2 = read(__fd,auStack_420,0x400);
    if (sVar2 == -1) {
      perror(__s);
    }
    else if (sVar2 == 0) {
      *(undefined4 *)(iVar1 + param_1 * 4) = 1;
    }
    else {
      close(__fd);
      __fd = open(__s_00,__oflag);
    }
    sleep(3);
    iVar3 = *(int *)(iVar1 + param_1 * 4);
  }
  free(__s_00);
  if (__fd != -1) {
    close(__fd);
  }
  return 0;
}

