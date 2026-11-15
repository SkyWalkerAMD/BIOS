
void * cdrom_start(int param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  void *__arg;
  char *pcVar4;
  undefined4 *puVar5;
  stat sStack_70;
  
  if (param_1 != 0) {
    __arg = (void *)0x0;
    pcVar4 = DAT_0001e500;
    puVar5 = DAT_0001e4fc;
    while (iVar1 = __xstat(3,pcVar4,&sStack_70), iVar1 == 0) {
      __arg = (void *)((int)__arg + 1);
      if (__arg == (void *)0x4) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0001e51c,DAT_0001e514,0x95);
        return (void *)0xffffffff;
      }
      pcVar4 = (char *)*puVar5;
      puVar5 = puVar5 + 1;
    }
    touch(pcVar4);
    pcVar4 = calloc(0x400,1);
    if (pcVar4 == (char *)0x0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001e544,DAT_0001e514,DAT_0001e540);
      FUN_0001dd40(__arg);
      return (void *)0xffffffff;
    }
    uVar2 = snprintf(pcVar4,0x400,DAT_0001e504,param_1,__arg);
    if (uVar2 < 0x400) {
      iVar1 = safe_system(pcVar4);
      if (iVar1 < 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0001e548,DAT_0001e514,0x244,__arg);
      }
      else {
        iVar1 = safe_system(DAT_0001e520);
        if (-1 < iVar1) {
          free(pcVar4);
          iVar1 = DAT_0001e528;
          *(undefined4 *)(DAT_0001e524 + (int)__arg * 4) = 0;
          iVar1 = pthread_create((pthread_t *)(iVar1 + (int)__arg * 4),(pthread_attr_t *)0x0,
                                 DAT_0001e52c,__arg);
          if (iVar1 == 0) {
            return __arg;
          }
          IDBG_LINUXAPP_DbgOut(0x82,DAT_0001e534,DAT_0001e514,DAT_0001e530,__arg);
          return __arg;
        }
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0001e53c,DAT_0001e514,DAT_0001e538,__arg);
      }
    }
    else {
      uVar3 = DAT_0001e508;
      if (-1 < (int)uVar2) {
        uVar3 = DAT_0001e50c;
      }
      IDBG_LINUXAPP_DbgOut(0x84,DAT_0001e518,DAT_0001e514,DAT_0001e510,uVar3);
    }
    FUN_0001dd40(__arg);
    free(pcVar4);
  }
  return (void *)0xffffffff;
}

