
void * FUN_00017dec(int param_1)

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
    pcVar4 = DAT_00018058;
    puVar5 = DAT_00018054;
    while (iVar1 = __xstat(3,pcVar4,&sStack_70), iVar1 == 0) {
      __arg = (void *)((int)__arg + 1);
      if (__arg == (void *)0x4) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_00018070,DAT_00018068,0xb3);
        return (void *)0xffffffff;
      }
      pcVar4 = (char *)*puVar5;
      puVar5 = puVar5 + 1;
    }
    touch(pcVar4);
    pcVar4 = calloc(0x400,1);
    puVar5 = DAT_0001805c;
    if (pcVar4 == (char *)0x0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001809c,DAT_00018068,0x250);
      FUN_000177c8(__arg);
      return (void *)0xffffffff;
    }
    snprintf(pcVar4,0x400,DAT_00018060,*DAT_0001805c,__arg);
    iVar1 = safe_system(pcVar4);
    if (iVar1 < 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_0001806c,DAT_00018068,DAT_00018064,__arg);
    }
    else {
      memset(pcVar4,0,0x400);
      snprintf(pcVar4,0x400,DAT_00018074,puVar5[1],__arg);
      iVar1 = safe_system(pcVar4);
      if (iVar1 < 0) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_0001806c,DAT_00018068,DAT_000180a0,__arg);
      }
      else {
        memset(pcVar4,0,0x400);
        uVar2 = snprintf(pcVar4,0x400,DAT_00018078,param_1,__arg);
        if (uVar2 < 0x400) {
          iVar1 = safe_system(pcVar4);
          if (iVar1 < 0) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_000180b0,DAT_00018068,DAT_000180ac,__arg);
          }
          else {
            iVar1 = safe_system(DAT_0001808c);
            if (-1 < iVar1) {
              free(pcVar4);
              iVar1 = DAT_00018090 + 0x10;
              *(undefined4 *)(DAT_00018090 + (int)__arg * 4) = 0;
              iVar1 = pthread_create((pthread_t *)(iVar1 + (int)__arg * 4),(pthread_attr_t *)0x0,
                                     DAT_00018094,__arg);
              if (iVar1 == 0) {
                return __arg;
              }
              IDBG_LINUXAPP_DbgOut(0x82,DAT_00018098,DAT_00018068,0x288,__arg);
              return __arg;
            }
            IDBG_LINUXAPP_DbgOut(0x82,DAT_000180a8,DAT_00018068,DAT_000180a4,__arg);
          }
        }
        else {
          uVar3 = DAT_0001807c;
          if (-1 < (int)uVar2) {
            uVar3 = DAT_00018080;
          }
          IDBG_LINUXAPP_DbgOut(0x84,DAT_00018088,DAT_00018068,DAT_00018084,uVar3);
        }
      }
    }
    FUN_000177c8(__arg);
    free(pcVar4);
  }
  return (void *)0xffffffff;
}

