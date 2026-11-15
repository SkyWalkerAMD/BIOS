
uint FUN_000183f4(char *param_1)

{
  char *__s;
  uint uVar1;
  int iVar2;
  int *piVar3;
  char *pcVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  pthread_mutex_t *__mutex;
  
  __s = malloc(0x400);
  if (__s == (char *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_000185b8,DAT_000185a4,0x4e);
  }
  else {
    if ((param_1 != (char *)0x0) && (*param_1 != '\0')) {
      uVar1 = FUN_0001836c(0);
      uVar1 = uVar1 & 0xff;
      if (3 < uVar1) {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000185ac,DAT_000185a4,0x60,uVar1);
        free(__s);
        return 0xffffffff;
      }
      memset(__s,0,0x400);
      iVar2 = snprintf(__s,0x400,DAT_00018598,param_1,uVar1);
      __mutex = DAT_000185a0;
      if (iVar2 < 0x400) {
        if (iVar2 < 0) {
          piVar3 = __errno_location();
          __mutex = DAT_000185a0;
          iVar2 = *piVar3;
          pcVar4 = strerror(iVar2);
          uVar6 = 0x76;
          uVar5 = DAT_000185b0;
        }
        else {
          iVar2 = safe_system(__s);
          if (-1 < iVar2) {
            IDBG_LINUXAPP_DbgOut(0x86,DAT_0001859c,uVar1);
            free(__s);
            return uVar1;
          }
          piVar3 = __errno_location();
          __mutex = DAT_000185a0;
          iVar2 = *piVar3;
          pcVar4 = strerror(iVar2);
          uVar6 = 0x82;
          uVar5 = DAT_000185a8;
        }
        IDBG_LINUXAPP_DbgOut(0x82,uVar5,DAT_000185a4,uVar6,uVar1,iVar2,pcVar4);
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x82,DAT_000185b4,DAT_000185a4,0x6b,uVar1);
      }
      pthread_mutex_lock(__mutex);
      *(undefined4 *)((int)__mutex + uVar1 * 4 + 0x18) = 0;
      pthread_mutex_unlock(__mutex);
    }
    free(__s);
  }
  return 0xffffffff;
}

