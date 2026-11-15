
int FUN_00017a2c(void)

{
  pthread_mutex_t *__mutex;
  int *piVar1;
  int iVar2;
  
  iVar2 = 0;
  pthread_mutex_lock(DAT_00017aa4);
  __mutex = DAT_00017aa4;
  piVar1 = DAT_00017aa8;
  do {
    if (*piVar1 == 0) {
      *(undefined4 *)((int)DAT_00017aa4 + iVar2 * 4 + 0x18) = 1;
      pthread_mutex_unlock(__mutex);
      return iVar2;
    }
    iVar2 = iVar2 + 1;
    piVar1 = piVar1 + 1;
  } while (iVar2 != 4);
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00017ab0,DAT_00017aac,0xc2,4);
  pthread_mutex_unlock(DAT_00017aa4);
  return -1;
}

