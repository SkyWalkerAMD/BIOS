
int FUN_0001836c(void)

{
  pthread_mutex_t *__mutex;
  int *piVar1;
  int iVar2;
  
  iVar2 = 0;
  pthread_mutex_lock(DAT_000183e4);
  __mutex = DAT_000183e4;
  piVar1 = DAT_000183e8;
  do {
    if (*piVar1 == 0) {
      *(undefined4 *)((int)DAT_000183e4 + iVar2 * 4 + 0x18) = 1;
      pthread_mutex_unlock(__mutex);
      return iVar2;
    }
    iVar2 = iVar2 + 1;
    piVar1 = piVar1 + 1;
  } while (iVar2 != 4);
  IDBG_LINUXAPP_DbgOut(0x82,DAT_000183f0,DAT_000183ec,0xc2,4);
  pthread_mutex_unlock(DAT_000183e4);
  return -1;
}

