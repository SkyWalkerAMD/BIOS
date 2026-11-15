
int set_redirection_mode_cd(void)

{
  pthread_mutex_t *__mutex;
  int *piVar1;
  int iVar2;
  
  iVar2 = 0;
  pthread_mutex_lock(DAT_00027544);
  __mutex = DAT_00027544;
  piVar1 = DAT_00027548;
  do {
    if (*piVar1 == 0) {
      *(undefined4 *)((int)DAT_00027544 + iVar2 * 4 + 0x18) = 1;
      pthread_mutex_unlock(__mutex);
      return iVar2;
    }
    iVar2 = iVar2 + 1;
    piVar1 = piVar1 + 1;
  } while (iVar2 != 4);
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00027550,DAT_0002754c,0xc2,4);
  pthread_mutex_unlock(DAT_00027544);
  return -1;
}

