
void FUN_00013a54(uint param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar1 = DAT_00013b1c;
  iVar4 = DAT_00013b18;
  iVar3 = DAT_00013b18 + param_1 * 4;
  iVar2 = *(int *)(iVar3 + 0x1fc);
  do {
    if (iVar2 == 0) {
LAB_00013ab4:
                    /* WARNING: Subroutine does not return */
      pthread_exit((void *)0x0);
    }
    iVar2 = *(int *)(iVar1 + param_1 * 4);
    if ((iVar2 != -1) && (iVar2 = FUN_000181ec(iVar2 == 1), iVar2 != 0)) {
      if (*(int *)(iVar1 + param_1 * 4) != -1) {
        FUN_000180b4();
        *(undefined4 *)(iVar1 + param_1 * 4) = 0xffffffff;
      }
      iVar4 = param_1 * 0x4c + iVar4;
      if (*(int *)(iVar4 + 0x14) != -1) {
        nbd_disconnect(iVar4);
        *(undefined4 *)(iVar4 + 0x14) = 0xffffffff;
      }
      FUN_00013960(*(undefined4 *)(iVar1 + param_1 * 4 + 0x20),param_1 & 0xff,0x10);
      goto LAB_00013ab4;
    }
    select_sleep(1,0);
    iVar2 = *(int *)(iVar3 + 0x1fc);
  } while( true );
}

