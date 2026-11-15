
void FUN_000147c0(undefined4 param_1)

{
  prctl(0xf,DAT_00014808,0,0,0);
  FUN_00014234(1,param_1);
  IDBG_LINUXAPP_DbgOut(0x86,DAT_0001480c);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

