
void FUN_00014770(undefined4 param_1)

{
  prctl(0xf,DAT_000147b8,0,0,0);
  FUN_00014234(2,param_1);
  IDBG_LINUXAPP_DbgOut(0x86,DAT_000147bc);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

