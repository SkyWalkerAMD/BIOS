
void FUN_00014720(undefined4 param_1)

{
  prctl(0xf,DAT_00014768,0,0,0);
  FUN_00014234(3,param_1);
  IDBG_LINUXAPP_DbgOut(0x86,DAT_0001476c);
                    /* WARNING: Subroutine does not return */
  pthread_exit((void *)0x0);
}

