
undefined4 bios_perform_recovery(undefined2 param_1)

{
  int iVar1;
  pthread_t pStack_10028;
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  
  memset(auStack_10024,0,DAT_00012208);
  iVar1 = pthread_create(&pStack_10028,(pthread_attr_t *)0x0,DAT_0001220c,(void *)0x0);
  if (iVar1 != 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00012210);
    *(undefined4 *)(DAT_00012214 + 0x60) = 0;
    uStack_10020 = 0xff;
  }
  uStack_1001c = 0;
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

