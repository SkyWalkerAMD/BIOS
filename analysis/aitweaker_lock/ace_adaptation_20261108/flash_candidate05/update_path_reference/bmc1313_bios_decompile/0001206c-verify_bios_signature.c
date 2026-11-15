
undefined4 verify_bios_signature(undefined2 param_1)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  
  IDBG_LINUXAPP_DbgOut(0x82,DAT_00012150,DAT_0001214c,DAT_00012148,DAT_00012144);
  memset(auStack_10024,0,DAT_00012154);
  iVar1 = dlopen(DAT_00012158,1);
  if (((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_0001215c), pcVar2 == (code *)0x0)) ||
     (iVar3 = (*pcVar2)(), iVar3 == 0)) {
    dlclose(iVar1);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00012160);
    uStack_10020 = 0xff;
    uStack_1001c = 0;
    dlclose(iVar1);
  }
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

