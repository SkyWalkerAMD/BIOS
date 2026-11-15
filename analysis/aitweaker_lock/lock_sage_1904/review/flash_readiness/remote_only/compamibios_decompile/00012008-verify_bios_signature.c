
undefined4 verify_bios_signature(undefined2 param_1)

{
  int iVar1;
  code *pcVar2;
  int iVar3;
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  
  IDBG_LINUXAPP_DbgOut(0x82,DAT_000120ec,DAT_000120e8,DAT_000120e4,DAT_000120e0);
  memset(auStack_10024,0,DAT_000120f0);
  iVar1 = dlopen(DAT_000120f4,1);
  if (((iVar1 == 0) || (pcVar2 = (code *)dlsym(iVar1,DAT_000120f8), pcVar2 == (code *)0x0)) ||
     (iVar3 = (*pcVar2)(), iVar3 == 0)) {
    dlclose(iVar1);
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_000120fc);
    uStack_10020 = 0xff;
    uStack_1001c = 0;
    dlclose(iVar1);
  }
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

