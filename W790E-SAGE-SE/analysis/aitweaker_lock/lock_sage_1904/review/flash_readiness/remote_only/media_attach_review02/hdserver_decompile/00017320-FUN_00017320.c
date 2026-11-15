
undefined4 FUN_00017320(int param_1,_union_1051 param_2)

{
  int iVar1;
  _union_1051 local_94;
  sigset_t sStack_90;
  undefined4 local_10;
  
  local_94 = param_2;
  sigfillset(&sStack_90);
  local_10 = 0x10000000;
  iVar1 = sigaction(param_1,(sigaction *)&local_94,(sigaction *)0x0);
  if (-1 < iVar1) {
    return 0;
  }
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00017390,DAT_0001738c,DAT_00017388,param_1);
  return 0;
}

