
undefined4 FUN_0001142c(int param_1,_union_1051 param_2)

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
  printf(DAT_00011488,param_1);
  return 0;
}

