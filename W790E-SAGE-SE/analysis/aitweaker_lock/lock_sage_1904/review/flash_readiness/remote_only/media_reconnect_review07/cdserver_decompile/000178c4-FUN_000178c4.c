
void FUN_000178c4(char *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  char *__s;
  int iVar1;
  
  __s = calloc(0x11,1);
  iVar1 = snprintf(__s,0x10,DAT_00017944,param_3,param_4);
  if (0x11 < iVar1) {
    printf(DAT_0001794c,iVar1);
  }
  snprintf(param_1,0x1d,DAT_00017948,param_2,__s,param_5);
  free(__s);
  return;
}

