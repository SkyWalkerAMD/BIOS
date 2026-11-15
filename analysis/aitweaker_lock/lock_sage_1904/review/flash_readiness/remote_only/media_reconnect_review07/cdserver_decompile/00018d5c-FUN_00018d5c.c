
undefined4 FUN_00018d5c(char *param_1)

{
  FILE *__stream;
  int iVar1;
  __ssize_t _Var2;
  undefined4 uVar3;
  size_t local_d8;
  char *local_d4;
  undefined1 auStack_d0 [64];
  char acStack_90 [128];
  
  local_d8 = 0;
  local_d4 = (char *)0x0;
  __stream = fopen(DAT_00018e18,DAT_00018e14);
  uVar3 = DAT_00018e1c;
  if (__stream == (FILE *)0x0) {
    IDBG_LINUXAPP_DbgOut(0x82,DAT_00018e24,DAT_00018e20,0x14);
    uVar3 = 0xffffffea;
  }
  else {
    while (_Var2 = getline(&local_d4,&local_d8,__stream), _Var2 != -1) {
      __isoc99_sscanf(local_d4,uVar3,auStack_d0,acStack_90);
      iVar1 = strcmp(param_1,acStack_90);
      if (iVar1 == 0) {
        fclose(__stream);
        return 1;
      }
    }
    fclose(__stream);
    uVar3 = 0;
  }
  return uVar3;
}

