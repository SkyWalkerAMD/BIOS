
undefined4 FUN_00018ccc(undefined4 param_1)

{
  char *__needle;
  FILE *__stream;
  char *pcVar1;
  int iVar2;
  undefined4 uVar3;
  char acStack_68 [84];
  
  __stream = fopen(DAT_00018d68,DAT_00018d64);
  uVar3 = DAT_00018d70;
  __needle = DAT_00018d6c;
  if (__stream == (FILE *)0x0) {
    uVar3 = 0xffffffff;
  }
  else {
    while ((iVar2 = feof(__stream), iVar2 == 0 &&
           (pcVar1 = fgets(acStack_68,0x50,__stream), pcVar1 != (char *)0x0))) {
      pcVar1 = strstr(acStack_68,__needle);
      if (pcVar1 != (char *)0x0) {
        __isoc99_sscanf(acStack_68,uVar3,param_1);
      }
    }
    fclose(__stream);
    uVar3 = 0;
  }
  return uVar3;
}

