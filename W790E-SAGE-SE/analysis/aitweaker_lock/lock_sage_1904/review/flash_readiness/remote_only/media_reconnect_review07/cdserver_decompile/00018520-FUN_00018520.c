
undefined4 FUN_00018520(undefined4 param_1)

{
  char *__needle;
  FILE *__stream;
  char *pcVar1;
  int iVar2;
  undefined4 uVar3;
  char acStack_68 [84];
  
  __stream = fopen(DAT_000185bc,DAT_000185b8);
  uVar3 = DAT_000185c4;
  __needle = DAT_000185c0;
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

