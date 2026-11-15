
int IniLoadFile(char *param_1)

{
  FILE *__stream;
  int iVar1;
  
  __stream = fopen(param_1,DAT_00013a94);
  if (__stream == (FILE *)0x0) {
    printf(DAT_00013a98,param_1);
    __stream = fopen(param_1,DAT_00013a9c);
    if (__stream == (FILE *)0x0) {
      printf(DAT_00013aa0,param_1);
      return 0;
    }
  }
  fclose(__stream);
  iVar1 = iniparser_load(param_1);
  if (iVar1 == 0) {
    printf(DAT_00013aa4,param_1);
  }
  return iVar1;
}

