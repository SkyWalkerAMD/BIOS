
void FUN_000177c8(int param_1)

{
  int iVar1;
  char *__filename;
  stat sStack_60;
  
  __filename = *(char **)(DAT_00017808 + param_1 * 4);
  iVar1 = __xstat(3,__filename,&sStack_60);
  if (iVar1 != 0) {
    return;
  }
  unlink(__filename);
  return;
}

