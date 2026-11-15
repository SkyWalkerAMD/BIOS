
void FUN_00017a04(void)

{
  int *piVar1;
  
  piVar1 = DAT_00017a28;
  if (*DAT_00017a28 < 1) {
    return;
  }
  sigwrap_close();
  *piVar1 = -1;
  return;
}

