
void FUN_00018344(void)

{
  int *piVar1;
  
  piVar1 = DAT_00018368;
  if (*DAT_00018368 < 1) {
    return;
  }
  sigwrap_close();
  *piVar1 = -1;
  return;
}

