
void _FINI_0(void)

{
  char *pcVar1;
  
  pcVar1 = DAT_00012e60;
  if (*DAT_00012e60 != '\0') {
    return;
  }
  FUN_00012dd8();
  *pcVar1 = '\x01';
  return;
}

