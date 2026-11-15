
void _FINI_0(void)

{
  char *pcVar1;
  
  pcVar1 = DAT_00012e04;
  if (*DAT_00012e04 != '\0') {
    return;
  }
  FUN_00012d7c();
  *pcVar1 = '\x01';
  return;
}

