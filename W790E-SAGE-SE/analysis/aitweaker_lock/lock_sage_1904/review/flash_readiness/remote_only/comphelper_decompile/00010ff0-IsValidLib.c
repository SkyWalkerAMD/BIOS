
bool IsValidLib(char *param_1)

{
  int iVar1;
  char *pcVar2;
  
  iVar1 = strcmp(param_1,DAT_00011034);
  if (iVar1 == 0) {
    return false;
  }
  iVar1 = strcmp(param_1,DAT_00011038);
  if (iVar1 == 0) {
    return false;
  }
  pcVar2 = strstr(param_1,DAT_0001103c);
  return pcVar2 != (char *)0x0;
}

