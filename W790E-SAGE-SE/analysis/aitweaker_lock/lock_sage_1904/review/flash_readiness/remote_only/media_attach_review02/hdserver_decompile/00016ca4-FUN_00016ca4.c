
void FUN_00016ca4(void)

{
  int iVar1;
  
  iVar1 = DAT_00016cd4;
  FUN_00017cc4();
  if (*(int *)(iVar1 + 0x40) != -1) {
    ShutDownServer();
  }
  if (*(int *)(iVar1 + 0x44) == -1) {
    return;
  }
  ShutDownServer();
  return;
}

