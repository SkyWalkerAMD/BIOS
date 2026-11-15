
void FUN_0001623c(void)

{
  int iVar1;
  
  iVar1 = DAT_00016288;
  FUN_00017444();
  if (*(int *)(iVar1 + 0x30) != -1) {
    ShutDownServer();
  }
  if (*(int *)(iVar1 + 0x34) != -1) {
    ShutDownServer();
  }
  iVar1 = DAT_0001628c;
  if (*(int *)(DAT_0001628c + 0x90) < 0) {
    return;
  }
  sigwrap_close();
  *(undefined4 *)(iVar1 + 0x90) = 0xffffffff;
  return;
}

