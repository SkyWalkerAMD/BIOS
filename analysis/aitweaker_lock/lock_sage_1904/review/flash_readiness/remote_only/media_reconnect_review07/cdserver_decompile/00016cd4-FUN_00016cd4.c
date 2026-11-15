
void FUN_00016cd4(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  __pid_t local_14 [2];
  
  local_14[0] = getpid();
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_00016d90,DAT_00016d8c,DAT_00016d88,local_14[0]);
  iVar1 = sigwrap_open_mode(param_1,DAT_00016d98,DAT_00016d94);
  if (iVar1 < 0) {
    IDBG_LINUXAPP_DbgOut(0x84,DAT_00016da8,DAT_00016d8c,DAT_00016da4,param_1);
    return;
  }
  iVar2 = sigwrap_write(iVar1,local_14,4);
  if (iVar2 == 4) {
    sigwrap_close(iVar1);
    return;
  }
  IDBG_LINUXAPP_DbgOut(0x84,DAT_00016da0,DAT_00016d8c,DAT_00016d9c,param_1);
  sigwrap_close(iVar1);
  return;
}

