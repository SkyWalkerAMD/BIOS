
void FUN_0001752c(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  __pid_t local_14 [2];
  
  local_14[0] = getpid();
  IDBG_LINUXAPP_Runtime_DbgOut(0x87,DAT_000175e8,DAT_000175e4,DAT_000175e0,local_14[0]);
  iVar1 = sigwrap_open_mode(param_1,DAT_000175f0,DAT_000175ec);
  if (iVar1 < 0) {
    IDBG_LINUXAPP_DbgOut(0x84,DAT_00017600,DAT_000175e4,DAT_000175fc,param_1);
    return;
  }
  iVar2 = sigwrap_write(iVar1,local_14,4);
  if (iVar2 == 4) {
    sigwrap_close(iVar1);
    return;
  }
  IDBG_LINUXAPP_DbgOut(0x84,DAT_000175f8,DAT_000175e4,DAT_000175f4,param_1);
  sigwrap_close(iVar1);
  return;
}

