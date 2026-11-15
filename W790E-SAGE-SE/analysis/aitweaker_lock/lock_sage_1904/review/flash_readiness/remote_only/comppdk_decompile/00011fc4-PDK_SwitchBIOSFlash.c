
undefined4 PDK_SwitchBIOSFlash(char param_1)

{
  int iVar1;
  undefined4 local_3c;
  char acStack_38 [40];
  
  memset(acStack_38,0,0x28);
  local_3c = *DAT_000120a4;
  snprintf(acStack_38,0x28,DAT_000120a8,0xf);
  iVar1 = sigwrap_open(acStack_38,2);
  if (-1 < iVar1) {
    write(iVar1,&local_3c,3);
    sigwrap_close(iVar1);
    memset(acStack_38,0,0x28);
    local_3c = 0;
    snprintf(acStack_38,0x28,DAT_000120ac,0xf);
    iVar1 = sigwrap_open(acStack_38,2);
    if (-1 < iVar1) {
      local_3c = CONCAT31(local_3c._1_3_,param_1 + '0');
      write(iVar1,&local_3c,1);
      sigwrap_close(iVar1);
      return 0;
    }
  }
  printf(DAT_000120b4,DAT_000120b0);
  return 0xffffffff;
}

