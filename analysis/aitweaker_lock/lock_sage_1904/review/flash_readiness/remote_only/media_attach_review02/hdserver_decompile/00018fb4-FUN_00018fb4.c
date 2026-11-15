
void FUN_00018fb4(undefined4 param_1)

{
  char *pcVar1;
  undefined4 uVar2;
  int iVar3;
  undefined1 uStack_11;
  
  iVar3 = FUN_00019508(DAT_0001916c);
  if (iVar3 == 0) {
    safe_system(DAT_0001917c);
    iVar3 = safe_system(DAT_00019170);
  }
  else {
    iVar3 = safe_system(DAT_00019170);
  }
  if (iVar3 == 0) {
    iVar3 = FUN_00018ccc(&uStack_11);
  }
  else {
    safe_system(DAT_00019180);
    safe_system(DAT_00019184);
    safe_system(DAT_00019188);
    safe_system(DAT_0001918c);
    safe_system(DAT_00019190);
    safe_system(DAT_00019194);
    safe_system(DAT_00019198);
    safe_system(DAT_0001919c);
    safe_system(DAT_000191a0);
    safe_system(DAT_000191a4);
    safe_system(DAT_000191a8);
    pcVar1 = DAT_000191ac;
    safe_system(DAT_000191b0);
    safe_system(DAT_000191b4);
    if (*pcVar1 == '\x02') {
      safe_system(DAT_000191e4);
      FUN_00018620(pcVar1 + 0x44,0x3f);
    }
    else {
      safe_system(DAT_000191b8);
      FUN_00018620(pcVar1 + 4,0x3e);
    }
    safe_system(DAT_000191bc);
    safe_system(DAT_000191c0);
    safe_system(DAT_000191c4);
    uVar2 = DAT_000191c8;
    safe_system(DAT_000191cc);
    safe_system(DAT_000191d0);
    iVar3 = sigwrap_open(uVar2,2);
    if (iVar3 < 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_000191ec,DAT_000191e8,0x20c,uVar2);
      sigwrap_close(iVar3);
    }
    else {
      sigwrap_write(iVar3,DAT_000191d4,0x41);
      sigwrap_close(iVar3);
    }
    safe_system(DAT_000191d8);
    safe_system(DAT_000191dc);
    iVar3 = FUN_00018ccc(&uStack_11);
  }
  if (iVar3 != 0) {
    safe_system(DAT_000191e0);
  }
  FUN_00018d74(param_1);
  FUN_00018b0c(DAT_00019178,DAT_00019174);
  return;
}

