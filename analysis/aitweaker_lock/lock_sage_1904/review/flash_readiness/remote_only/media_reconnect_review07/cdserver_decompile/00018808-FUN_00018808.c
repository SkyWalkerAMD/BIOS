
void FUN_00018808(undefined4 param_1)

{
  char *pcVar1;
  undefined4 uVar2;
  int iVar3;
  undefined1 uStack_11;
  
  iVar3 = FUN_00018d5c(DAT_000189c0);
  if (iVar3 == 0) {
    safe_system(DAT_000189d0);
    iVar3 = safe_system(DAT_000189c4);
  }
  else {
    iVar3 = safe_system(DAT_000189c4);
  }
  if (iVar3 == 0) {
    iVar3 = FUN_00018520(&uStack_11);
  }
  else {
    safe_system(DAT_000189d4);
    safe_system(DAT_000189d8);
    safe_system(DAT_000189dc);
    safe_system(DAT_000189e0);
    safe_system(DAT_000189e4);
    safe_system(DAT_000189e8);
    safe_system(DAT_000189ec);
    safe_system(DAT_000189f0);
    safe_system(DAT_000189f4);
    safe_system(DAT_000189f8);
    safe_system(DAT_000189fc);
    pcVar1 = DAT_00018a00;
    safe_system(DAT_00018a04);
    safe_system(DAT_00018a08);
    if (*pcVar1 == '\x02') {
      safe_system(DAT_00018a38);
      FUN_00017e74(pcVar1 + 0x44,0x3f);
    }
    else {
      safe_system(DAT_00018a0c);
      FUN_00017e74(pcVar1 + 4,0x3e);
    }
    safe_system(DAT_00018a10);
    safe_system(DAT_00018a14);
    safe_system(DAT_00018a18);
    uVar2 = DAT_00018a1c;
    safe_system(DAT_00018a20);
    safe_system(DAT_00018a24);
    iVar3 = sigwrap_open(uVar2,2);
    if (iVar3 < 0) {
      IDBG_LINUXAPP_DbgOut(0x82,DAT_00018a40,DAT_00018a3c,0x20c,uVar2);
      sigwrap_close(iVar3);
    }
    else {
      sigwrap_write(iVar3,DAT_00018a28,0x41);
      sigwrap_close(iVar3);
    }
    safe_system(DAT_00018a2c);
    safe_system(DAT_00018a30);
    iVar3 = FUN_00018520(&uStack_11);
  }
  if (iVar3 != 0) {
    safe_system(DAT_00018a34);
  }
  FUN_000185c8(param_1);
  FUN_00018360(DAT_000189cc,DAT_000189c8);
  return;
}

