
void comp_get_bios_recovery_status(undefined1 *param_1,undefined4 param_2)

{
  int iVar1;
  undefined2 uStack_20028;
  undefined1 uStack_20026;
  undefined4 uStack_20024;
  undefined1 auStack_1001c [10];
  undefined1 uStack_10012;
  
  memset(&uStack_20028,0,DAT_000137c4);
  memset(auStack_1001c,0,DAT_000137c4);
  uStack_20026 = 2;
  uStack_20028 = 9;
  uStack_20024 = param_2;
  iVar1 = send_compmngr_command(&uStack_20028,auStack_1001c,0x3c);
  if (iVar1 == 0) {
    *param_1 = uStack_10012;
  }
  return;
}

