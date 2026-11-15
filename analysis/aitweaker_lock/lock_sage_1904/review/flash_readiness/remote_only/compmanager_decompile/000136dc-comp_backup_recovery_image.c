
void comp_backup_recovery_image(undefined4 param_1,undefined4 param_2)

{
  size_t __n;
  undefined2 uStack_20028;
  undefined1 uStack_20026;
  undefined4 uStack_20024;
  
  __n = DAT_00013740;
  memset(&uStack_20028,0,DAT_00013740);
  memset((void *)((int)&uStack_20028 + __n),0,__n);
  uStack_20028 = 7;
  uStack_20026 = 2;
  uStack_20024 = param_2;
  send_compmngr_command(&uStack_20028,(int)&uStack_20028 + __n,0x3c);
  return;
}

