
undefined4 bios_recovery_status(undefined2 param_1)

{
  undefined2 auStack_10024 [4];
  undefined2 uStack_1001c;
  undefined1 uStack_1001a;
  
  memset(auStack_10024,0,DAT_00012000);
  uStack_1001c = 1;
  uStack_1001a = (undefined1)*(undefined4 *)(DAT_00012004 + 0x70);
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

