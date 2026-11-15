
undefined4 bios_get_update_progress(undefined2 param_1,undefined4 param_2,uint param_3)

{
  void *__src;
  undefined2 auStack_10024 [2];
  undefined4 uStack_10020;
  undefined2 uStack_1001c;
  undefined1 auStack_1001a [65538];
  char local_6;
  
  memset(auStack_10024,0,DAT_00011f80);
  if ((param_3 & 0xffff) == 1) {
    local_6 = (char)(param_3 >> 0x10);
    __src = DAT_00011f8c;
    if ((local_6 == '\x01') || (__src = DAT_00011f88, local_6 == '\x02')) {
      memcpy(auStack_1001a,__src,4);
      uStack_1001c = 4;
    }
  }
  else {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00011f84);
    uStack_1001c = 0;
    uStack_10020 = 0xff;
  }
  auStack_10024[0] = param_1;
  send_compmngr_response(auStack_10024);
  return 0;
}

