
undefined4 FUN_0001192c(undefined2 param_1)

{
  int iVar1;
  FILE *__s;
  size_t sVar2;
  uint uStack_10038;
  undefined2 auStack_10034 [2];
  undefined4 uStack_10030;
  undefined2 uStack_1002c;
  undefined1 auStack_1002a [65542];
  
  uStack_10038 = 0xffffffff;
  memset(auStack_10034,0,DAT_00011a88);
  iVar1 = access(DAT_00011a8c,0);
  if (iVar1 == 0) {
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00011a90);
    uStack_10030 = 0xffffffff;
  }
  else {
    __s = fopen(DAT_00011a8c,DAT_00011a94);
    if (__s == (FILE *)0x0) {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00011aa0,DAT_00011a8c);
      uStack_10030 = 0xffffffff;
    }
    else {
      iVar1 = generate_random_number(&uStack_10038,4);
      if (iVar1 == -1) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00011aa4);
        uStack_10030 = 0xffffffff;
      }
      else {
        uStack_10038 = uStack_10038 & 0x7fffffff;
        sVar2 = fwrite(&uStack_10038,1,4,__s);
        if (sVar2 == 4) {
          *DAT_00011a98 = uStack_10038;
        }
        else {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00011a9c,DAT_00011a8c);
          uStack_10030 = 0xffffffff;
        }
      }
      fclose(__s);
    }
  }
  uStack_1002c = 4;
  memcpy(auStack_1002a,&uStack_10038,4);
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

