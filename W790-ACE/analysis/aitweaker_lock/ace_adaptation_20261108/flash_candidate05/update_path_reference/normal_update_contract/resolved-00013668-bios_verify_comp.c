

undefined4
bios_verify_comp(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *__arg;
  size_t __n;
  undefined4 uVar1;
  undefined4 uVar2;
  pthread_t pStack_10044;
  undefined4 uStack_10040;
  undefined4 uStack_1003c;
  int iStack_10038;
  undefined2 auStack_10034 [2];
  int iStack_10030;
  undefined2 uStack_1002c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  __arg = &gFlashInfo;
  *&gFlashInfo = 0;
  __n = 0x1000c;
  __arg[1] = 0;
  __arg[2] = 0;
  __arg[3] = 0;
  uStack_10040 = 0;
  uStack_1003c = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  memset(auStack_10034,0,__n);
  memcpy(&iStack_10038,(void *)((int)&uStack_8 + 2),4);
  if (iStack_10038 == *&g_FirmwareID) {
    memcpy(&uStack_10040,(void *)((int)&uStack_4 + 2),4);
    memcpy(&uStack_1003c,&stack0x00000002,4);
    uVar2 = uStack_1003c;
    uVar1 = uStack_10040;
    IDBG_LINUXAPP_DbgOut(0x86,"[%s]FlashOffset = 0x%x, Size = 0x%x\n","bios_verify_comp",uStack_10040,uStack_1003c);
    __arg[3] = param_2;
    *__arg = uVar1;
    __arg[1] = uVar2;
    get_bios_file_size(__arg + 1);
    if (*0x164a0 == -1) {
      uStack_1002c = 0;
      iStack_10030 = -1;
    }
    else {
      iStack_10030 = pthread_create(&pStack_10044,(pthread_attr_t *)0x0,&bios_verify_flash,__arg);
      if (iStack_10030 == 0) {
        uStack_1002c = 0;
        goto LAB_000136ec;
      }
      IDBG_LINUXAPP_DbgOut(0x86,"Error while creating the BIOS Verify Flash Thread.\n");
      uStack_1002c = 0;
    }
  }
  else {
    iStack_10030 = 6;
  }
  ActiveHostSPIDriver(1);
LAB_000136ec:
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

