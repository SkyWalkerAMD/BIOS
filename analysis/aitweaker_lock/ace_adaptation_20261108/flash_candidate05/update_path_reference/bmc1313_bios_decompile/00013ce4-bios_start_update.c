
undefined4
bios_start_update(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  undefined4 *__arg;
  size_t __n;
  __start_routine *__start_routine;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  uint uVar8;
  int iVar9;
  pthread_t pStack_10054;
  uint uStack_10050;
  undefined4 uStack_1004c;
  uint uStack_10048;
  int iStack_10044;
  int iStack_10040;
  undefined2 auStack_1003c [2];
  int iStack_10038;
  undefined2 uStack_10034;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  __n = DAT_00013fa8;
  puVar1 = DAT_00013fa4;
  uStack_10050 = 0;
  uStack_1004c = 0;
  uStack_10048 = 0;
  iStack_10044 = 0;
  *DAT_00013fa4 = 0;
  puVar1[1] = 0;
  puVar1[2] = 0;
  puVar1[3] = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  memset(auStack_1003c,0,__n);
  memcpy(&iStack_10040,(void *)((int)&uStack_8 + 2),4);
  if (iStack_10040 == *DAT_00013fac) {
    memcpy(&uStack_1004c,(void *)((int)&uStack_4 + 2),4);
    memcpy(&uStack_10048,&stack0x00000002,4);
    memcpy(&iStack_10044,&stack0x00000006,4);
    iVar4 = iStack_10044;
    uVar3 = uStack_10048;
    uVar2 = uStack_1004c;
    uVar8 = uStack_10048;
    iVar9 = iStack_10044;
    IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fb4,DAT_00013fb0,uStack_1004c,uStack_10048,iStack_10044);
    iVar5 = get_bios_file_size(&uStack_10050);
    uVar6 = DAT_00013fd0;
    uVar7 = DAT_00013fc8;
    if (iVar5 == 0) {
      if (*(int *)(DAT_00013fb8 + 0x34) == 1) {
        iVar5 = VerifyImageSign(1,DAT_00013fd8,0);
        if (iVar5 != 0) {
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00013fec,DAT_00013fcc,DAT_00013fe8,uVar8,iVar9);
          uStack_10034 = 0;
          iStack_10038 = 0xff;
          goto LAB_00013d68;
        }
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fdc);
        iVar5 = GetHashLength(DAT_00013fd8);
        uVar6 = DAT_00013ff8;
        uVar7 = DAT_00013ff4;
        if (iVar5 == -1) goto LAB_00013ecc;
        if (iVar5 == 0) {
          uStack_10050 = uStack_10050 - 0x88;
        }
      }
      uVar6 = DAT_00013fe4;
      uVar7 = DAT_00013fe0;
      if (uVar3 < uStack_10050) {
LAB_00013f44:
        IDBG_LINUXAPP_DbgOut(0x82,uVar6,DAT_00013fcc,uVar7,uVar8,iVar9);
        iStack_10038 = 0xff;
        uStack_10034 = 0;
      }
      else {
        if (iVar4 == 0xff) {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fd4);
        }
        else {
          iVar5 = BiosConfiguration();
          if (iVar5 != 0) {
            uVar6 = DAT_00013ff0;
            uVar7 = 0x400;
            goto LAB_00013f44;
          }
        }
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fbc,DAT_00013fb0,uVar2,uStack_10050);
        __start_routine = DAT_00013fc0;
        __arg = DAT_00013fa4;
        *puVar1 = uVar2;
        puVar1[2] = iVar4;
        puVar1[1] = uStack_10050;
        puVar1[3] = param_2;
        iStack_10038 = pthread_create(&pStack_10054,(pthread_attr_t *)0x0,__start_routine,__arg);
        if (iStack_10038 == 0) {
          uStack_10034 = 0;
          goto LAB_00013d70;
        }
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00013fc4);
        uStack_10034 = 0;
      }
    }
    else {
LAB_00013ecc:
      IDBG_LINUXAPP_DbgOut(0x82,uVar6,DAT_00013fcc,uVar7,uVar8,iVar9);
      uStack_10034 = 0;
      iStack_10038 = 0xff;
    }
  }
  else {
    iStack_10038 = 6;
  }
LAB_00013d68:
  ActiveHostSPIDriver(1);
LAB_00013d70:
  auStack_1003c[0] = param_1;
  send_compmngr_response(auStack_1003c);
  return 0;
}

