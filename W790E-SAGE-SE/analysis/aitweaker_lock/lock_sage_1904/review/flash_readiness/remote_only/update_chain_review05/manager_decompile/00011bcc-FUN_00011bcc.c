
undefined4 FUN_00011bcc(void)

{
  char *pcVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  code *pcVar10;
  uint uStack_20038;
  uint uStack_20034;
  undefined4 uStack_10034;
  undefined4 uStack_10030;
  undefined4 uStack_1002c;
  undefined4 uStack_10028;
  undefined1 auStack_10024 [65536];
  
  memset(&uStack_10034,0,DAT_00011e64);
  uVar7 = DAT_00011e7c;
  uVar6 = DAT_00011e78;
  uVar5 = DAT_00011e74;
  uVar4 = DAT_00011e70;
  uVar3 = DAT_00011e6c;
  uVar2 = DAT_00011e68;
LAB_00011c0c:
  do {
    do {
      while( true ) {
        iVar8 = FUN_00011614(&uStack_10034);
        if (iVar8 < 0) {
          uStack_20038 = DAT_00011ea8;
          IDBG_LINUXAPP_DbgOut(0x82,DAT_00011eb0,DAT_00011e68,DAT_00011eac);
          return 0;
        }
        uStack_20034 = uStack_10034 & 0xffff;
        uStack_20038 = uStack_10034 >> 0x10 & 0xff;
        IDBG_LINUXAPP_Runtime_DbgOut(0x87,uVar3,uVar2,DAT_00011e80);
        if (uStack_10034._2_1_ != '\0') break;
        switch(uStack_10034 & 0xffff) {
        case 1:
          memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
          iVar8 = FUN_0001192c(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
          if (iVar8 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,DAT_00011e98,uVar2,DAT_00011e94);
          }
          break;
        case 2:
          memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
          iVar8 = FUN_00011aa8(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
          if (iVar8 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,uVar7,uVar2,DAT_00011e90);
          }
          break;
        case 3:
          memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
          iVar8 = FUN_00011704(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
          if (iVar8 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,uVar6,uVar2,DAT_00011e8c);
          }
          break;
        case 4:
          memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
          iVar8 = FUN_00011878(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
          if (iVar8 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,uVar4,uVar2,DAT_00011e88);
          }
          break;
        case 5:
          memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
          iVar8 = FUN_000117c8(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
          if (iVar8 != 0) {
            IDBG_LINUXAPP_DbgOut(0x82,uVar5,uVar2,0x180);
          }
          break;
        default:
          IDBG_LINUXAPP_DbgOut(0x86,DAT_00011eb4);
        }
      }
    } while (*DAT_00011e9c < 1);
    if (*(char *)(DAT_00011ea0 + 0xff) == uStack_10034._2_1_) {
      iVar9 = 0;
    }
    else {
      iVar9 = 0;
      iVar8 = DAT_00011ea0;
      do {
        iVar9 = iVar9 + 1;
        if (iVar9 == *DAT_00011e9c) goto LAB_00011c0c;
        pcVar1 = (char *)(iVar8 + 0x213);
        iVar8 = iVar8 + 0x114;
      } while (*pcVar1 != uStack_10034._2_1_);
    }
    pcVar10 = *(code **)(DAT_00011ea0 + iVar9 * 0x114 + 0x10c);
    if (pcVar10 != (code *)0x0) {
      memcpy(&uStack_20038,auStack_10024,DAT_00011e84);
      iVar8 = (*pcVar10)(uStack_10034,uStack_10030,uStack_1002c,uStack_10028);
      if (iVar8 != 0) {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00011ea4,uStack_10034 & 0xffff);
      }
    }
  } while( true );
}

