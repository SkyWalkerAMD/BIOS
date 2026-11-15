
undefined4
bios_prepare_comp(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  char *__name;
  int iVar5;
  int iStack_1007c;
  uint uStack_10078;
  sysinfo sStack_10074;
  undefined2 auStack_10034 [2];
  int iStack_10030;
  undefined2 uStack_1002c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  uVar4 = DAT_000135c0;
  uVar3 = DAT_000135bc;
  puVar2 = DAT_000135b8;
  uVar1 = DAT_000135b4;
  DAT_000135b8[2] = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  IDBG_LINUXAPP_DbgOut(0x82,uVar4,uVar3,0x1ec,uVar1);
  memset(auStack_10034,0,DAT_000135c4);
  memcpy(&iStack_1007c,(void *)((int)&uStack_8 + 2),4);
  memcpy(&uStack_10078,(void *)((int)&uStack_4 + 2),4);
  if (iStack_1007c == *DAT_000135c8) {
    iVar5 = Check_FeatureList();
    if (iVar5 == 1) {
      iVar5 = ActiveHostSPIDriver(0);
      if (iVar5 == 0) {
        iVar5 = find_bios_spi_device(DAT_000135cc);
        if (iVar5 == 0) {
          iVar5 = sysinfo(&sStack_10074);
          __name = DAT_000135d0;
          if (iVar5 == 0) {
            if (sStack_10074.freeram < uStack_10078) {
              IDBG_LINUXAPP_DbgOut(0x86,DAT_000135e0);
              uStack_1002c = 0;
              iStack_10030 = 0xffffff;
            }
            else {
              puVar2[4] = uStack_10078;
              puVar2[3] = (uint)((uStack_10078 & 0xffffff) != 0);
              iVar5 = access(__name,0);
              if (iVar5 == 0) {
                unlink(DAT_000135d0);
              }
              iVar5 = access(DAT_000135d4,0);
              if (iVar5 == 0) {
                unlink(DAT_000135d4);
              }
              *puVar2 = 0;
              puVar2[1] = 0;
              uStack_1002c = 0;
              if (iStack_10030 == 0) goto LAB_00013430;
            }
          }
          else {
            IDBG_LINUXAPP_DbgOut(0x86,DAT_000135e8,iVar5);
            uStack_1002c = 0;
            iStack_10030 = 0xffffff;
          }
        }
        else {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_000135e4);
          uStack_1002c = 0;
          iStack_10030 = 0xffffff;
        }
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_000135dc);
        uStack_1002c = 0;
        iStack_10030 = 0xffffff;
      }
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_000135d8,uVar1);
      uStack_1002c = 0;
      iStack_10030 = 6;
    }
  }
  else {
    iStack_10030 = 6;
  }
  ActiveHostSPIDriver(1);
LAB_00013430:
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

