
undefined4
bios_prepare_comp(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  char *__name;
  int iVar6;
  int iStack_1007c;
  uint uStack_10078;
  sysinfo sStack_10074;
  undefined2 auStack_10034 [2];
  int iStack_10030;
  undefined2 uStack_1002c;
  undefined4 uStack_8;
  undefined4 uStack_4;
  
  uVar5 = DAT_00013428;
  uVar4 = DAT_00013424;
  uVar3 = DAT_00013420;
  puVar2 = DAT_0001341c;
  uVar1 = DAT_00013418;
  DAT_0001341c[2] = 0;
  uStack_8 = param_3;
  uStack_4 = param_4;
  IDBG_LINUXAPP_DbgOut(0x82,uVar5,uVar4,uVar3,uVar1);
  memset(auStack_10034,0,DAT_0001342c);
  memcpy(&iStack_1007c,(void *)((int)&uStack_8 + 2),4);
  memcpy(&uStack_10078,(void *)((int)&uStack_4 + 2),4);
  if (iStack_1007c == *DAT_00013430) {
    iVar6 = Check_FeatureList();
    if (iVar6 == 1) {
      iVar6 = ActiveHostSPIDriver(0);
      if (iVar6 == 0) {
        iVar6 = find_bios_spi_device(DAT_00013434);
        if (iVar6 == 0) {
          iVar6 = sysinfo(&sStack_10074);
          __name = DAT_00013438;
          if (iVar6 == 0) {
            if (sStack_10074.freeram < uStack_10078) {
              IDBG_LINUXAPP_DbgOut(0x86,DAT_00013448);
              uStack_1002c = 0;
              iStack_10030 = 0xffffff;
            }
            else {
              puVar2[4] = uStack_10078;
              puVar2[3] = (uint)((uStack_10078 & 0xffffff) != 0);
              iVar6 = access(__name,0);
              if (iVar6 == 0) {
                unlink(DAT_00013438);
              }
              iVar6 = access(DAT_0001343c,0);
              if (iVar6 == 0) {
                unlink(DAT_0001343c);
              }
              *puVar2 = 0;
              puVar2[1] = 0;
              uStack_1002c = 0;
              if (iStack_10030 == 0) goto LAB_00013294;
            }
          }
          else {
            IDBG_LINUXAPP_DbgOut(0x86,DAT_00013450,iVar6);
            uStack_1002c = 0;
            iStack_10030 = 0xffffff;
          }
        }
        else {
          IDBG_LINUXAPP_DbgOut(0x86,DAT_0001344c);
          uStack_1002c = 0;
          iStack_10030 = 0xffffff;
        }
      }
      else {
        IDBG_LINUXAPP_DbgOut(0x86,DAT_00013444);
        uStack_1002c = 0;
        iStack_10030 = 0xffffff;
      }
    }
    else {
      IDBG_LINUXAPP_DbgOut(0x86,DAT_00013440,uVar1);
      uStack_1002c = 0;
      iStack_10030 = 6;
    }
  }
  else {
    iStack_10030 = 6;
  }
  ActiveHostSPIDriver(1);
LAB_00013294:
  auStack_10034[0] = param_1;
  send_compmngr_response(auStack_10034);
  return 0;
}

