
void InventoryProtocolNotify_from_disassembly(undefined8 param_1)

{
  bool bVar1;
  bool bVar2;
  char cVar3;
  longlong lVar4;
  ulonglong uVar5;
  undefined *puVar6;
  ulonglong *puVar7;
  ulonglong **ppuVar8;
  undefined8 *puVar9;
  char local_res18 [8];
  ulonglong *local_res20;
  ulonglong *local_68;
  longlong local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  local_60 = 0;
  local_48 = 0;
  bVar2 = false;
  local_res20 = (ulonglong *)0x0;
  local_68 = (ulonglong *)0x0;
  local_38 = 0;
  local_40 = 8;
  local_30 = 0xea4838b6;
  local_2c = 0x4a6230e9;
  local_28 = 0x880d7e94;
  local_24 = 0xa4e7d32a;
  if (DAT_0001e060 != '\0') {
    return;
  }
  lVar4 = (**(code **)(DAT_0001e070 + 0x140))(&DAT_00019880,0);
  bVar1 = false;
  if ((-1 < lVar4) &&
     (lVar4 = (**(code **)(DAT_0001e070 + 0x140))(&DAT_000198f0,0), bVar1 = false, -1 < lVar4)) {
    bVar1 = true;
  }
  ppuVar8 = (ulonglong **)0x0;
  puVar9 = &local_40;
  puVar6 = &DAT_00019910;
  lVar4 = (**(code **)(DAT_0001e070 + 0xb0))(2);
  if (-1 < lVar4) {
    ppuVar8 = &local_res20;
    puVar6 = &DAT_00019850;
    lVar4 = (**(code **)(DAT_0001e070 + 0x98))(local_58);
    if (-1 < lVar4) {
      ppuVar8 = &local_68;
      puVar6 = &DAT_00019910;
      lVar4 = (**(code **)(DAT_0001e070 + 0x98))(local_58);
      bVar2 = false;
      if (-1 < lVar4) {
        bVar2 = true;
      }
    }
  }
  if (!bVar1) {
    return;
  }
  (**(code **)(DAT_0001e070 + 0x70))(param_1);
  if (!bVar2) {
    DAT_0001e060 = 1;
    FUN_00016a1c(&DAT_00019910,puVar6,ppuVar8,puVar9,&local_38);
    return;
  }
  local_res18[0] = '\x01';
  local_res18[1] = '\x01';
  local_res18[2] = '\x01';
  if (1 < *local_68) {
    cVar3 = (*(code *)local_68[4])(local_68);
    if (cVar3 != '\0') {
      uVar5 = PublishInventory_from_disassembly(local_res20,(longlong)local_68,local_60,local_res18)
      ;
      if ((-1 < (longlong)uVar5) &&
         (lVar4 = (**(code **)(DAT_0001e070 + 0x170))(0x200,8,0x484,0,&DAT_00019890,&local_50),
         -1 < lVar4)) {
        (**(code **)(DAT_0001e070 + 0x68))(local_50);
        (**(code **)(DAT_0001e070 + 0x70))(local_50);
      }
      goto LAB_000006a6;
    }
    if (((local_res18[0] == '\0') && (local_res18[1] == '\0')) && (local_res18[2] == '\0'))
    goto LAB_000006a6;
  }
  FUN_00002f34(local_res20,puVar6);
  puVar7 = local_68;
  FUN_00001f7c(local_res20,(longlong)local_68,local_60,local_res18);
  PublishCRC_from_disassembly(local_res20,puVar7,local_60,local_res18);
LAB_000006a6:
  (**(code **)(DAT_0001e078 + 0x58))(u_AmiRedfishInventoryFlags_00019960,&local_30,3,3,local_res18);
  return;
}

