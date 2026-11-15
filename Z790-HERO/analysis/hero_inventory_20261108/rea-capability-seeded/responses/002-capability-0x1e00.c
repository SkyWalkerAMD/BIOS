
ulonglong ProbeInventoryData_from_disassembly(longlong param_1)

{
  ulonglong uVar1;
  undefined8 *puVar2;
  byte *pbVar3;
  longlong lVar4;
  int local_res8 [2];
  short *local_res10;
  byte *local_res18;
  longlong local_res20;
  ulonglong local_38 [2];
  
  pbVar3 = (byte *)0x0;
  lVar4 = 0;
  local_res10 = (short *)0x0;
  local_res18 = (byte *)0x0;
  local_res20 = 0;
  if (param_1 == 0) {
    uVar1 = 0x8000000000000002;
  }
  else {
    uVar1 = RestJsonRequest_from_disassembly
                      (param_1,s__redfish_v1_Oem_Ami_InventoryDat_00007308,&local_res10,local_38,
                       '\x01','\x01');
    if (-1 < (longlong)uVar1) {
      local_res8[0] = 0;
      if (*(undefined8 **)(param_1 + 0x18) == (undefined8 *)0x0) {
        uVar1 = 0x8000000000000002;
      }
      else {
        uVar1 = FUN_00003348(*(undefined8 **)(param_1 + 0x18),0,local_res10,local_38,0,0,
                             (ulonglong *)0x0,(longlong *)&local_res18,&local_res20,local_res8);
        pbVar3 = local_res18;
        lVar4 = local_res20;
      }
      if (local_res8[0] != 3) {
        uVar1 = 0x8000000000000018;
      }
      if (((-1 < (longlong)uVar1) && (pbVar3 != (byte *)0x0)) && (lVar4 != 0)) {
        puVar2 = FUN_00005c58(pbVar3);
        *(undefined8 **)(param_1 + 0x100) = puVar2;
        if (puVar2 != (undefined8 *)0x0) {
          *(undefined1 *)(param_1 + 0xf9) = 1;
        }
        (**(code **)(DAT_00007b28 + 0x48))(pbVar3);
      }
    }
    if (local_res10 != (short *)0x0) {
      (**(code **)(DAT_00007b28 + 0x48))(local_res10);
    }
    FUN_00004d00(local_38);
  }
  return uVar1;
}

