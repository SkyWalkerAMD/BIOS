
void InventoryDataNotify_from_disassembly(longlong param_1)

{
  longlong lVar1;
  longlong lVar2;
  code *pcVar3;
  ulonglong uVar4;
  longlong local_res18;
  undefined8 local_res20;
  undefined8 local_28 [2];
  
  local_28[0] = 0;
  local_res18 = 0;
  lVar1 = (**(code **)(DAT_00018a28 + 0x140))(&DAT_00016470,0,&local_res18);
  if (-1 < lVar1) {
    if (*(char *)(local_res18 + 0xc) == '\0') {
      lVar2 = (**(code **)(DAT_00018a28 + 0x140))(&DAT_00016400,0,&DAT_000189c0);
      lVar1 = local_res18;
      if (lVar2 < 0) {
        return;
      }
      FUN_0000de54(local_res18);
      FUN_0000e120(lVar1);
      FUN_0000b014(local_res18);
      FUN_00009570(local_res18);
      lVar1 = local_res18;
      pcVar3 = FUN_0000049c;
      uVar4 = 0;
      do {
        (*pcVar3)(lVar1);
        uVar4 = (ulonglong)((int)uVar4 + 1);
        pcVar3 = *(code **)(&DAT_00018580 + uVar4 * 8);
      } while (pcVar3 != (code *)0x0);
      FUN_0000ccf4(local_res18);
      lVar1 = local_res18;
      uVar4 = 0;
      pcVar3 = FUN_0000049c;
      while (pcVar3 != (code *)0x0) {
        (*pcVar3)(lVar1);
        uVar4 = (ulonglong)((int)uVar4 + 1);
        pcVar3 = *(code **)(&DAT_00018580 + uVar4 * 8);
      }
      local_res20 = 0;
      lVar1 = (**(code **)(DAT_00018a28 + 0x170))(0x200,8,0x49c,0,&DAT_000163d0,&local_res20);
      if (lVar1 == 0) {
        (**(code **)(DAT_00018a28 + 0x68))(local_res20);
        (**(code **)(DAT_00018a28 + 0x70))(local_res20);
      }
      FUN_00001a58(local_res18);
      FUN_0000197c(local_res18);
      *(undefined1 *)(local_res18 + 0xc) = 1;
      (**(code **)(DAT_00018a28 + 0x148))(local_28,&DAT_00016330,0,0);
    }
    if (param_1 != 0) {
      (**(code **)(DAT_00018a28 + 0x70))(param_1);
    }
  }
  return;
}

