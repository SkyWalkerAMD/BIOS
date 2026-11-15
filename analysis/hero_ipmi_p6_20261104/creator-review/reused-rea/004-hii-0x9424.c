
longlong FUN_00009424(longlong param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 uVar1;
  longlong lVar2;
  longlong lVar3;
  uint *puVar4;
  undefined8 **ppuVar5;
  undefined **ppuVar6;
  longlong local_res8;
  undefined8 local_res10;
  undefined8 local_res18;
  undefined8 *local_res20;
  undefined8 in_stack_ffffffffffffffb0;
  undefined4 uVar7;
  longlong local_48;
  longlong local_40;
  undefined8 *local_38 [2];
  
  ppuVar6 = DAT_00015400;
  uVar7 = (undefined4)((ulonglong)in_stack_ffffffffffffffb0 >> 0x20);
  local_res20 = (undefined8 *)0x0;
  local_res8 = param_1;
  local_res10 = param_2;
  local_res18 = param_3;
  lVar2 = (**(code **)(DAT_000154a0 + 0x98))(DAT_00015400,&DAT_0000d268,&local_40);
  if ((-1 < lVar2) &&
     (lVar2 = (**(code **)(DAT_000154a0 + 0x118))
                        (ppuVar6,&DAT_0000d2a8,&local_res8,ppuVar6,0,CONCAT44(uVar7,2)), -1 < lVar2)
     ) {
    ppuVar5 = local_38;
    lVar2 = (**(code **)(DAT_000154a0 + 0x140))(&DAT_0000d208,0);
    if (-1 < lVar2) {
      local_res10 = 0;
      local_48 = 0;
      for (puVar4 = (uint *)(local_res8 + 0x14);
          (puVar4 < (uint *)((ulonglong)*(uint *)(local_res8 + 0x10) + local_res8) &&
          (*(char *)((longlong)puVar4 + 3) != '\x02'));
          puVar4 = (uint *)((longlong)puVar4 + (ulonglong)(*puVar4 & 0xffffff))) {
      }
      lVar2 = FUN_00009274(local_40,(longlong)(puVar4 + 1),ppuVar5,ppuVar6,&local_48,&local_res10);
      uVar1 = local_res10;
      if (-1 < lVar2) {
        if (DAT_000154b8 == '\0') {
          DAT_000154f0 = &DAT_000154f0;
          DAT_000154f8 = &DAT_000154f0;
          DAT_000154b8 = '\x01';
        }
        lVar2 = (*(code *)*local_38[0])(local_38[0],local_res8,local_res10,&local_res18);
        if (lVar2 < 0) {
          return lVar2;
        }
        lVar3 = (**(code **)(DAT_000154a0 + 0x40))(4,0x38,&local_res20);
        lVar2 = local_48;
        if (-1 < lVar3) {
          local_res20[2] = *(undefined8 *)(local_48 + 8);
          local_res20[3] = uVar1;
          local_res20[4] = local_res18;
          (**(code **)(DAT_000154a0 + 0x160))(local_res20 + 5,(longlong)puVar4 + 6,0x10);
          *local_res20 = &DAT_000154f0;
          local_res20[1] = DAT_000154f8;
          *DAT_000154f8 = local_res20;
          DAT_000154f8 = local_res20;
        }
        if (lVar2 != 0) {
          *(undefined8 *)(lVar2 + 0x18) = local_res18;
        }
        FUN_00000828(local_res18,lVar2);
      }
      lVar2 = 0;
    }
  }
  return lVar2;
}

