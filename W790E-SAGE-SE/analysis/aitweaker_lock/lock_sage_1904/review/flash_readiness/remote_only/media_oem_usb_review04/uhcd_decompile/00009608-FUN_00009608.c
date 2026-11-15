
undefined8 * FUN_00009608(uint param_1,ulonglong param_2)

{
  longlong lVar1;
  undefined8 *puVar2;
  ulonglong uVar3;
  uint uVar4;
  undefined8 *local_res18 [2];
  
  if (DAT_0000ed70 == '\0') {
    uVar3 = (ulonglong)DAT_00010528 % (param_2 & 0xffff);
    if (uVar3 != 0) {
      DAT_00010528 = (undefined8 *)(((param_2 & 0xffff) - uVar3) + (longlong)DAT_00010528);
    }
    puVar2 = (undefined8 *)
             (-(ulonglong)
               ((undefined8 *)((longlong)DAT_00010528 + (ulonglong)param_1) < DAT_00010538) &
             (ulonglong)DAT_00010528);
    DAT_00010528 = (undefined8 *)((longlong)DAT_00010528 + (ulonglong)param_1);
  }
  else {
    uVar4 = param_1 >> 0xc;
    local_res18[0] = (undefined8 *)0xffffffff;
    DAT_0000ed70 = '\0';
    lVar1 = (**(code **)(DAT_000104c0 + 0x28))(1,DAT_0000ec40,uVar4,local_res18);
    if ((lVar1 < 0) &&
       (lVar1 = (**(code **)(DAT_000104c0 + 0x28))(0,DAT_0000ec40,uVar4,local_res18), lVar1 < 0)) {
      puVar2 = (undefined8 *)0x0;
    }
    else {
      uVar3 = (ulonglong)(uVar4 << 0xc);
      DAT_00010528 = local_res18[0];
      if (uVar3 != 0) {
        FUN_00000340(local_res18[0],uVar3,0);
      }
      DAT_00010538 = (undefined8 *)((uVar3 - 1) + (longlong)DAT_00010528);
      puVar2 = DAT_00010528;
      DAT_00010530 = DAT_00010528;
    }
  }
  return puVar2;
}

