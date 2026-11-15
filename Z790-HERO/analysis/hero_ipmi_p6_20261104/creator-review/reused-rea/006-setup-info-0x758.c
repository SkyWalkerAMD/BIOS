
longlong FUN_00000758(longlong param_1,undefined8 param_2,short param_3,undefined1 param_4,
                     undefined8 param_5,undefined8 *param_6)

{
  longlong *plVar1;
  longlong lVar2;
  short *psVar3;
  longlong local_38;
  undefined8 local_30;
  short local_28;
  undefined1 local_26;
  undefined8 local_20;
  undefined8 *local_18;
  
  DAT_000153f8 = &local_38;
  local_20 = param_5;
  local_18 = param_6;
  if (param_6 != (undefined8 *)0x0) {
    *param_6 = 0;
  }
  lVar2 = -0x7ffffffffffffffd;
  if (PTR_FUN_0000a3e8 != (undefined *)0x0) {
    psVar3 = &DAT_0000a3e2;
    local_38 = param_1;
    local_30 = param_2;
    local_28 = param_3;
    local_26 = param_4;
    do {
      if ((((psVar3[-1] == *(short *)(param_1 + 0x18)) && (*psVar3 == *(short *)(param_1 + 0x1a)))
          && (psVar3[1] == param_3)) &&
         (lVar2 = (**(code **)(psVar3 + 3))(DAT_0000a678,psVar3[-1],*psVar3,param_3),
         lVar2 != -0x7ffffffffffffffd)) {
        DAT_000153f8 = (longlong *)0x0;
        return lVar2;
      }
      plVar1 = (longlong *)(psVar3 + 0xb);
      psVar3 = psVar3 + 8;
    } while (*plVar1 != 0);
  }
  DAT_000153f8 = (longlong *)0x0;
  return lVar2;
}

