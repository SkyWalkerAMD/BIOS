
longlong Observed_Setup_ConfigAccess_Callback
                   (undefined8 param_1,undefined8 param_2,short param_3,undefined1 param_4,
                   undefined8 param_5,undefined8 *param_6)

{
  longlong lVar1;
  longlong lVar2;
  undefined8 *puVar3;
  longlong lVar4;
  undefined8 local_38;
  undefined8 local_30;
  short local_28;
  undefined1 local_26;
  undefined8 local_20;
  undefined8 *local_18;
  undefined8 local_10;
  
  local_20 = param_5;
  local_10 = DAT_0002b880;
  local_18 = param_6;
  if (param_6 != (undefined8 *)0x0) {
    *param_6 = 0;
  }
  lVar2 = 0;
  DAT_00043090 = &local_38;
  lVar1 = -0x7ffffffffffffffd;
  puVar3 = DAT_0004ef10;
  local_38 = param_1;
  local_30 = param_2;
  local_28 = param_3;
  local_26 = param_4;
  if (PTR_FUN_00027d48 != (undefined *)0x0) {
    lVar4 = 0;
    do {
      if (*(short *)((longlong)&DAT_00027d44 + lVar4) == param_3) {
        DAT_00043080 = 1;
        lVar1 = (**(code **)((longlong)&PTR_FUN_00027d48 + lVar4))(DAT_0002b880,1,0,param_3);
        DAT_00043080 = 0;
        if ((DAT_00043090[1] == 0x1000) && (puVar3 = DAT_0004ef10, lVar1 != -0x7ffffffffffffffd))
        break;
      }
      lVar2 = lVar2 + 1;
      lVar4 = lVar2 * 0x10;
      puVar3 = DAT_0004ef10;
    } while ((&PTR_FUN_00027d48)[lVar2 * 2] != (undefined *)0x0);
  }
  while (((undefined8 **)puVar3 != &DAT_0004ef10 &&
         ((*(short *)(puVar3 + 2) != param_3 ||
          (lVar1 = (*(code *)puVar3[3])(&local_38), lVar1 == -0x7ffffffffffffffd))))) {
    puVar3 = (undefined8 *)*puVar3;
  }
  DAT_00043090 = (undefined8 *)0x0;
  return lVar1;
}

