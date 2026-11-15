
undefined8 FUN_00001f38(undefined8 param_1,undefined8 *param_2,longlong *param_3,ulonglong param_4)

{
  longlong lVar1;
  undefined8 uVar2;
  
  if ((param_3 == (longlong *)0x0) || (param_2 == (undefined8 *)0x0)) {
    uVar2 = 0x8000000000000002;
  }
  else {
    lVar1 = FUN_0000249c(param_3,(longlong *)&DAT_0000e0c0,0x10);
    if (lVar1 == 0) {
      if ((DAT_0000ea38 == (undefined8 *)0x0) || (DAT_0000ea30 == 0)) {
        uVar2 = 0x800000000000000e;
      }
      else {
        *(uint *)(param_2 + 2) = DAT_0000ea30;
        *param_2 = DAT_0000ea20;
        param_2[1] = DAT_0000ea28;
        if ((undefined8 *)param_2[3] == (undefined8 *)0x0) {
          param_2[3] = DAT_0000ea38;
        }
        else {
          if (param_4 < DAT_0000ea30) {
            return 0x8000000000000005;
          }
          FUN_0000dce0((undefined8 *)param_2[3],DAT_0000ea38,(ulonglong)DAT_0000ea30);
        }
        uVar2 = 0;
      }
    }
    else {
      uVar2 = 0x8000000000000003;
    }
  }
  return uVar2;
}

