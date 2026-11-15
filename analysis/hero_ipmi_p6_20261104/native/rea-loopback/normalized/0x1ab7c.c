longlong FUN_0001ab7c(uint param_1,undefined8 *param_2,ulonglong param_3)
{
  longlong lVar1;
  ulonglong uVar2;
  longlong lVar3;
  uVar2 = (ulonglong)param_1;
  lVar1 = -0x7ffffffffffffffe;
  if (((param_2 != (undefined8 *)0x0) && (param_1 < *DAT_001937f0)) &&
     (lVar3 = (ulonglong)DAT_001937f0[uVar2 + 1] + (longlong)DAT_001937f0, lVar3 != 0)) {
    if ((*(byte *)(lVar3 + 0x68) & 2) == 0) {
      if (((*(uint *)(lVar3 + 0x68) & 0x1000) == 0) &&
         ((0x39 < param_1 || ((0x3ff800003fcfffeU >> (uVar2 & 0x3f) & 1) == 0)))) {
        lVar1 = FUN_0002785c(lVar3,param_2,0,param_3);
      }
      else {
        lVar1 = (**(code **)(DAT_00180198 + 0x58))
                          (lVar3 + 0x10,lVar3,*(undefined4 *)(lVar3 + 0x60),param_3,param_2);
        if (lVar1 < 0) {
          return lVar1;
        }
      }
      if (lVar1 < 0) {
        return lVar1;
      }
    }
    else {
      lVar1 = 0;
    }
    FUN_0001b74c(uVar2);
  }
  return lVar1;
}
