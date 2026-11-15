undefined8 FUN_0003048c(undefined8 param_1)
{
  uint uVar1;
  if (DAT_001936bc <= DAT_0019368c + 0x80) {
    DAT_00193670 = FUN_00001450(DAT_00193670,(ulonglong)DAT_001936bc,
                                (ulonglong)(DAT_001936bc + 0x100));
    if (DAT_00193670 == 0) {
      return 0x8000000000000009;
    }
    DAT_001936bc = DAT_001936bc + 0x100;
  }
  (**(code **)(DAT_00180188 + 0x160))((ulonglong)DAT_0019368c + DAT_00193670,param_1,0x80);
  uVar1 = DAT_0019368c;
  DAT_0019368c = DAT_0019368c + 0x80;
  if (DAT_00193658 != (uint *)0x0) {
    if ((ulonglong)DAT_001936b8 <= (ulonglong)DAT_00193678 + 4) {
      DAT_00193658 = (uint *)FUN_00001450((longlong)DAT_00193658,(ulonglong)DAT_001936b8,
                                          (ulonglong)(DAT_001936b8 + 0x80));
      if (DAT_00193658 == (uint *)0x0) {
        return 0x8000000000000009;
      }
      DAT_001936b8 = DAT_001936b8 + 0x80;
    }
    DAT_00193658[(ulonglong)*DAT_00193658 + 1] = uVar1;
    DAT_0018f14c = *DAT_00193658;
    uVar1 = DAT_0018f14c + 1;
    *DAT_00193658 = uVar1;
    if (1999 < uVar1) {
      FUN_0002c890(0x16d340);
    }
    DAT_00193678 = DAT_00193678 + 4;
    return 0;
  }
  DAT_001936b8 = 0x80;
  DAT_00193658 = (uint *)FUN_000014c8(0x80);
  if (DAT_00193658 == (uint *)0x0) {
    return 0x8000000000000009;
  }
  DAT_00193678 = 8;
  DAT_00193658[(ulonglong)*DAT_00193658 + 1] = uVar1;
  *DAT_00193658 = 1;
  return 0;
}
