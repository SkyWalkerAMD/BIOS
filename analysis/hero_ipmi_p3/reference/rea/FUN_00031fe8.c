ulonglong FUN_00031fe8(void)
{
  uint uVar1;
  ulonglong uVar2;
  ulonglong uVar3;
  uVar3 = 0;
  if (DAT_00193694 + DAT_001936ac == 0) {
    DAT_001937b0 = (uint *)0x0;
    uVar3 = 0;
    DAT_001937e0 = 0;
  }
  else {
    DAT_001937b0 = (uint *)FUN_000014c8((ulonglong)(DAT_00193694 + DAT_001936ac));
    if (DAT_001937b0 == (uint *)0x0) {
      uVar3 = 0x8000000000000009;
    }
    else {
      (**(code **)(DAT_00180188 + 0x160))(DAT_001937b0,DAT_00193660,DAT_001936ac);
      (**(code **)(DAT_00180188 + 0x160))
                ((ulonglong)DAT_001936ac + (longlong)DAT_001937b0,DAT_00193640,DAT_00193694);
      uVar1 = DAT_001936ac;
      uVar2 = uVar3;
      if (*DAT_001937b0 != 0) {
        do {
          DAT_001937b0[uVar2 + 1] = DAT_001937b0[uVar2 + 1] + uVar1;
          uVar2 = uVar2 + 1;
        } while (uVar2 < *DAT_001937b0);
      }
      DAT_001937e0 = (ulonglong)DAT_001937b0[1] + (longlong)DAT_001937b0;
      FUN_000013d0(&DAT_00193640);
      FUN_000013d0(&DAT_00193660);
    }
  }
  return uVar3;
}