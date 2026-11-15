
longlong entry(ulonglong param_1,longlong param_2)

{
  longlong lVar1;
  
  FUN_000013c8(param_1,param_2);
  DAT_00005980 = -0x7fffffffffffffff;
  lVar1 = FUN_00001000((undefined8 *)&DAT_00005880);
  if (lVar1 == 0) {
    lVar1 = FUN_00002a14(param_1,param_2);
    if ((-1 < lVar1) || (DAT_00005980 < 0)) {
      DAT_00005980 = lVar1;
    }
    FUN_000010d0(0x5880,0xffffffffffffffff);
  }
  lVar1 = DAT_00005980;
  if (DAT_00005980 < 0) {
    FUN_00004338();
  }
  return lVar1;
}

