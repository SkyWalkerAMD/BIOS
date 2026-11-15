
longlong entry(ulonglong param_1,longlong param_2)

{
  longlong lVar1;
  undefined *puVar2;
  
  FUN_00001328(param_1,param_2);
  puVar2 = &DAT_0000ead0;
  DAT_0000ebd0 = -0x7fffffffffffffff;
  lVar1 = FUN_00001000((undefined8 *)&DAT_0000ead0);
  if (lVar1 == 0) {
    lVar1 = FUN_00002274(puVar2,param_2);
    if ((-1 < lVar1) || (DAT_0000ebd0 < 0)) {
      DAT_0000ebd0 = lVar1;
    }
    FUN_000010d0(0xead0,0xffffffffffffffff);
  }
  lVar1 = DAT_0000ebd0;
  if (DAT_0000ebd0 < 0) {
    FUN_000023f4();
  }
  return lVar1;
}

