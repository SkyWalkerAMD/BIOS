
longlong FUN_000021f4(longlong param_1)

{
  longlong lVar1;
  undefined8 *puVar2;
  
  if (param_1 == 0) {
    lVar1 = -0x7ffffffffffffffe;
  }
  else {
    DAT_0000ea38 = (undefined8 *)0x0;
    lVar1 = FUN_00001e74(param_1,&DAT_0000ea20);
    if (((-1 < lVar1) && (DAT_0000ea38 != (undefined8 *)0x0)) &&
       (puVar2 = (undefined8 *)FUN_000023c4(param_1,(ulonglong)DAT_0000ea30),
       puVar2 != (undefined8 *)0x0)) {
      FUN_0000dce0(puVar2,DAT_0000ea38,(ulonglong)DAT_0000ea30);
      DAT_0000ea38 = puVar2;
    }
  }
  return lVar1;
}

