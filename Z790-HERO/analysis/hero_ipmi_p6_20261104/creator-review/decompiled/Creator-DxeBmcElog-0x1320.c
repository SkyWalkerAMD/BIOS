
longlong ElogAddRecord_published_method
                   (longlong param_1,undefined8 *param_2,int param_3,undefined8 param_4,
                   ulonglong param_5,ulonglong *param_6)

{
  ulonglong *puVar1;
  longlong lVar2;
  undefined8 uVar3;
  char cVar4;
  byte local_28 [4];
  undefined1 local_24;
  ushort local_23;
  undefined8 local_20 [3];
  
  puVar1 = param_6;
  if ((param_6 == (ulonglong *)0x0) || (param_2 == (undefined8 *)0x0)) {
    lVar2 = -0x7ffffffffffffffe;
  }
  else if (*(int *)(param_1 + -0x70) == param_3) {
    if (DAT_00002040 == 0) {
      cVar4 = '\0';
    }
    else {
      uVar3 = FUN_00001948(DAT_00002040,local_28);
      cVar4 = (char)uVar3;
    }
    if (cVar4 == '\0') {
      if (param_5 < 0x11) {
        if (local_20 != param_2) {
          FUN_00001000(local_20,param_2,0x10);
        }
        param_6._0_1_ = 3;
        lVar2 = (**(code **)(DAT_00002040 + 8))
                          (DAT_00002040,10,0,0x44,local_20,0x10,&local_24,&param_6);
        if (-1 < lVar2) {
          *puVar1 = (ulonglong)local_23;
        }
      }
      else {
        lVar2 = -0x7ffffffffffffffd;
      }
    }
    else {
      lVar2 = -0x7ffffffffffffff7;
    }
  }
  else {
    lVar2 = -0x7ffffffffffffff2;
  }
  return lVar2;
}

