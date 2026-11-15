
longlong ElogReadRecord_published_method
                   (longlong param_1,undefined8 *param_2,int param_3,ulonglong *param_4,
                   ulonglong *param_5)

{
  longlong lVar1;
  undefined1 local_res10 [8];
  undefined2 local_28;
  undefined1 local_26;
  undefined1 local_25;
  undefined2 local_24;
  undefined1 local_20;
  ushort local_1f;
  undefined8 local_1d [2];
  
  local_res10[0] = 0x13;
  if (((param_2 == (undefined8 *)0x0) || (param_4 == (ulonglong *)0x0)) ||
     (param_5 == (ulonglong *)0x0)) {
    lVar1 = -0x7ffffffffffffffe;
  }
  else if (*(int *)(param_1 + -0x70) == param_3) {
    if (*param_4 < 0x10) {
      lVar1 = -0x7ffffffffffffffb;
    }
    else {
      local_26 = (undefined1)*param_5;
      local_28 = 0;
      local_25 = *(undefined1 *)((longlong)param_5 + 1);
      local_24 = 0xff00;
      lVar1 = (**(code **)(DAT_00002040 + 8))
                        (DAT_00002040,10,0,0x43,&local_28,6,&local_20,local_res10);
      if (-1 < lVar1) {
        *param_5 = (ulonglong)local_1f;
        *param_4 = 0x10;
        if (param_2 != local_1d) {
          FUN_00001000(param_2,local_1d,0x10);
        }
        lVar1 = 0;
      }
    }
  }
  else {
    lVar1 = -0x7ffffffffffffff2;
  }
  return lVar1;
}

