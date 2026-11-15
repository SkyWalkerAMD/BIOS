
longlong ElogEraseRecord_published_method(longlong param_1,int param_2,ulonglong *param_3)

{
  longlong lVar1;
  undefined4 in_register_00000014;
  undefined1 local_res8 [8];
  undefined1 local_res10 [8];
  undefined1 local_res20 [8];
  undefined1 local_38 [4];
  undefined1 local_34;
  undefined2 local_33;
  ushort local_30 [2];
  undefined1 local_2c;
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_28;
  undefined1 local_27;
  undefined4 local_26;
  undefined1 local_20 [14];
  byte local_12;
  
  local_res10[0] = 0xf;
  local_res8[0] = 2;
  local_res20[0] = 3;
  if (*(int *)(param_1 + -0x70) == param_2) {
    lVar1 = (**(code **)(DAT_00002040 + 8))
                      (DAT_00002040,CONCAT71((int7)(CONCAT44(in_register_00000014,param_2) >> 8),10)
                       ,0,0x40,0,0,local_20,local_res10);
    if (-1 < lVar1) {
      if ((param_3 == (ulonglong *)0x0) || ((local_12 & 8) != 0)) {
        if ((local_12 & 2) == 0) {
          local_33 = 0;
          local_33._0_1_ = 0;
          local_33._1_1_ = 0;
        }
        else {
          lVar1 = FUN_00001838(DAT_00002040,(longlong)&local_34);
          if (lVar1 < 0) {
            return lVar1;
          }
        }
        if (param_3 == (ulonglong *)0x0) {
          local_26 = 0xaa524c43;
          local_28 = (undefined1)local_33;
          local_27 = local_33._1_1_;
          (**(code **)(DAT_00002040 + 8))(DAT_00002040,10,0,0x47,&local_28,6,local_38,local_res8);
          if (DAT_00002040 != 0) {
            lVar1 = FUN_00001888(DAT_00002040,(longlong)&local_34);
            return lVar1;
          }
          return -0x7ffffffffffffffe;
        }
        local_2a = (undefined1)*param_3;
        local_29 = *(undefined1 *)((longlong)param_3 + 1);
        local_2c = (undefined1)local_33;
        local_2b = local_33._1_1_;
        lVar1 = (**(code **)(DAT_00002040 + 8))
                          (DAT_00002040,10,0,0x46,&local_2c,4,local_30,local_res20);
        if (lVar1 < 0) {
          return lVar1;
        }
        if ((char)local_30[0] != -0x80) {
          if ((char)local_30[0] != -0x7f) {
            *param_3 = (ulonglong)local_30[0];
            return lVar1;
          }
          return -0x7ffffffffffffffa;
        }
      }
      lVar1 = -0x7ffffffffffffffd;
    }
  }
  else {
    lVar1 = -0x7ffffffffffffff2;
  }
  return lVar1;
}

