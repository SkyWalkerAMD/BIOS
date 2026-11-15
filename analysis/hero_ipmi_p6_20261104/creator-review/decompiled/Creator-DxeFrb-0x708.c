
longlong FUN_00000708(undefined8 param_1,uint param_2)

{
  longlong lVar1;
  undefined4 in_register_00000014;
  longlong lVar2;
  undefined1 local_res10 [8];
  undefined1 local_res18 [8];
  undefined1 local_res20 [8];
  byte local_38 [4];
  undefined2 local_34;
  char local_30;
  byte local_2f;
  byte local_2e;
  undefined1 local_2d;
  undefined2 local_29;
  
  lVar2 = (longlong)(int)param_2;
  if ((param_2 - 1 < 3) && (DAT_000011c0 != '\0')) {
    local_res10[0] = 9;
    lVar1 = (**(code **)(DAT_00001468 + 8))
                      (DAT_00001468,CONCAT71((int7)(CONCAT44(in_register_00000014,param_2) >> 8),6),
                       0,0x25,0,0,&local_30,local_res10);
    if ((-1 < lVar1) && (local_30 == '\0')) {
      if ((local_2f & 0x40) == 0) {
        lVar1 = -0x7fffffffffffffeb;
      }
      else if ((local_2f & 7) == param_2) {
        *(undefined2 *)(&DAT_00001480 + lVar2 * 6) = local_29;
        (&DAT_00001482)[lVar2 * 6] = local_2d;
        (&DAT_00001484)[lVar2 * 6] = local_2e & 7;
        (&DAT_00001483)[lVar2 * 6] = local_2e >> 4 & 7;
        FUN_00000260((undefined8 *)local_38,6);
        local_34 = 0;
        local_38[0] = local_38[0] & 0xb8 | (byte)param_2 & 7;
        local_res10[0] = 6;
        local_res18[0] = 1;
        lVar1 = (**(code **)(DAT_00001468 + 8))
                          (DAT_00001468,6,0,0x24,local_38,6,local_res20,local_res18);
      }
      else {
        lVar1 = -0x7ffffffffffffff2;
      }
    }
  }
  else {
    lVar1 = -0x7ffffffffffffffd;
  }
  return lVar1;
}

