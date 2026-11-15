
undefined8 WS05_4037c(longlong param_1,undefined8 param_2,undefined8 *param_3)

{
  longlong lVar1;
  longlong lVar2;
  undefined8 local_res8 [4];
  
  if (DAT_000aff28 != (longlong *)0x0) {
    lVar2 = 0;
    if (*DAT_000aff28 != 0) {
      param_1 = 0;
      do {
        param_2 = *(undefined8 *)(param_1 + (longlong)DAT_000aff28);
        param_3 = local_res8;
        lVar1 = (**(code **)(DAT_000afc38 + 0x50))(DAT_000afc38);
        if (-1 < lVar1) {
          param_3 = (undefined8 *)0x0;
          param_2 = 0;
          lVar1 = (**(code **)(DAT_000afbc8 + 0x110))(local_res8[0]);
          if (-1 < lVar1) {
            param_3 = (undefined8 *)0x0;
            param_2 = 0;
            (**(code **)(DAT_000afbc8 + 0x108))(local_res8[0],0,0,1);
          }
        }
        lVar2 = lVar2 + 1;
        param_1 = lVar2 * 8;
      } while (DAT_000aff28[lVar2] != 0);
    }
    if ((DAT_000afff8 != '\0') && (DAT_000aff21 == '\0')) {
      DAT_000aff21 = 1;
      FUN_00040094(param_1,param_2,param_3);
      DAT_000aff21 = '\0';
    }
  }
  return 0;
}

