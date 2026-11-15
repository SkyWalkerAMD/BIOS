
longlong FUN_000091e0(longlong param_1,longlong param_2)

{
  longlong lVar1;
  longlong lVar2;
  undefined8 local_res8;
  
  local_res8 = 0;
  lVar1 = (**(code **)(DAT_000104c0 + 0x118))
                    (param_2,&DAT_0000ea90,&local_res8,*(undefined8 *)(param_1 + 0x28),param_2,0x10)
  ;
  if (lVar1 == 0) {
    (**(code **)(DAT_000104c0 + 0x120))
              (param_2,&DAT_0000ea90,*(undefined8 *)(param_1 + 0x28),param_2);
    lVar1 = FUN_00005cdc(param_2);
    if ((lVar1 == 0) ||
       ((lVar2 = (**(code **)(DAT_000104c0 + 0x118))(), lVar2 != 0 && (lVar2 != -0x7fffffffffffffec)
        ))) {
      lVar2 = -0x7ffffffffffffffd;
    }
  }
  else {
    lVar2 = -0x7fffffffffffffec;
    if (lVar1 != -0x7fffffffffffffec) {
      lVar2 = -0x7ffffffffffffffd;
    }
  }
  return lVar2;
}

