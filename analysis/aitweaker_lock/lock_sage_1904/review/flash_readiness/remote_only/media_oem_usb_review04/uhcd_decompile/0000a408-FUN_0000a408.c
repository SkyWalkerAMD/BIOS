
longlong FUN_0000a408(longlong param_1,longlong param_2)

{
  longlong lVar1;
  undefined4 *puVar2;
  longlong local_res20;
  undefined1 local_18 [5];
  char local_13;
  byte local_11;
  
  if (*(char *)(*(longlong *)(DAT_00010458 + 0x3aa) + 0x2f) != '\0') {
    lVar1 = (**(code **)(DAT_000104c0 + 0x118))
                      (param_2,&DAT_0000eb40,&local_res20,*(undefined8 *)(param_1 + 0x28),param_2,
                       0x10);
    if (lVar1 < 0) {
      return lVar1;
    }
    (**(code **)(DAT_000104c0 + 0x120))
              (param_2,&DAT_0000eb40,*(undefined8 *)(param_1 + 0x28),param_2);
    puVar2 = FUN_000065fc(param_2);
    if ((((puVar2 != (undefined4 *)0x0) &&
         (lVar1 = (**(code **)(local_res20 + 0x40))(local_res20,local_18), -1 < lVar1)) &&
        (local_13 == '\b')) && ((local_11 < 2 || (local_11 == 0x50)))) {
      return 0;
    }
  }
  return -0x7ffffffffffffffd;
}

