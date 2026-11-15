
void FUN_00000890(undefined *param_1,undefined8 param_2,undefined8 *param_3)

{
  longlong lVar1;
  undefined *puVar2;
  
  puVar2 = param_1;
  if (DAT_000153e0 == 0) {
    param_3 = &DAT_000153e0;
    param_2 = 0;
    puVar2 = &DAT_0000a360;
    lVar1 = (**(code **)(DAT_00015458 + 0x140))();
    if (lVar1 < 0) {
      return;
    }
  }
  if (DAT_000153f0 == 0) {
    param_3 = &DAT_000153f0;
    param_2 = 0;
    puVar2 = &DAT_0000a350;
    lVar1 = (**(code **)(DAT_00015458 + 0x140))();
    if (lVar1 < 0) {
      return;
    }
  }
  if (param_1 != (undefined *)0x0) {
    (**(code **)(DAT_00015458 + 0x70))();
    puVar2 = param_1;
  }
  if (DAT_000153e8 == '\0') {
    DAT_000153e8 = '\x01';
    FUN_00009424((longlong)puVar2,param_2,param_3);
  }
  return;
}

