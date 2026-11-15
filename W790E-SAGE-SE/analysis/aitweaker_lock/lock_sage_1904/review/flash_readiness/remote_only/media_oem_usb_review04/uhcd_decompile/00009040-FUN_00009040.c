
undefined8
FUN_00009040(undefined8 param_1,longlong param_2,undefined8 param_3,undefined1 param_4,
            undefined2 param_5,undefined1 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined8 uVar1;
  ulonglong uVar2;
  
  if (param_2 == 0xe8) {
    uVar1 = 0x800000000000000e;
  }
  else {
    *(undefined2 *)(*(longlong *)(param_2 + -200) + 0x16a) = param_5;
    *(undefined1 *)(*(longlong *)(param_2 + -200) + 0x16c) = param_6;
    *(undefined8 *)(*(longlong *)(param_2 + -200) + 0x170) = param_8;
    *(undefined1 *)(*(longlong *)(param_2 + -200) + 0x168) = param_4;
    uVar2 = (**(code **)(DAT_000104c0 + 0x18))(0x1f);
    (**(code **)(DAT_000104c0 + 0x20))(uVar2);
    if (uVar2 < 0x11) {
      uVar2 = 0x10;
    }
    uVar1 = (**(code **)(DAT_000104c0 + 0x18))(uVar2);
    FUN_00003fd8(0xb,*(undefined1 *)(*(longlong *)(param_2 + -0xc0) + 1),
                 *(longlong *)(param_2 + -0xc0),*(undefined8 *)(param_2 + -200));
    (**(code **)(DAT_000104c0 + 0x20))(uVar1);
    uVar1 = 0;
  }
  return uVar1;
}

