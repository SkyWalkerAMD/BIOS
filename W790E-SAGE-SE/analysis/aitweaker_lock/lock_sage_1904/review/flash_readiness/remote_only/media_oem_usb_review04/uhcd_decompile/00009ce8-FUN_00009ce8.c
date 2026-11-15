
undefined8 FUN_00009ce8(longlong param_1,undefined8 param_2,uint *param_3)

{
  undefined8 uVar1;
  undefined2 *puVar2;
  undefined8 uVar3;
  
  if (*param_3 < 0xb) {
    uVar3 = 0x8000000000000005;
  }
  else {
    (**(code **)(DAT_000104c0 + 0x168))(DAT_00010460,0x1f);
    puVar2 = DAT_00010460;
    *DAT_00010460 = 0xb27;
    uVar1 = *(undefined8 *)(param_1 + 0x38);
    uVar3 = 0;
    *(undefined8 *)((longlong)puVar2 + 0xb) = 0;
    *(undefined8 *)((longlong)puVar2 + 3) = uVar1;
    FUN_00003d5c();
    if (*(longlong *)((longlong)DAT_00010460 + 0xb) == 0) {
      return 0x8000000000000003;
    }
    (**(code **)(DAT_000104c0 + 0x160))(param_2,*(longlong *)((longlong)DAT_00010460 + 0xb),0xb);
  }
  *param_3 = 0xb;
  return uVar3;
}

