
longlong FUN_000092c8(longlong param_1,undefined8 param_2,longlong param_3,short param_4)

{
  undefined8 uVar1;
  undefined8 *puVar2;
  undefined8 *puVar3;
  longlong lVar4;
  undefined8 uVar5;
  undefined8 local_res10;
  longlong local_28 [2];
  
  local_28[0] = 0;
  local_res10 = param_2;
  puVar2 = FUN_000063c0(DAT_00010558,&LAB_00006554,&local_res10);
  if (puVar2 == (undefined8 *)0x0) {
    return -0x7ffffffffffffff9;
  }
  uVar1 = *puVar2;
  uVar5 = 80000;
  local_28[0] = (**(code **)(DAT_000104c0 + 0x58))();
  if (local_28[0] < 0) {
    return local_28[0];
  }
  FUN_00008bdc(0,0,uVar5,param_4);
  puVar3 = FUN_000063c0((undefined8 *)puVar2[3],FUN_00008a50,local_28);
  if (puVar3 != (undefined8 *)0x0) {
    lVar4 = (**(code **)(DAT_000104c0 + 0x58))(DAT_00010490,1,80000);
    return lVar4;
  }
  if (param_3 == 0) {
    FUN_00006374((longlong)puVar2);
    (**(code **)(DAT_000104c0 + 0x120))
              (local_res10,&DAT_0000ea90,*(undefined8 *)(param_1 + 0x28),local_res10);
    (**(code **)(DAT_000104c0 + 0x48))(uVar1);
    DAT_000104a0 = DAT_000104a0 + -1;
    if (DAT_000104a0 != 0) goto LAB_0000940a;
    local_28[0] = (**(code **)(DAT_000104c0 + 0x58))(DAT_00010490,0,80000);
    local_28[0] = (**(code **)(DAT_000104c0 + 0x70))(DAT_00010490);
    DAT_00010490 = 0;
  }
  if (DAT_000104a0 == 0) {
    return 0;
  }
LAB_0000940a:
  (**(code **)(DAT_000104c0 + 0x58))(DAT_00010490,1,80000);
  return 0;
}

