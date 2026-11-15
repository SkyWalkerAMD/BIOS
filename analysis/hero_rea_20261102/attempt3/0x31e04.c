
longlong FUN_00031e04(undefined8 param_1,undefined8 param_2,undefined8 *param_3)

{
  longlong lVar1;
  longlong lVar2;
  longlong lVar3;
  longlong lVar4;
  uint uVar5;
  uint *puVar6;
  undefined8 *puVar7;
  longlong local_res18;
  longlong local_res20;
  undefined8 local_68;
  longlong local_60 [7];
  
  local_68 = 10;
  lVar4 = 0;
  puVar7 = &local_68;
  if (param_3 != (undefined8 *)0x0) {
    puVar7 = param_3;
  }
  lVar1 = FUN_000014c8(*puVar7);
  local_res18 = lVar1;
  lVar2 = (**(code **)(DAT_00180320 + 0x20))(DAT_00180320,param_1,puVar7,lVar1);
  lVar3 = lVar4;
  if (lVar2 == -0x7ffffffffffffffb) {
    FUN_000013d0(&local_res18);
    lVar1 = FUN_000014c8(*puVar7);
    if (lVar1 == 0) {
      return 0;
    }
    local_res18 = lVar1;
    lVar2 = (**(code **)(DAT_00180320 + 0x20))(DAT_00180320,param_1,puVar7,lVar1);
    if (lVar2 < 0) goto LAB_00031e9b;
  }
  else if (lVar2 < 0) {
    return 0;
  }
  uVar5 = 0x14;
  if (*(uint *)(lVar1 + 0x10) < 0x15) {
LAB_00031e9b:
    FUN_000013d0(&local_res18);
    return lVar3;
  }
  while( true ) {
    puVar6 = (uint *)((ulonglong)uVar5 + lVar1);
    if (*(char *)((longlong)puVar6 + 3) == '\x02') break;
    lVar3 = lVar4;
    if ((*(char *)((longlong)puVar6 + 3) == -0x21) ||
       (uVar5 = uVar5 + (*puVar6 & 0xffffff), lVar3 = 0, *(uint *)(lVar1 + 0x10) <= uVar5))
    goto LAB_00031e9b;
  }
  lVar3 = FUN_000014c8((ulonglong)*puVar6 & 0xffffff);
  if (lVar3 == 0) {
    return 0;
  }
  local_res20 = lVar3;
  (**(code **)(DAT_00180188 + 0x160))(lVar3,puVar6);
  if (*(char *)(lVar3 + 4) == '\x0e') {
    FUN_0010749e((undefined4 *)local_60,0x30,0);
    local_60[0] = lVar3;
    lVar4 = FUN_00031f6c(local_60);
    if (lVar4 != -0x7ffffffffffffffd) goto LAB_00031e9b;
  }
  FUN_000013d0(&local_res20);
  *puVar7 = 0;
  return 0;
}

