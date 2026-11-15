undefined8
FUN_0001b00c(longlong param_1,longlong param_2,uint param_3,uint param_4,ulonglong param_5,
            undefined4 *param_6)
{
  ulonglong *puVar1;
  ulonglong uVar2;
  longlong lVar3;
  undefined4 *puVar4;
  longlong *plVar5;
  longlong *plVar6;
  ulonglong uVar7;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  if (((*DAT_001937f0 <= param_3) || (param_6 == (undefined4 *)0x0)) || (param_5 == 0)) {
    return 0x8000000000000002;
  }
  plVar5 = (longlong *)((ulonglong)param_3 * 0x10 + param_2);
  plVar6 = (longlong *)((ulonglong)DAT_001937f0[(ulonglong)param_3 + 1] + (longlong)DAT_001937f0);
  if (plVar6 == (longlong *)0x0) {
    return 0x8000000000000002;
  }
  if (param_4 == 0xffff) {
    local_38 = 0x9b9b610b;
    local_34 = 0x465e1887;
    local_30 = 0xd9331bb2;
    local_2c = 0xa7445fe0;
    lVar3 = FUN_000b1b20(plVar6,(longlong *)&local_38,0x10);
    if (lVar3 != 0) {
      return 0x8000000000000002;
    }
    param_4 = 0;
  }
  uVar7 = 0;
  if ((*(uint *)(plVar6 + 0xd) & 0x2000) == 0) {
    uVar7 = (ulonglong)param_4;
  }
  if ((param_1 == 1) && (*plVar5 == 0)) {
    lVar3 = FUN_000014c8(uVar7 + param_5);
    *plVar5 = lVar3;
    if (lVar3 == 0) {
      return 0x8000000000000002;
    }
    plVar5[1] = uVar7 + param_5;
  }
  puVar1 = (ulonglong *)(plVar5 + 1);
  if (*puVar1 == 0) {
    lVar3 = FUN_0001a908((ulonglong)param_3,puVar1);
    *plVar5 = lVar3;
    if (lVar3 == 0) {
      return 0x8000000000000002;
    }
  }
  uVar2 = uVar7 + param_5;
  if ((*puVar1 < uVar2) && (param_1 == 1)) {
    lVar3 = FUN_000014c8(uVar2);
    if (lVar3 == 0) {
      return 0x8000000000000002;
    }
    (**(code **)(DAT_00180188 + 0x160))(lVar3,*plVar5);
    FUN_000013d0(plVar5);
    *plVar5 = lVar3;
    *puVar1 = uVar2;
  }
  if (param_1 == 0) {
    FUN_0010749e(param_6,param_5,0);
    if (*puVar1 < uVar2) {
      param_5 = *puVar1 - uVar7;
    }
    if (*puVar1 <= uVar7) {
      return 0;
    }
    puVar4 = param_6;
    param_6 = (undefined4 *)(*plVar5 + uVar7);
  }
  else {
    puVar4 = (undefined4 *)(*plVar5 + uVar7);
  }
  (**(code **)(DAT_00180188 + 0x160))(puVar4,param_6,param_5);
  return 0;
}
