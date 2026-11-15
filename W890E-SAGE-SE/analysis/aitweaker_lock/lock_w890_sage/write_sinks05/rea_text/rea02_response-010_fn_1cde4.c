
undefined8
WS05_1cde4(longlong param_1,longlong param_2,uint param_3,uint param_4,longlong param_5,
          undefined1 *param_6)

{
  longlong lVar1;
  ulonglong uVar2;
  undefined8 *puVar3;
  longlong *plVar4;
  undefined1 *puVar5;
  undefined1 *puVar6;
  ulonglong uVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  
  uVar9 = (ulonglong)param_3;
  if ((((*DAT_000baaf8 <= param_3) || (param_6 == (undefined1 *)0x0)) || (param_5 == 0)) ||
     (plVar4 = (longlong *)((ulonglong)DAT_000baaf8[uVar9 + 1] + (longlong)DAT_000baaf8),
     plVar4 == (longlong *)0x0)) {
    return 0x8000000000000002;
  }
  if (param_4 == 0xffff) {
    if (*plVar4 != 0x465e18879b9b610b) {
      return 0x8000000000000002;
    }
    if (plVar4[1] != -0x58bba01f26cce44e) {
      return 0x8000000000000002;
    }
    param_4 = 0;
  }
  uVar7 = 0;
  if ((*(uint *)(plVar4 + 0xd) & 0x2000) == 0) {
    uVar7 = (ulonglong)param_4;
  }
  if ((param_1 == 1) && (*(longlong *)(param_2 + uVar9 * 0x10) == 0)) {
    puVar3 = FUN_00059b50(plVar4,uVar7 + param_5);
    *(undefined8 **)(param_2 + uVar9 * 0x10) = puVar3;
    if (puVar3 == (undefined8 *)0x0) {
      return 0x8000000000000002;
    }
    *(ulonglong *)(param_2 + 8 + uVar9 * 0x10) = uVar7 + param_5;
  }
  lVar1 = param_2 + uVar9 * 0x10;
  if (*(longlong *)(lVar1 + 8) == 0) {
    plVar4 = (longlong *)(ulonglong)param_3;
    puVar3 = FUN_0001c6d0((ulonglong)plVar4,(ulonglong *)(lVar1 + 8));
    *(undefined8 **)(param_2 + uVar9 * 0x10) = puVar3;
    if (puVar3 == (undefined8 *)0x0) {
      return 0x8000000000000002;
    }
  }
  uVar8 = uVar7 + param_5;
  if ((*(ulonglong *)(lVar1 + 8) < uVar8) && (param_1 == 1)) {
    puVar3 = FUN_00059b50(plVar4,uVar8);
    if (puVar3 == (undefined8 *)0x0) {
      return 0x8000000000000002;
    }
    (**(code **)(DAT_000afbc8 + 0x160))
              (puVar3,*(undefined8 *)(param_2 + uVar9 * 0x10),*(undefined8 *)(lVar1 + 8));
    if (*(longlong *)(param_2 + uVar9 * 0x10) != 0) {
      (**(code **)(DAT_000afbc8 + 0x48))();
    }
    *(undefined8 **)(param_2 + uVar9 * 0x10) = puVar3;
    *(ulonglong *)(lVar1 + 8) = uVar8;
  }
  else if (param_1 == 0) {
    FUN_00001600(param_6,param_5,0);
    uVar2 = *(ulonglong *)(param_2 + 8 + uVar9 * 0x10);
    if (uVar2 < uVar8) {
      param_5 = uVar2 - uVar7;
    }
    if (uVar2 <= uVar7) {
      return 0;
    }
    puVar6 = (undefined1 *)(*(longlong *)(param_2 + uVar9 * 0x10) + uVar7);
    puVar5 = param_6;
    goto LAB_0001cf58;
  }
  puVar5 = (undefined1 *)(*(longlong *)(param_2 + uVar9 * 0x10) + uVar7);
  puVar6 = param_6;
LAB_0001cf58:
  (**(code **)(DAT_000afbc8 + 0x160))(puVar5,puVar6,param_5);
  return 0;
}

