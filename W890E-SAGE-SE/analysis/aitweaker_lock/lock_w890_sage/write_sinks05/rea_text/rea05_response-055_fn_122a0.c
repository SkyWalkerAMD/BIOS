
undefined8 FUN_000122a0(undefined8 *param_1,longlong *param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  longlong lVar4;
  uint *puVar5;
  uint *puVar6;
  uint *puVar7;
  longlong lVar8;
  ulonglong uVar9;
  longlong *plVar10;
  uint uVar11;
  
  uVar11 = 0;
  lVar8 = *param_2 + 4;
  lVar4 = *DAT_00048288;
  uVar1 = *(uint *)*param_1;
  puVar6 = (uint *)*param_1 + 1;
  uVar2 = *(uint *)DAT_00048288[1];
  if (uVar1 != 0) {
    do {
      if (uVar2 <= *puVar6) {
        return 0;
      }
      uVar3 = *puVar6;
      lVar8 = lVar8 + 6;
      uVar9 = (ulonglong)(ushort)puVar6[1];
      puVar6 = (uint *)((longlong)puVar6 + 6);
      plVar10 = (longlong *)((ulonglong)uVar3 * 0x10 + lVar4);
      if (uVar9 == plVar10[1]) {
        if (uVar9 != 0) {
          puVar7 = puVar6;
          do {
            if ((*(char *)((longlong)puVar7 + (lVar8 - (longlong)puVar6)) == -1) &&
               (puVar5 = (uint *)(*plVar10 + -(longlong)puVar6 + (longlong)puVar7), puVar5 != puVar7
               )) {
              FUN_00001000(puVar5,puVar7,1);
            }
            puVar7 = (uint *)((longlong)puVar7 + 1);
          } while ((ulonglong)(-(longlong)puVar6 + (longlong)puVar7) < uVar9);
          goto LAB_0001235d;
        }
      }
      else {
LAB_0001235d:
        if (uVar11 < uVar1 - 1) {
          puVar6 = (uint *)((longlong)puVar6 + uVar9);
          lVar8 = lVar8 + uVar9;
        }
      }
      uVar11 = uVar11 + 1;
    } while (uVar11 < uVar1);
  }
  return 0;
}

