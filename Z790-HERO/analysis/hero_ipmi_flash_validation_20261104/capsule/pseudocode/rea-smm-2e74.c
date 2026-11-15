
undefined8 FUN_00002e74(longlong param_1,longlong param_2,ulonglong param_3,undefined8 param_4)

{
  longlong lVar1;
  ulonglong *puVar2;
  uint uVar3;
  longlong lVar4;
  longlong lVar5;
  undefined8 uVar6;
  uint *puVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  ulonglong uVar12;
  longlong lVar13;
  ulonglong *puVar14;
  
  lVar4 = DAT_000057a8;
  uVar10 = 0;
  lVar1 = param_1 + (ulonglong)*(ushort *)(param_1 + 0x1e);
  uVar8 = (ulonglong)
          (longlong)(int)((uint)*(ushort *)(param_1 + 0x1c) - (uint)*(ushort *)(param_1 + 0x1e)) /
          0x18;
  if (uVar8 != 0) {
    puVar7 = (uint *)(lVar1 + 0x14);
    lVar13 = 0;
    do {
      lVar5 = lVar13;
      if (puVar7[-2] == 0) break;
      uVar3 = *puVar7;
      puVar7 = puVar7 + 6;
      uVar10 = uVar10 + 1;
      lVar5 = lVar13 + 1;
      if ((uVar3 & 0x200) == 0) {
        lVar5 = lVar13;
      }
      lVar13 = lVar5;
    } while (uVar10 < uVar8);
    if (lVar5 != 0) {
      uVar11 = lVar5 + 2;
      uVar8 = 0;
      uVar12 = 0;
      puVar2 = (ulonglong *)(DAT_000057a8 + uVar11 * 8);
      if (uVar10 != 0) {
        puVar7 = (uint *)(lVar1 + 8);
        lVar13 = DAT_000057a8 - (longlong)puVar2;
        puVar14 = puVar2;
        do {
          if (uVar11 <= uVar8) {
            return 0x800000000000001a;
          }
          if (puVar7[1] == 0) break;
          if ((puVar7[3] & 0x200) != 0) {
            uVar9 = (ulonglong)*puVar7;
            if (param_3 < uVar9) {
              return 0x800000000000001a;
            }
            if (param_3 < puVar7[1] + uVar9) {
              return 0x800000000000001a;
            }
            uVar8 = uVar8 + 1;
            *(ulonglong *)(lVar13 + (longlong)puVar14) = uVar9 + param_2;
            *puVar14 = (ulonglong)puVar7[1];
            puVar14 = puVar14 + 1;
          }
          uVar12 = uVar12 + 1;
          puVar7 = puVar7 + 6;
        } while (uVar12 < uVar10);
      }
      if (uVar8 < uVar11) {
        if ((*(byte *)(param_1 + 0x14) & 2) != 0) {
          *(longlong *)(lVar4 + uVar8 * 8) = param_1;
          puVar2[uVar8] = 0x38;
          uVar8 = uVar8 + 1;
          if (uVar11 <= uVar8) {
            return 0x800000000000001a;
          }
        }
        *(longlong *)(lVar4 + uVar8 * 8) = lVar1;
        puVar2[uVar8] = (uVar12 + 1) * 0x18;
        uVar6 = (**(code **)(DAT_00005a40 + 0x10))
                          (DAT_00005a40,param_4,uVar8 + 1,lVar4,puVar2,&DAT_00005a00);
        return uVar6;
      }
    }
  }
  return 0x800000000000001a;
}

