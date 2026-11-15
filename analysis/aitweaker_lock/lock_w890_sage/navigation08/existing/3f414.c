
undefined8 NA06_3f414(longlong param_1,longlong param_2,uint *param_3)

{
  uint uVar1;
  longlong lVar2;
  undefined8 uVar3;
  uint *puVar4;
  uint uVar5;
  uint uVar6;
  ulonglong uVar7;
  longlong lVar8;
  uint *puVar9;
  
  lVar2 = DAT_000babc0;
  uVar1 = *(uint *)(param_1 + 0x1c);
  uVar5 = 0;
  if ((*param_3 != 0) && (uVar7 = 0, uVar5 = 0, uVar1 != 0)) {
    do {
      if ((uint)*(ushort *)((ulonglong)*(uint *)(param_1 + 0x20 + uVar7 * 4) + 0xc + DAT_000bab08)
          == *param_3) break;
      uVar6 = (int)uVar7 + 1;
      uVar7 = (ulonglong)uVar6;
    } while (uVar6 < uVar1);
    if ((uint)uVar7 < uVar1) {
      uVar5 = (uint)uVar7 + 1;
    }
  }
  if (uVar5 < uVar1) {
    puVar9 = (uint *)(param_1 + ((ulonglong)uVar5 + 8) * 4);
    lVar8 = DAT_000bab08;
    do {
      puVar4 = (uint *)((ulonglong)*puVar9 + lVar8);
      if ((puVar4[7] >> 5 & 1) != 0) {
        if (DAT_00093aa0 == 1) {
          if (param_2 - 2U < 2) {
            uVar3 = FUN_00036b48((longlong)puVar4);
            lVar8 = DAT_000bab08;
            if ((char)uVar3 != '\0') goto LAB_0003f534;
            goto LAB_0003f4cc;
          }
        }
        else {
LAB_0003f4cc:
          if (((DAT_00093aa0 == 2) && (param_2 - 2U < 2)) &&
             (((uVar3 = FUN_00036b48((longlong)puVar4), (char)uVar3 != '\0' &&
               (lVar8 = DAT_000bab08, (puVar4[7] & 1) == 0)) ||
              (uVar3 = FUN_00036b48((longlong)puVar4), lVar8 = DAT_000bab08, (char)uVar3 == '\0'))))
          goto LAB_0003f534;
        }
        uVar6 = puVar4[3];
        FUN_0003f26c((undefined8 *)0x0);
        NA06_3e700(puVar4,(ushort)puVar4[3],0,(undefined1 *)param_2);
        if ((DAT_000afd19 != '\0') || (lVar8 = DAT_000bab08, lVar2 != DAT_000babc0)) {
          DAT_000afd19 = 0;
          *param_3 = (uint)(ushort)uVar6;
          return 0x8000000000000006;
        }
      }
LAB_0003f534:
      uVar5 = uVar5 + 1;
      puVar9 = puVar9 + 1;
    } while (uVar5 < uVar1);
  }
  return 0;
}

