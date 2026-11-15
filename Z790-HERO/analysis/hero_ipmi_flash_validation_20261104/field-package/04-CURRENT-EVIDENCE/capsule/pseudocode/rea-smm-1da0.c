
undefined8 FUN_00001da0(ulonglong param_1,ulonglong param_2,longlong *param_3,longlong param_4)

{
  longlong lVar1;
  ulonglong uVar2;
  ulonglong *puVar3;
  longlong lVar4;
  longlong lVar5;
  longlong lVar6;
  ulonglong uVar7;
  ulonglong local_28;
  longlong local_20;
  
  if ((((DAT_00005210 == 0) || (DAT_00005228 == 0)) || (DAT_00005228 != *DAT_000057a8)) ||
     (puVar3 = DAT_00005218, *DAT_000057a8 == -0x24242425)) {
    return 0x8000000000000008;
  }
  do {
    if (puVar3 == (ulonglong *)0x0) {
      return 0x8000000000000008;
    }
    if (*(int *)((longlong)puVar3 + 0xc) == 0) {
      return 0x8000000000000008;
    }
    if (param_1 < *puVar3) {
LAB_00001e2e:
      if (*puVar3 < param_1 + param_2) {
LAB_00001e3d:
        if ((*(uint *)((longlong)puVar3 + 0x14) & 0x200) == 0) {
          if (param_4 == 0) {
            return 0;
          }
          if ((*(uint *)(param_4 + 0x14) & 0x200) == 0) {
            return 0;
          }
        }
        if (*(int *)((longlong)puVar3 + 0xc) == 0) {
          return 0x8000000000000008;
        }
        local_20 = 0x1000;
        uVar2 = ((ulonglong)(uint)puVar3[1] - *puVar3) + param_1;
        uVar7 = uVar2 >> 0xc;
        local_28 = uVar7 * 0x1000 + DAT_00005210;
        lVar6 = DAT_00005210 + uVar2;
        lVar5 = (ulonglong)(param_2 % 0x1000 != 0) + param_2 / 0x1000;
        if (lVar5 != 0) {
          lVar4 = uVar7 << 5;
          do {
            lVar5 = lVar5 + -1;
            if (0x1fff < uVar7) {
              return 0x8000000000000008;
            }
            if (lVar6 + param_2 <= local_28) {
              return 0x8000000000000008;
            }
            lVar1 = (**(code **)(DAT_00005a40 + 0x10))
                              (DAT_00005a40,&DAT_00005030,1,&local_28,&local_20,&DAT_00005a00);
            if (lVar1 < 0) {
              return 0x8000000000000008;
            }
            lVar1 = FUN_00004650((longlong *)&DAT_00005a00,
                                 (longlong *)((longlong)DAT_000057a8 + lVar4),0x20);
            if (lVar1 != 0) {
              return 0x8000000000000008;
            }
            uVar7 = uVar7 + 1;
            local_28 = local_28 + local_20;
            lVar4 = lVar4 + 0x20;
          } while (lVar5 != 0);
        }
        if (param_3 != (longlong *)0x0) {
          *param_3 = lVar6;
        }
        return 0;
      }
    }
    else {
      if (param_1 < (ulonglong)*(uint *)((longlong)puVar3 + 0xc) + *puVar3) goto LAB_00001e3d;
      if (param_1 <= *puVar3) goto LAB_00001e2e;
    }
    puVar3 = puVar3 + 3;
  } while( true );
}

