undefined8 FUN_000310c8(longlong *param_1,undefined4 param_2)
{
  ushort uVar1;
  undefined8 uVar2;
  longlong *plVar3;
  ushort *puVar4;
  uint uVar5;
  longlong lVar7;
  uint *puVar8;
  uint uVar9;
  uint uVar10;
  ushort uVar11;
  ulonglong uVar12;
  longlong lVar13;
  ulonglong uVar6;
  uVar12 = 0;
  uVar11 = 0;
  uVar10 = 1;
  uVar9 = uVar10;
  if (1 < *DAT_00193638) {
    do {
      plVar3 = (longlong *)((ulonglong)DAT_00193638[(ulonglong)uVar9 + 1] + DAT_00193648);
      if ((*plVar3 == 0xffff) &&
         (*(short *)((longlong)plVar3 + 10) == *(short *)((longlong)param_1 + 10))) {
        if (*(int *)((longlong)plVar3 + 0x1c) == *(int *)((longlong)param_1 + 0x1c)) {
          uVar11 = *(ushort *)(param_1 + 2);
          *plVar3 = *param_1;
          uVar2 = FUN_00031348((longlong)plVar3,param_1,param_2);
          puVar8 = DAT_00193638;
        }
        else {
          puVar8 = DAT_00193638;
          uVar9 = uVar10;
          if (1 < *DAT_00193638) {
            do {
              plVar3 = (longlong *)((ulonglong)puVar8[(ulonglong)uVar9 + 1] + DAT_00193648);
              if ((*plVar3 == *param_1) && (uVar6 = uVar12, *(int *)((longlong)plVar3 + 0x1c) != 0))
              {
                do {
                  lVar13 = (ulonglong)*(uint *)((longlong)plVar3 + uVar6 * 4 + 0x20) + DAT_001937f8;
                  uVar1 = FUN_0002d124((ulonglong)*(ushort *)((longlong)param_1 + 10));
                  if (*(ushort *)(lVar13 + 0x18) == uVar1) {
                    *(short *)(lVar13 + 0x18) = (short)param_1[2];
                  }
                  uVar5 = (int)uVar6 + 1;
                  uVar6 = (ulonglong)uVar5;
                  puVar8 = DAT_00193638;
                } while (uVar5 < *(uint *)((longlong)plVar3 + 0x1c));
              }
              uVar9 = uVar9 + 1;
            } while (uVar9 < *puVar8);
          }
          uVar2 = 0x8000000000000003;
        }
        if (uVar11 == 0) {
          return uVar2;
        }
        puVar4 = DAT_00183768;
        uVar6 = uVar12;
        if (*DAT_00183768 == 0) goto LAB_00031269;
        do {
          if (puVar4[uVar6 * 3 + 1] == *(ushort *)((longlong)param_1 + 10)) {
            uVar1 = *(ushort *)(param_1 + 2);
LAB_00031230:
            puVar4[uVar6 * 3 + 3] = uVar1;
            puVar4 = DAT_00183768;
          }
          else {
            if (puVar4[uVar6 * 3 + 2] == uVar11) {
              puVar4[uVar6 * 3 + 2] = *(ushort *)(param_1 + 2);
              puVar4 = DAT_00183768;
            }
            if (uVar11 < puVar4[uVar6 * 3 + 3]) {
              uVar1 = puVar4[uVar6 * 3 + 3] - 1;
              goto LAB_00031230;
            }
          }
          if (uVar11 < puVar4[uVar6 * 3 + 2]) {
            puVar4[uVar6 * 3 + 2] = puVar4[uVar6 * 3 + 2] - 1;
            puVar4 = DAT_00183768;
          }
          uVar9 = (int)uVar6 + 1;
          uVar6 = (ulonglong)uVar9;
          puVar8 = DAT_00193638;
          if (*puVar4 <= uVar9) {
LAB_00031269:
            uVar9 = uVar10;
            if (1 < *puVar8) {
              do {
                plVar3 = (longlong *)((ulonglong)puVar8[(ulonglong)uVar9 + 1] + DAT_00193648);
                if (*plVar3 == *param_1) {
                  if (*(ushort *)((longlong)plVar3 + 0x12) == uVar11) {
                    *(short *)((longlong)plVar3 + 0x12) = (short)param_1[2];
                    puVar8 = DAT_00193638;
                  }
                  if (uVar11 < *(ushort *)((longlong)plVar3 + 0x12)) {
                    *(ushort *)((longlong)plVar3 + 0x12) = *(ushort *)((longlong)plVar3 + 0x12) - 1;
                    puVar8 = DAT_00193638;
                  }
                }
                uVar9 = uVar9 + 1;
              } while (uVar9 < *puVar8);
            }
            lVar13 = *param_1;
            if (*puVar8 < 2) {
              return uVar2;
            }
            do {
              plVar3 = (longlong *)((ulonglong)puVar8[(ulonglong)uVar10 + 1] + DAT_00193648);
              if ((*plVar3 == lVar13) && (uVar6 = uVar12, *(int *)((longlong)plVar3 + 0x1c) != 0)) {
                do {
                  lVar7 = (ulonglong)*(uint *)((longlong)plVar3 + uVar6 * 4 + 0x20) + DAT_001937f8;
                  uVar1 = *(ushort *)(lVar7 + 0x18);
                  if ((uVar11 < uVar1) && (uVar1 != 0xffff)) {
                    *(ushort *)(lVar7 + 0x18) = uVar1 - 1;
                  }
                  uVar9 = (int)uVar6 + 1;
                  uVar6 = (ulonglong)uVar9;
                  puVar8 = DAT_00193638;
                } while (uVar9 < *(uint *)((longlong)plVar3 + 0x1c));
              }
              uVar10 = uVar10 + 1;
            } while (uVar10 < *puVar8);
            return uVar2;
          }
        } while( true );
      }
      uVar9 = uVar9 + 1;
    } while (uVar9 < *DAT_00193638);
  }
  return 0;
}