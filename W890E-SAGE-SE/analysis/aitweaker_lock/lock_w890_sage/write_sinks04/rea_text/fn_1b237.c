
void FUN_0001b1b0(longlong param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  longlong lVar4;
  longlong lVar5;
  undefined8 *puVar6;
  undefined8 *puVar7;
  int *piVar8;
  int *piVar9;
  undefined8 uVar10;
  uint uVar11;
  longlong lVar12;
  ulonglong uVar14;
  longlong *plVar15;
  ulonglong uVar16;
  uint uVar17;
  uint uVar18;
  int iVar19;
  bool bVar20;
  ulonglong uVar13;
  
  uVar13 = 0;
  uVar16 = (ulonglong)param_2;
  if (DAT_000afdd0 == 0) {
    if (DAT_000baab0 != '\0') {
      DAT_00093aa0 = 2;
      FUN_000456d0(param_1);
      DAT_00093aa0 = 0;
    }
  }
  else {
    if (param_2 < *DAT_000baaf8) {
      uVar14 = uVar16 << 4;
      DAT_000afcd8 = FUN_0000fc40((longlong)DAT_000afcd8,uVar14,(ulonglong)*DAT_000baaf8 << 4);
      DAT_000afce8 = FUN_0000fc40((longlong)DAT_000afce8,uVar14,(ulonglong)*DAT_000baaf8 << 4);
      DAT_000afd20 = FUN_0000fc40((longlong)DAT_000afd20,uVar14,(ulonglong)*DAT_000baaf8 << 4);
      if (param_2 < *DAT_000baaf8) {
        do {
          puVar6 = FUN_0001c6d0(uVar16,DAT_000afcd8 + uVar16 * 2 + 1);
          puVar7 = DAT_000afcd8;
          DAT_000afcd8[uVar16 * 2] = puVar6;
          if (DAT_000afcd8[uVar16 * 2 + 1] == 0) {
            DAT_000afd20[uVar16 * 2] = 0;
            DAT_000afce8[uVar16 * 2] = 0;
LAB_0001b397:
            DAT_000afd20[uVar16 * 2 + 1] = DAT_000afcd8[uVar16 * 2 + 1];
            DAT_000afce8[uVar16 * 2 + 1] = DAT_000afcd8[uVar16 * 2 + 1];
          }
          else {
            puVar7 = FUN_00059b50(puVar7,DAT_000afcd8[uVar16 * 2 + 1]);
            DAT_000afce8[uVar16 * 2] = puVar7;
            if (DAT_000afce8[uVar16 * 2] != 0) {
              plVar15 = DAT_000afcd8 + uVar16 * 2;
              lVar12 = *plVar15;
              if (lVar12 == 0) {
                puVar7 = FUN_00059b50(DAT_000afce8,plVar15[1]);
                DAT_000afcd8[uVar16 * 2] = puVar7;
                plVar15 = DAT_000afcd8 + uVar16 * 2;
                lVar12 = *plVar15;
                if (lVar12 == 0) goto LAB_0001b3c7;
              }
              uVar10 = DAT_000afce8[uVar16 * 2];
              (**(code **)(DAT_000afbc8 + 0x160))(uVar10,lVar12,plVar15[1]);
              puVar7 = FUN_00059b50(uVar10,DAT_000afcd8[uVar16 * 2 + 1]);
              DAT_000afd20[uVar16 * 2] = puVar7;
              (**(code **)(DAT_000afbc8 + 0x160))
                        (puVar7,DAT_000afcd8[uVar16 * 2],DAT_000afcd8[uVar16 * 2 + 1]);
              goto LAB_0001b397;
            }
          }
LAB_0001b3c7:
          uVar18 = (int)uVar16 + 1;
          uVar16 = (ulonglong)uVar18;
        } while (uVar18 < *DAT_000baaf8);
      }
    }
    DAT_00093aa0 = 2;
    FUN_000456d0(param_1);
    DAT_00093aa0 = 0;
    uVar18 = *(uint *)(DAT_000afdd0 + 0x28);
    piVar8 = (int *)PTR_DAT_00094670;
    do {
      if (*piVar8 == 0) break;
      uVar11 = (int)uVar13 + 1;
      uVar13 = (ulonglong)uVar11;
      piVar8 = piVar8 + 6;
    } while (uVar11 < 6);
    uVar16 = 1;
    lVar12 = *(longlong *)
              (*(longlong *)
                (*(longlong *)(*(longlong *)(DAT_000afdd0 + 0x30) + (ulonglong)uVar18 * 8) + 0x50) +
              uVar13 * 8);
    iVar2 = *(int *)(lVar12 + 0x3c);
    uVar11 = *(uint *)(lVar12 + 0x44);
    uVar3 = *(undefined4 *)(lVar12 + 0x5c);
    lVar12 = DAT_000afdd0;
    if (1 < *DAT_000baaf0) {
      do {
        plVar15 = (longlong *)((ulonglong)DAT_000baaf0[uVar16 + 1] + DAT_000babc0);
        if ((*plVar15 == param_1) || (*plVar15 == 0xffff)) {
          uVar17 = 1;
          bVar20 = *(uint *)(lVar12 + 0x2c) == 1;
          if (1 < *(uint *)(lVar12 + 0x2c)) {
            do {
              lVar4 = *(longlong *)(*(longlong *)(lVar12 + 0x30) + (ulonglong)uVar17 * 8);
              if (((lVar4 != 0) && (*(longlong *)(lVar4 + 0x20) == param_1)) &&
                 (*(short *)((longlong)plVar15 + 10) == *(short *)(lVar4 + 0x2a))) {
                (*(code *)PTR_FUN_00093de8)(lVar4);
                if (*plVar15 == 0xffff) {
                  *(undefined8 *)(lVar4 + 0x20) = 0;
                  lVar12 = DAT_000afdd0;
                }
                else {
                  if (((*(byte *)((longlong)plVar15 + 0x14) & 0x20) != 0) &&
                     (*(short *)((longlong)plVar15 + 0x12) == 0)) {
                    *(undefined2 *)((longlong)plVar15 + 0x12) = DAT_000afde4;
                  }
                  (*(code *)PTR_FUN_00093df0)
                            (*(undefined8 *)
                              (*(longlong *)(DAT_000afdd0 + 0x30) + (ulonglong)uVar17 * 8),plVar15);
                  FUN_0001a91c((longlong)plVar15,param_2);
                  lVar12 = DAT_000afdd0;
                }
                break;
              }
              uVar17 = uVar17 + 1;
            } while (uVar17 < *(uint *)(lVar12 + 0x2c));
            bVar20 = uVar17 == *(uint *)(lVar12 + 0x2c);
          }
          if (bVar20) {
            (*(code *)PTR_FUN_00093d20)(lVar12,plVar15);
            FUN_0001a91c((longlong)plVar15,param_2);
            lVar12 = DAT_000afdd0;
          }
        }
        uVar17 = (int)uVar16 + 1;
        uVar16 = (ulonglong)uVar17;
      } while (uVar17 < *DAT_000baaf0);
    }
    piVar8 = (int *)PTR_DAT_00094670;
    uVar13 = 0;
    lVar4 = *(longlong *)(*(longlong *)(lVar12 + 0x30) + (ulonglong)*(uint *)(lVar12 + 0x28) * 8);
    piVar9 = piVar8;
    if (*(longlong *)(lVar4 + 0x20) == 0) {
      uVar17 = 1;
      uVar16 = uVar13;
      uVar14 = uVar13;
      while( true ) {
        uVar1 = *(uint *)(lVar12 + 0x2c);
        iVar19 = (int)uVar14;
        if (uVar1 <= uVar17) break;
        lVar5 = *(longlong *)(*(longlong *)(lVar12 + 0x30) + (ulonglong)uVar17 * 8);
        if (lVar5 != 0) {
          if (*(longlong *)(lVar5 + 0x20) == param_1) {
            if (*(short *)(lVar4 + 0x2a) == *(short *)(lVar5 + 0x2a)) {
              *(uint *)(lVar12 + 0x28) = uVar17;
              uVar1 = *(uint *)(DAT_000afdd0 + 0x2c);
              lVar12 = DAT_000afdd0;
              uVar18 = uVar17;
              break;
            }
            if (*(short *)(lVar5 + 0x32) == 0) {
              uVar16 = (ulonglong)*(ushort *)(lVar5 + 0x30);
            }
          }
          if (((*(longlong *)(lVar5 + 0x20) != 0) && (iVar19 == 0)) &&
             ((*(byte *)(lVar5 + 0x34) & 1) == 0)) {
            uVar14 = (ulonglong)uVar17;
          }
        }
        uVar17 = uVar17 + 1;
      }
      if (uVar17 == uVar1) {
        if ((int)uVar16 == 0) {
          if (iVar19 != 0) {
            *(int *)(lVar12 + 0x28) = iVar19;
            lVar12 = DAT_000afdd0;
          }
        }
        else {
          *(int *)(lVar12 + 0x28) = (int)uVar16;
          lVar12 = DAT_000afdd0;
        }
      }
      *(undefined1 *)(lVar12 + 0x58) = 1;
      lVar12 = DAT_000afdd0;
    }
    do {
      if (*piVar9 == 4) break;
      uVar17 = (int)uVar13 + 1;
      uVar13 = (ulonglong)uVar17;
      piVar9 = piVar9 + 6;
    } while (uVar17 < 6);
    uVar16 = 1;
    if (1 < *(uint *)(lVar12 + 0x2c)) {
      do {
        lVar4 = *(longlong *)(*(longlong *)(lVar12 + 0x30) + uVar16 * 8);
        if ((lVar4 != 0) && (*(longlong *)(lVar4 + 0x20) != 0)) {
          uVar10 = 0;
          (*(code *)PTR_FUN_00093d90)(*(undefined8 *)(*(longlong *)(lVar4 + 0x50) + uVar13 * 8));
          FUN_0004b424(*(longlong *)(*(longlong *)(lVar4 + 0x50) + uVar13 * 8),uVar10,lVar4 + 0x20);
          lVar12 = DAT_000afdd0;
        }
        uVar17 = (int)uVar16 + 1;
        uVar16 = (ulonglong)uVar17;
        piVar8 = (int *)PTR_DAT_00094670;
      } while (uVar17 < *(uint *)(lVar12 + 0x2c));
    }
    uVar13 = 0;
    if (uVar18 == *(uint *)(lVar12 + 0x28)) {
      do {
        if (*piVar8 == 0) break;
        uVar18 = (int)uVar13 + 1;
        uVar13 = (ulonglong)uVar18;
        piVar8 = piVar8 + 6;
      } while (uVar18 < 6);
      lVar12 = *(longlong *)
                (*(longlong *)
                  (*(longlong *)
                    (*(longlong *)(lVar12 + 0x30) + (ulonglong)*(uint *)(lVar12 + 0x28) * 8) + 0x50)
                + uVar13 * 8);
      if (*(int *)(lVar12 + 0x3c) == iVar2) {
        *(undefined4 *)(lVar12 + 0x5c) = uVar3;
        *(uint *)(lVar12 + 0x44) = uVar11;
        FUN_00022d54(lVar12,uVar11);
      }
    }
  }
  return;
}

