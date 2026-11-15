
void thunk_FUN_0001f4ac(longlong param_1,longlong param_2)

{
  uint *puVar1;
  byte *pbVar2;
  ulonglong uVar3;
  bool bVar4;
  char cVar5;
  byte bVar6;
  uint uVar7;
  uint *puVar8;
  uint *puVar9;
  undefined8 *puVar10;
  uint *puVar11;
  ushort *puVar12;
  ushort *puVar13;
  int *piVar14;
  byte *pbVar15;
  longlong lVar16;
  ushort uVar17;
  uint uVar18;
  ulonglong uVar19;
  longlong *plVar21;
  undefined8 uVar22;
  uint *puVar23;
  ulonglong uVar24;
  longlong *plVar25;
  short sStackX_10;
  uint uStackX_18;
  ushort auStack_48 [4];
  undefined8 uStack_40;
  ulonglong uVar20;
  
  uVar22 = DAT_000afcd0;
  uVar20 = 0;
  sStackX_10 = 0;
  uStack_40 = DAT_000afcd0;
  DAT_000afcd0 = 7;
  if ((param_2 != 0) && (cVar5 = FUN_0002ae44(param_2,3), cVar5 != '\0')) {
    DAT_000afcd0 = uVar22;
    return;
  }
  DAT_000afd88 = 1;
  if (DAT_000bab30 != (short *)0x0) {
    bVar4 = false;
    uVar24 = uVar20;
    if (DAT_000bab90 != 0) {
      do {
        if ((short *)(DAT_000bab88 + uVar24 * 0x48) == DAT_000bab30) {
          bVar4 = true;
        }
        uVar24 = (ulonglong)((int)uVar24 + 1);
      } while (uVar24 < DAT_000bab90);
      if (bVar4) {
        sStackX_10 = *DAT_000bab30;
        goto LAB_0001f56a;
      }
    }
    DAT_000bab30 = (short *)0x0;
  }
LAB_0001f56a:
  uStackX_18 = 0;
  puVar23 = DAT_000baaf0;
  if (*DAT_000baaf0 != 0) {
    do {
      uVar24 = 0;
      plVar25 = (longlong *)((ulonglong)puVar23[uVar20 + 1] + DAT_000babc0);
      uVar18 = (uint)uVar20;
      if ((*plVar25 != 0) && (*(int *)((longlong)plVar25 + 0x1c) != 0)) {
        do {
          puVar11 = (uint *)0x0;
          puVar23 = (uint *)((ulonglong)*(uint *)((longlong)plVar25 + uVar24 * 4 + 0x20) +
                            DAT_000bab08);
          if ((puVar23 == (uint *)0x0) ||
             ((*(longlong *)(puVar23 + 10) == 0 || (uVar18 = puVar23[7], (uVar18 & 1) == 0))))
          goto LAB_0001fb53;
          puVar8 = puVar11;
          if ((uVar18 >> 5 & 1) != 0) {
            puVar8 = FUN_0003e700(puVar23,(ushort)puVar23[3],0,&DAT_00001000);
            uVar18 = puVar23[7];
          }
          if ((((uVar18 >> 5 & 1) == 0) || (puVar8 == (uint *)0x8000000000000003)) &&
             ((uVar18 & 0x40) == 0)) {
            uVar20 = (ulonglong)puVar23[2];
            puVar1 = *(uint **)(param_1 + 8 + uVar20 * 0x10);
            if (puVar1 == (uint *)0x0) goto LAB_0001fa0e;
            pbVar2 = *(byte **)(puVar23 + 10);
            if ((short)puVar23[5] == 0xf) {
              bVar6 = *pbVar2;
              pbVar15 = pbVar2;
              while (bVar6 != 9) {
                if (bVar6 == 0x29) goto LAB_0001fb53;
                pbVar15 = pbVar15 + (pbVar15[1] & 0x7f);
                bVar6 = *pbVar15;
              }
              uVar19 = (ulonglong)((uint)(byte)('\x01' << (pbVar15[5] & 3)) * (uint)pbVar2[0xd]);
            }
            else {
              uVar19 = 0;
              if (pbVar2 != (byte *)0x0) {
                bVar6 = *pbVar2;
                if (bVar6 == 5) {
LAB_0001f6ad:
                  uVar19 = (ulonglong)(ushort)(1 << (pbVar2[0xd] & 3));
                }
                else if (bVar6 == 6) {
                  uVar19 = 1;
                }
                else {
                  if (bVar6 == 7) goto LAB_0001f6ad;
                  if (bVar6 == 8) {
                    uVar19 = (ulonglong)
                             ((uint)*(ushort *)(pbVar2 + 0xf) + (uint)*(ushort *)(pbVar2 + 0xf));
                  }
                  else if (bVar6 == 0x1a) {
                    uVar19 = 4;
                  }
                  else if (bVar6 == 0x1b) {
                    uVar19 = 3;
                  }
                  else if (bVar6 == 0x1c) {
                    uVar19 = (ulonglong)(ushort)((ushort)pbVar2[0xe] * 2);
                  }
                }
              }
              uVar19 = uVar19 & 0xffff;
            }
            if ((int)uVar19 == 0) goto LAB_0001fb53;
            uVar17 = 0;
            if (pbVar2 != (byte *)0x0) {
              bVar6 = *pbVar2;
              if (bVar6 < 0xe) {
                if ((bVar6 == 0xd) ||
                   ((((bVar6 == 5 || (bVar6 == 6)) || (bVar6 == 7)) ||
                    ((bVar6 == 8 || (bVar6 == 0xc)))))) {
LAB_0001f744:
                  uVar17 = *(ushort *)(pbVar2 + 10);
                }
              }
              else if (((bVar6 == 0xf) || (bVar6 == 0x1a)) ||
                      ((bVar6 == 0x1b || ((bVar6 == 0x1c || (bVar6 == 0x23)))))) goto LAB_0001f744;
            }
            puVar9 = puVar11;
            if (puVar23[2] < *DAT_000baaf8) {
              puVar9 = (uint *)((ulonglong)DAT_000baaf8[uVar20 + 1] + (longlong)DAT_000baaf8);
            }
            if ((puVar9[0x1a] & 0x2000) == 0) {
              puVar11 = (uint *)(ulonglong)uVar17;
            }
            uVar18 = (uint)puVar11;
            if ((uVar18 != 0xffff) &&
               ((puVar9 = DAT_000baaf8, (puVar23[7] & 0x80000) != 0 ||
                (puVar9 = (uint *)(ulonglong)(uVar18 + (int)uVar19), puVar9 <= puVar1)))) {
              if ((*(longlong *)(param_1 + uVar20 * 0x10) != 0) &&
                 (*(longlong *)(DAT_000afcd8 + uVar20 * 0x10) == 0)) {
                puVar10 = FUN_00059b50(puVar9,*(ulonglong *)(param_1 + 8 + uVar20 * 0x10));
                *(undefined8 **)(DAT_000afcd8 + (ulonglong)puVar23[2] * 0x10) = puVar10;
                *(undefined8 *)(DAT_000afcd8 + 8 + (ulonglong)puVar23[2] * 0x10) =
                     *(undefined8 *)(param_1 + 8 + (ulonglong)puVar23[2] * 0x10);
                uVar20 = (ulonglong)puVar23[2];
              }
              uVar7 = (uint)uVar20;
              if ((0x39 < uVar7) || ((0x3800000033ca64aU >> (uVar20 & 0x3f) & 1) == 0)) {
                lVar16 = uVar20 * 0x10;
                if ((*(longlong *)(lVar16 + param_1) == 0) ||
                   ((uVar3 = *(ulonglong *)(lVar16 + 8 + param_1), uVar3 == 0 ||
                    ((uVar7 - 7 & 0xffffffef) != 0)))) {
                  if ((uVar7 != 8) &&
                     ((*(longlong *)(lVar16 + param_1) != 0 &&
                      (uVar3 = *(ulonglong *)(lVar16 + 8 + param_1), uVar3 != 0)))) {
                    plVar21 = (longlong *)(DAT_000afcd8 + lVar16);
                    if ((ulonglong)plVar21[1] < uVar3) {
                      if ((plVar21 != (longlong *)0x0) && (lVar16 = *plVar21, lVar16 != 0)) {
                        (**(code **)(DAT_000afbc8 + 0x48))();
                        *plVar21 = 0;
                        uVar20 = (ulonglong)puVar23[2];
                      }
                      puVar10 = FUN_00059b50(lVar16,*(ulonglong *)(param_1 + 8 + uVar20 * 0x10));
                      *(undefined8 **)(DAT_000afcd8 + (ulonglong)puVar23[2] * 0x10) = puVar10;
                      lVar16 = *(longlong *)(param_1 + 8 + (ulonglong)puVar23[2] * 0x10);
                      *(longlong *)(DAT_000afcd8 + 8 + (ulonglong)puVar23[2] * 0x10) = lVar16;
                    }
                    if ((puVar23[7] & 0x80000) == 0) {
                      (**(code **)(DAT_000afbc8 + 0x160))
                                (*(longlong *)(DAT_000afcd8 + (ulonglong)puVar23[2] * 0x10) +
                                 (longlong)puVar11);
                    }
                    else {
                      puVar11 = (uint *)FUN_00059b50(lVar16,uVar19);
                      FUN_0001cfd0(0,param_1,puVar23[2],uVar18,uVar19,puVar11,
                                   *(char **)(puVar23 + 10));
                      FUN_0001cfd0(1,DAT_000afcd8,puVar23[2],uVar18,uVar19,puVar11,
                                   *(char **)(puVar23 + 10));
                      if (puVar11 != (uint *)0x0) {
                        (**(code **)(DAT_000afbc8 + 0x48))(puVar11);
                      }
                    }
                  }
                }
                else {
                  plVar21 = (longlong *)(DAT_000afcd8 + lVar16);
                  if ((ulonglong)plVar21[1] < uVar3) {
                    if ((plVar21 != (longlong *)0x0) && (lVar16 = *plVar21, lVar16 != 0)) {
                      (**(code **)(DAT_000afbc8 + 0x48))();
                      *plVar21 = 0;
                      uVar20 = (ulonglong)puVar23[2];
                    }
                    puVar10 = FUN_00059b50(lVar16,*(ulonglong *)(param_1 + 8 + uVar20 * 0x10));
                    *(undefined8 **)(DAT_000afcd8 + (ulonglong)puVar23[2] * 0x10) = puVar10;
                  }
                  (**(code **)(DAT_000afbc8 + 0x160))
                            (*(undefined8 *)(DAT_000afcd8 + (ulonglong)puVar23[2] * 0x10),
                             *(undefined8 *)(param_1 + (ulonglong)puVar23[2] * 0x10));
                  *(undefined8 *)(DAT_000afcd8 + 8 + (ulonglong)puVar23[2] * 0x10) =
                       *(undefined8 *)(param_1 + 8 + (ulonglong)puVar23[2] * 0x10);
                }
                goto LAB_0001fa0e;
              }
            }
          }
          else {
LAB_0001fa0e:
            lVar16 = 0;
            if ((((puVar23[7] >> 5 & 1) == 0) || (puVar8 != (uint *)0x0)) &&
               ((puVar23[7] & 0x40) != 0)) {
              pbVar2 = *(byte **)(puVar23 + 10);
              uVar18 = 0;
              auStack_48[0] = 0;
              auStack_48[1] = 0;
              auStack_48[2] = 0;
              auStack_48[3] = 0;
              if (pbVar2 != (byte *)0x0) {
                bVar6 = *pbVar2;
                if (bVar6 < 0xe) {
                  if ((bVar6 == 0xd) ||
                     ((((bVar6 == 5 || (bVar6 == 6)) || (bVar6 == 7)) ||
                      ((bVar6 == 8 || (bVar6 == 0xc)))))) {
LAB_0001fa7b:
                    uVar18 = (uint)*(ushort *)(pbVar2 + 10);
                  }
                }
                else if (((bVar6 == 0xf) || (bVar6 == 0x1a)) ||
                        ((bVar6 == 0x1b || ((bVar6 == 0x1c || (bVar6 == 0x23))))))
                goto LAB_0001fa7b;
              }
              uVar7 = FUN_000499cc((longlong)puVar23,auStack_48);
              uVar20 = (ulonglong)(uVar7 & 0xffff);
              puVar12 = auStack_48;
              if ((short)puVar23[5] == 0x13) {
                if ((auStack_48[0] == 0xffff) ||
                   (puVar12 = (ushort *)
                              FUN_0004bc70(*(longlong *)puVar23,auStack_48[0],(short *)0x0),
                   puVar13 = puVar12, puVar12 == (ushort *)0x0)) goto LAB_0001fb53;
                for (; *puVar13 != 0; puVar13 = puVar13 + 1) {
                  lVar16 = lVar16 + 1;
                }
                uVar20 = lVar16 * 2 + 2;
              }
              FUN_0001ccbc(puVar23[2],uVar18,uVar20,puVar12);
              FUN_0001cde4(1,DAT_000afce8,puVar23[2],uVar18,uVar20,(undefined1 *)puVar12);
              if ((short)puVar23[5] == 0x13) {
                (**(code **)(DAT_000afbc8 + 0x48))(puVar12);
              }
            }
            if ((puVar23[7] & 0x20000) != 0) {
              FUN_00049b78((longlong *)puVar23);
              FUN_00049d50((uint)*(ushort *)((longlong)puVar23 + 0x16));
            }
          }
LAB_0001fb53:
          uVar7 = (int)uVar24 + 1;
          uVar24 = (ulonglong)uVar7;
          puVar23 = DAT_000baaf0;
          uVar18 = uStackX_18;
        } while (uVar7 < *(uint *)((longlong)plVar25 + 0x1c));
      }
      uStackX_18 = uVar18 + 1;
      uVar20 = (ulonglong)uStackX_18;
      uVar22 = uStack_40;
    } while (uStackX_18 < *puVar23);
  }
  uVar20 = 0;
  FUN_00010704(&DAT_000935c8);
  DAT_000afd88 = 0;
  DAT_000bab30 = FUN_00013298(sStackX_10);
  if (DAT_000bab30 != (short *)0x0) {
    FUN_0001ccbc(0xf,0,2,(ushort *)(DAT_000bab30 + 0x1c));
  }
  DAT_000afdc8 = 1;
  FUN_0000fd18(0xffff000e,&LAB_000069ec);
  if (DAT_000afdd0 != 0) {
    *(undefined1 *)(DAT_000afdd0 + 0x58) = 1;
    piVar14 = (int *)PTR_DAT_00094670;
    do {
      if (*piVar14 == 0) break;
      uVar18 = (int)uVar20 + 1;
      uVar20 = (ulonglong)uVar18;
      piVar14 = piVar14 + 6;
    } while (uVar18 < 6);
    lVar16 = *(longlong *)
              (*(longlong *)
                (*(longlong *)
                  (*(longlong *)(DAT_000afdd0 + 0x30) +
                  (ulonglong)*(uint *)(DAT_000afdd0 + 0x28) * 8) + 0x50) + uVar20 * 8);
    if (((*(int *)(lVar16 + 0x3c) != 0) && (*(int *)(lVar16 + 0x44) != -1)) &&
       (lVar16 = *(longlong *)
                  (*(longlong *)(lVar16 + 0x48) + (ulonglong)*(uint *)(lVar16 + 0x44) * 8),
       *(char *)(lVar16 + 0x6b) == '\x01')) {
      *(undefined1 *)(lVar16 + 0x6b) = 0;
    }
  }
  DAT_000afcd0 = uVar22;
  return;
}

