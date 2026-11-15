ulonglong FUN_0002d2ec(byte *param_1,longlong param_2)
{
  byte bVar1;
  bool bVar2;
  longlong lVar3;
  ushort *puVar4;
  undefined8 uVar5;
  ushort *puVar6;
  ulonglong uVar7;
  ushort uVar8;
  ulonglong uVar9;
  byte *pbVar10;
  ushort uVar11;
  ushort uVar12;
  ulonglong uVar13;
  ushort uVar14;
  ushort uVar15;
  ulonglong uVar16;
  longlong lVar17;
  char cVar18;
  ulonglong uVar19;
  ulonglong uVar20;
  ushort *local_res8 [3];
  ulonglong local_res20;
  longlong local_68;
  ulonglong local_60;
  longlong local_58;
  uVar13 = 0;
  local_res20 = 0;
  local_res8[0] = (ushort *)((ulonglong)local_res8[0] & 0xffffffffffffff00);
  local_58 = param_2;
  if (DAT_00183768 != (ushort *)0x0) {
    FUN_000013d0((longlong *)&DAT_00183768);
  }
  uVar16 = 100;
  local_68 = FUN_000014c8(800);
  local_60 = uVar13;
  lVar17 = local_68;
  uVar19 = uVar13;
  uVar20 = uVar13;
  do {
    bVar1 = param_1[uVar20];
    uVar7 = uVar13;
    if (bVar1 == 1) {
      for (; uVar7 < uVar19; uVar7 = uVar7 + 1) {
        if (*(ulonglong *)(lVar17 + uVar7 * 8) == (ulonglong)*(ushort *)(param_1 + uVar20 + 2))
        goto LAB_0002d3ab;
      }
LAB_0002d39e:
      uVar11 = *(ushort *)(param_1 + uVar20 + 2);
LAB_0002d3a4:
      *(ulonglong *)(lVar17 + uVar19 * 8) = (ulonglong)uVar11;
      uVar19 = uVar19 + 1;
    }
    else {
      uVar9 = uVar13;
      if (bVar1 == 0xf) {
        do {
          if (uVar19 <= uVar9) break;
          if (*(ulonglong *)(lVar17 + uVar9 * 8) == (ulonglong)*(ushort *)(param_1 + uVar20 + 0xd))
          {
            uVar7 = 1;
          }
          uVar9 = uVar9 + 1;
        } while (uVar7 == 0);
        if (uVar7 == 0) {
          uVar11 = *(ushort *)(param_1 + uVar20 + 0xd);
          goto LAB_0002d3a4;
        }
      }
      else if (bVar1 == 0x29) {
        local_60 = local_60 - 1;
      }
      else if (bVar1 == 0x5d) {
        do {
          if (uVar19 <= uVar9) break;
          if (*(ulonglong *)(lVar17 + uVar9 * 8) == (ulonglong)*(ushort *)(param_1 + uVar20 + 2)) {
            uVar7 = 1;
          }
          uVar9 = uVar9 + 1;
        } while (uVar7 == 0);
        if (uVar7 == 0) goto LAB_0002d39e;
      }
    }
LAB_0002d3ab:
    uVar7 = local_60 + 1;
    if (param_1[uVar20 + 1] < 0x80) {
      uVar7 = local_60;
    }
    lVar3 = lVar17;
    local_60 = uVar7;
    if (uVar16 <= uVar19) {
      uVar16 = uVar16 + 0x32;
      lVar3 = FUN_000014c8(uVar16 * 8);
      (**(code **)(DAT_00180188 + 0x160))(lVar3,lVar17,uVar19 << 3);
      FUN_000013d0(&local_68);
      local_68 = lVar3;
    }
    uVar20 = uVar20 + (param_1[uVar20 + 1] & 0x7f);
    lVar17 = lVar3;
  } while (local_60 != 0);
  FUN_000013d0(&local_68);
  puVar4 = (ushort *)FUN_000014c8(uVar19 * 6 + 0x7a);
  DAT_00183768 = puVar4;
  if (puVar4 == (ushort *)0x0) {
    uVar13 = 0x8000000000000009;
  }
  else {
    uVar12 = 0;
    cVar18 = '\0';
    uVar19 = uVar13;
    lVar17 = local_58;
    uVar11 = uVar12;
    do {
      bVar1 = *param_1;
      uVar15 = (ushort)lVar17;
      uVar20 = uVar19;
      if (bVar1 == 1) {
        puVar6 = puVar4 + 1;
        for (uVar16 = uVar13; uVar16 < *puVar4; uVar16 = uVar16 + 1) {
          if (*puVar6 == *(ushort *)(param_1 + 2)) {
            puVar4[uVar16 * 3 + 3] = uVar15;
            goto LAB_0002d800;
          }
          puVar6 = puVar6 + 3;
        }
        if (uVar11 == 0) {
          uVar11 = *(ushort *)(param_1 + 2);
        }
        puVar4[(ulonglong)*puVar4 * 3 + 1] = *(ushort *)(param_1 + 2);
        if (uVar11 == *(ushort *)(param_1 + 2)) {
          DAT_00183768[(ulonglong)*DAT_00183768 * 3 + 2] = 0;
        }
        else {
          DAT_00183768[(ulonglong)*DAT_00183768 * 3 + 2] = DAT_00183768[3];
        }
        DAT_00183768[((ulonglong)*DAT_00183768 + 1) * 3] = uVar15;
        *DAT_00183768 = *DAT_00183768 + 1;
LAB_0002d800:
        if (param_1[1] < 0x80) {
LAB_0002d816:
          lVar17 = lVar17 + 1;
          puVar4 = DAT_00183768;
        }
        else {
          uVar20 = uVar19 + 1;
LAB_0002d5b9:
          local_res20 = uVar20;
          lVar17 = lVar17 + 1;
          cVar18 = '\x01';
          local_res8[0] = (ushort *)CONCAT71(local_res8[0]._1_7_,1);
          puVar4 = DAT_00183768;
          uVar20 = uVar19 + 1;
        }
LAB_0002d82d:
        uVar19 = uVar20;
        uVar20 = (ulonglong)(param_1[1] & 0x7f);
      }
      else {
        uVar16 = uVar13;
        uVar7 = uVar13;
        uVar9 = uVar13;
        if (bVar1 == 0xf) {
          do {
            if (*puVar4 <= uVar9) break;
            uVar14 = *(ushort *)(param_1 + 0xd);
            if (*(ushort *)(param_1 + 0xd) == 0) {
              uVar14 = uVar15;
            }
            if (*(ushort *)(uVar7 + 2 + (longlong)puVar4) == uVar14) {
              if ((uVar11 != *(ushort *)(uVar7 + 2 + (longlong)puVar4)) &&
                 ((uint)*(ushort *)(uVar7 + 6 + (longlong)puVar4) != ((uint)lVar17 & 0xffff) - 1)) {
                *(ushort *)(uVar7 + 4 + (longlong)puVar4) = uVar15 - 1;
                puVar4 = DAT_00183768;
              }
              uVar16 = 1;
            }
            uVar7 = uVar7 + 6;
            uVar9 = uVar9 + 1;
          } while (uVar16 == 0);
          if (uVar16 == 0) {
            if (*(short *)(param_1 + 2) == 0) {
              puVar4[(ulonglong)*puVar4 * 3 + 1] = uVar15;
            }
            else {
              puVar4[(ulonglong)*puVar4 * 3 + 1] = *(ushort *)(param_1 + 0xd);
            }
            DAT_00183768[(ulonglong)*DAT_00183768 * 3 + 2] = uVar15 - 1;
            DAT_00183768[((ulonglong)*DAT_00183768 + 1) * 3] = 0;
            *DAT_00183768 = *DAT_00183768 + 1;
            puVar4 = DAT_00183768;
          }
          uVar20 = uVar19 + 1;
          if (param_1[1] < 0x80) {
            uVar20 = uVar19;
          }
          goto LAB_0002d82d;
        }
        if (bVar1 != 0x1e) {
          if (bVar1 == 0x29) {
            uVar20 = uVar19 - 1;
            cVar18 = (char)local_res8[0];
            if (((char)local_res8[0] != '\0') && (uVar20 < local_res20)) {
              local_res20 = 0;
              local_res8[0] = (ushort *)((ulonglong)local_res8[0]._1_7_ << 8);
              cVar18 = '\0';
            }
          }
          else {
            if (bVar1 == 0x5d) {
              puVar6 = puVar4 + 1;
              for (; uVar16 < *puVar4; uVar16 = uVar16 + 1) {
                if (*puVar6 == *(ushort *)(param_1 + 2)) {
                  puVar4[uVar16 * 3 + 3] = uVar15;
                  goto LAB_0002d5a4;
                }
                puVar6 = puVar6 + 3;
              }
              if (uVar11 == 0) {
                uVar11 = *(ushort *)(param_1 + 2);
              }
              puVar4[(ulonglong)*puVar4 * 3 + 1] = *(ushort *)(param_1 + 2);
              if (uVar11 == *(ushort *)(param_1 + 2)) {
                DAT_00183768[(ulonglong)*DAT_00183768 * 3 + 2] = 0;
              }
              else {
                DAT_00183768[(ulonglong)*DAT_00183768 * 3 + 2] = DAT_00183768[3];
              }
              DAT_00183768[((ulonglong)*DAT_00183768 + 1) * 3] = uVar15;
              *DAT_00183768 = *DAT_00183768 + 1;
LAB_0002d5a4:
              if (param_1[1] < 0x80) goto LAB_0002d816;
              goto LAB_0002d5b9;
            }
            if (0x7f < param_1[1]) {
              uVar20 = uVar19 + 1;
            }
          }
          goto LAB_0002d82d;
        }
        if (cVar18 != '\0') {
LAB_0002d675:
          uVar20 = uVar19 + 1;
          if (param_1[1] < 0x80) {
            uVar20 = uVar19;
          }
          goto LAB_0002d82d;
        }
        DAT_0010a760 = 2;
        uVar5 = FUN_0003c3d8(param_1);
        DAT_0010a760 = 0;
        puVar4 = DAT_00183768;
        if ((char)uVar5 == '\0') goto LAB_0002d675;
        pbVar10 = param_1;
        uVar20 = uVar13;
        if (0x7f < param_1[1]) {
          do {
            if (*pbVar10 == 0x29) {
              uVar16 = uVar16 - 1;
            }
            else if (0x7f < pbVar10[1]) {
              uVar16 = uVar16 + 1;
            }
            uVar20 = uVar20 + (pbVar10[1] & 0x7f);
            pbVar10 = pbVar10 + (pbVar10[1] & 0x7f);
          } while (0 < (longlong)uVar16);
        }
      }
      param_1 = param_1 + uVar20;
    } while (uVar19 != 0);
    uVar19 = (ulonglong)*puVar4;
    uVar15 = uVar12;
    if (uVar19 != 0) {
      puVar6 = puVar4 + 1;
      uVar20 = uVar13;
      do {
        if (*puVar6 == uVar11) {
          uVar15 = puVar4[uVar20 * 3 + 3];
          break;
        }
        uVar20 = uVar20 + 1;
        puVar6 = puVar6 + 3;
      } while (uVar20 < uVar19);
    }
    puVar6 = (ushort *)FUN_000014c8(uVar19 * 2);
    uVar16 = (ulonglong)*DAT_00183768;
    puVar4 = DAT_00183768;
    uVar19 = uVar13;
    uVar20 = uVar13;
    local_res8[0] = puVar6;
    if (*DAT_00183768 != 0) {
      do {
        bVar2 = true;
        if (*(short *)((longlong)puVar4 + uVar19 + 4) != 0) {
          uVar11 = *(ushort *)((longlong)puVar4 + uVar19 + 6);
          FUN_0010749e((undefined4 *)puVar6,uVar16 * 2,0);
          uVar16 = 0;
          puVar4 = DAT_00183768;
          uVar14 = uVar12;
          if (*DAT_00183768 != 0) {
            do {
              if (puVar4[uVar16 * 3 + 3] == uVar11) {
                uVar7 = (ulonglong)uVar14;
                uVar14 = uVar14 + 1;
                puVar6[uVar7] = uVar11;
                uVar11 = DAT_00183768[uVar16 * 3 + 2];
                puVar4 = DAT_00183768;
                if (uVar11 == uVar15) break;
                uVar16 = 0;
                if (uVar14 != 0) {
                  do {
                    if (!bVar2) goto LAB_0002d991;
                    if ((puVar6[uVar16] == uVar11) && (uVar7 = 0, *puVar4 != 0)) {
                      do {
                        if (puVar4[(uVar7 + 1) * 3] == *puVar6) {
                          puVar4[uVar7 * 3 + 2] = uVar15;
                          puVar4 = DAT_00183768;
                          bVar2 = false;
                          break;
                        }
                        uVar8 = (short)uVar7 + 1;
                        uVar7 = (ulonglong)uVar8;
                      } while (uVar8 < *puVar4);
                    }
                    uVar8 = (short)uVar16 + 1;
                    uVar16 = (ulonglong)uVar8;
                  } while (uVar8 < uVar14);
                }
                uVar16 = uVar13;
                if (!bVar2) break;
              }
              else {
                uVar16 = (ulonglong)(ushort)((short)uVar16 + 1);
              }
            } while ((ushort)uVar16 < *puVar4);
          }
        }
LAB_0002d991:
        uVar16 = (ulonglong)*puVar4;
        uVar20 = uVar20 + 1;
        uVar19 = uVar19 + 6;
      } while (uVar20 < uVar16);
    }
    FUN_000013d0((longlong *)local_res8);
  }
  return uVar13;
}