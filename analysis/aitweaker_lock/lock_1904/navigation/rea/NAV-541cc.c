
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 Candidate_PasswordControlCallback(byte *param_1,undefined8 param_2,undefined8 param_3)

{
  bool bVar1;
  char cVar2;
  short sVar3;
  ushort uVar4;
  char *pcVar5;
  ushort *puVar6;
  longlong lVar7;
  undefined8 uVar8;
  ushort *puVar9;
  ulonglong uVar10;
  ushort *puVar11;
  byte *pbVar12;
  short *psVar13;
  undefined *puVar14;
  short *psVar15;
  byte *pbVar16;
  byte *pbVar17;
  short *psVar18;
  short *psVar19;
  ushort **ppuVar20;
  ushort *local_res8;
  short *local_res10;
  ushort *local_res18;
  ushort *local_res20;
  ushort *local_50 [2];
  
  pbVar12 = *(byte **)(param_1 + 0x48);
  uVar4 = *(ushort *)(param_1 + 0x2c);
  bVar1 = false;
  local_res8 = (ushort *)((ulonglong)local_res8 & 0xffffffffffffff00);
  psVar18 = (short *)0x0;
  local_res10 = (short *)0x0;
  psVar19 = (short *)0x0;
  local_res18 = (ushort *)0x0;
  local_res20 = (ushort *)0x0;
  if ((*(uint *)(param_1 + 0x3c) >> 5 & 1) == 0) {
    lVar7 = FUN_00034f28((longlong)param_1,(undefined1 *)&local_res8,pbVar12);
    if ((lVar7 == 0) || (uVar8 = FUN_000356c8(param_1), (int)uVar8 == 0)) {
      if ((char)local_res8 != '\0') goto LAB_000547dd;
    }
    else {
      lVar7 = Candidate_PasswordInputDialog((longlong)param_1,0x42,(longlong *)&local_res10);
      psVar18 = local_res10;
      if (lVar7 != 0) goto LAB_000547dd;
      uVar10 = FUN_00035788(param_1,local_res10);
      if ((char)uVar10 == '\0') goto LAB_00054328;
LAB_00054347:
      bVar1 = true;
    }
LAB_000543a4:
    do {
      psVar13 = (short *)0x0;
      ppuVar20 = &local_res18;
      lVar7 = Candidate_PasswordInputDialog((longlong)param_1,0x43,(longlong *)ppuVar20);
      puVar6 = local_res18;
      if (lVar7 != 0) {
LAB_000547c8:
        if ((*(uint *)(param_1 + 0x3c) >> 5 & 1) != 0) {
          FUN_000540b4((longlong)param_1,psVar18,(short *)ppuVar20);
        }
        goto LAB_000547dd;
      }
      if (local_res18 != (ushort *)0x0) {
        uVar4 = *local_res18;
        psVar19 = psVar13;
        puVar9 = local_res18;
        while (uVar4 != 0) {
          puVar9 = puVar9 + 1;
          psVar19 = (short *)((longlong)psVar19 + 1);
          uVar4 = *puVar9;
        }
        if (((psVar19 != (short *)0x0) && (*(int *)(param_1 + 0x28) - 5U < 2)) &&
           (psVar19 != (short *)0x0)) {
          do {
            uVar4 = local_res18[(longlong)psVar13];
            if ((ushort)(local_res18[(longlong)psVar13] - 0x61) < 0x1a) {
              uVar4 = uVar4 - 0x20;
            }
            local_res18[(longlong)psVar13] = uVar4;
            psVar13 = (short *)((longlong)psVar13 + 1);
          } while (psVar13 < psVar19);
        }
      }
      if ((*(int *)(param_1 + 0x28) != 6) && (uVar8 = FUN_000356c8(param_1), (int)uVar8 == 0)) {
LAB_000544d8:
        pcVar5 = *(char **)(param_1 + 0x48);
        uVar10 = FUN_0001cdb4(pcVar5);
        if ((psVar19 < (short *)(uVar10 & 0xff)) ||
           (uVar10 = FUN_0001ce00(pcVar5), (short *)(uVar10 & 0xff) < psVar19)) {
          if ((*(uint *)(param_1 + 0x3c) >> 5 & 1) != 0) {
            FUN_000540b4((longlong)param_1,psVar18,(short *)ppuVar20);
          }
          puVar14 = &DAT_0006b440;
          goto LAB_0005432f;
        }
        if ((((puVar6 != (ushort *)0x0) && (psVar19 == (short *)0x0)) || (psVar19 == (short *)0x0))
           && (((*(uint *)(param_1 + 0x3c) >> 5 & 1) == 0 && (*(int *)(param_1 + 0x28) != 6))))
        goto LAB_00054789;
        ppuVar20 = &local_res20;
        lVar7 = Candidate_PasswordInputDialog((longlong)param_1,0x44,(longlong *)ppuVar20);
        if (lVar7 != 0) goto LAB_000547c8;
        goto LAB_0005453f;
      }
      if (!bVar1) {
        pbVar16 = *(byte **)(param_1 + 0x48);
        if (((*(int *)(param_1 + 0x28) != 6) || (local_res8 = (ushort *)0x0, *DAT_00092278 < 7)) ||
           ((puVar9 = (ushort *)FUN_00011dcc(6,(ulonglong *)&local_res8), local_res8 = puVar9,
            puVar9 == (ushort *)0x0 || (puVar9[2] == 0)))) goto LAB_000544d8;
        sVar3 = FUN_0001cebc(pbVar16);
        if ((sVar3 == 0x12) || (puVar9[6] != 0)) {
          FUN_00005958((longlong *)&local_res8);
        }
      }
      if (psVar19 != (short *)0x0) goto LAB_000544d8;
      puVar14 = &DAT_0006b4a8;
      cVar2 = FUN_00019ef4(&DAT_0006b4a8,3);
    } while (cVar2 != '\0');
    local_res20 = (ushort *)FUN_0003eea8(puVar14,2);
    if (local_res20 == (ushort *)0x0) goto LAB_000547dd;
    *local_res20 = 0;
LAB_0005453f:
    psVar13 = (short *)0x0;
    if (local_res20 != (ushort *)0x0) {
      puVar9 = local_res20;
      psVar15 = psVar13;
      if (*local_res20 != 0) {
        do {
          puVar9 = puVar9 + 1;
          psVar15 = (short *)((longlong)psVar15 + 1);
        } while (*puVar9 != 0);
        if ((psVar15 != (short *)0x0) &&
           (puVar9 = local_res20, psVar15 = psVar13, *(int *)(param_1 + 0x28) - 5U < 2)) {
          do {
            puVar9 = puVar9 + 1;
            psVar19 = (short *)((longlong)psVar15 + 1);
            psVar15 = psVar19;
          } while (*puVar9 != 0);
          if (psVar19 != (short *)0x0) {
            do {
              uVar4 = local_res20[(longlong)psVar13];
              if ((ushort)(local_res20[(longlong)psVar13] - 0x61) < 0x1a) {
                uVar4 = uVar4 - 0x20;
              }
              local_res20[(longlong)psVar13] = uVar4;
              psVar13 = (short *)((longlong)psVar13 + 1);
            } while (psVar13 < psVar19);
          }
        }
      }
      if (puVar6 != (ushort *)0x0) {
        uVar4 = *puVar6;
        puVar9 = puVar6;
        puVar11 = local_res20;
        while ((uVar4 != 0 && (uVar4 == *puVar11))) {
          puVar9 = puVar9 + 1;
          puVar11 = puVar11 + 1;
          uVar4 = *puVar9;
        }
        pbVar16 = (byte *)(ulonglong)*puVar9;
        if (*puVar9 == *puVar11) {
          pbVar17 = param_1 + 0x78;
          if ((*(longlong *)pbVar17 != 0) && (pbVar17 != (byte *)0x0)) {
            pbVar16 = pbVar17;
            FUN_00005984((undefined8 *)pbVar17);
          }
          psVar18 = (short *)FUN_0003eea8(pbVar16,(longlong)psVar19 * 2 + 2);
          *(short **)pbVar17 = psVar18;
          FUN_0003e700(psVar18,(longlong)psVar19 + 1,(short *)puVar6);
          pbVar16 = param_1 + 0x20;
          FUN_00028fe0((longlong)pbVar16,(longlong)puVar6);
          if ((*(longlong *)(param_1 + 8) != 0) &&
             (lVar7 = *(longlong *)(param_1 + 0x18), lVar7 != 0)) {
            pbVar17 = *(byte **)(param_1 + 0x48);
            *(undefined4 *)(lVar7 + 8) = *(undefined4 *)(param_1 + 0x28);
            uVar4 = FUN_0001cebc(pbVar17);
            *(uint *)(lVar7 + 0xc) = (uint)uVar4;
            uVar10 = FUN_0001ce00((char *)pbVar17);
            *(ushort **)(lVar7 + 0x18) = puVar6;
            *(uint *)(lVar7 + 0x10) = ((uint)uVar10 & 0xff) * 2;
            FUN_00028ee8((undefined8 *)pbVar16);
            puVar9 = *(ushort **)(param_1 + 0x18);
            (**(code **)(param_1 + 8))(*(undefined8 *)(param_1 + 0x10),param_1);
            local_res8 = (ushort *)0x0;
            if ((6 < *DAT_00092278) &&
               (puVar11 = (ushort *)FUN_00011dcc(6,(ulonglong *)&local_res8), local_50[0] = puVar11,
               puVar11 != (ushort *)0x0)) {
              FUN_0005b214((longlong)puVar11,_DAT_00092080);
              puVar9 = local_res8;
              FUN_00011518(6,0,(ulonglong)local_res8,puVar11);
              if (DAT_00082748 != 0) {
                *(undefined1 *)(DAT_00082748 + 0x58) = 1;
              }
              FUN_00005958((longlong *)local_50);
            }
            if ((*(uint *)(param_1 + 0x3c) >> 5 & 1) != 0) {
              lVar7 = *(longlong *)pbVar16;
              uVar4 = *(ushort *)(param_1 + 0x2c);
              if (psVar19 != (short *)0x0) {
                uVar10 = FUN_0001ce00((char *)pbVar12);
                puVar9 = (ushort *)FUN_0003eea8(uVar10 & 0xff,(uVar10 & 0xff) * 2 + 2);
                if (puVar9 == (ushort *)0x0) {
                  return 0x8000000000000006;
                }
                local_res8 = puVar9;
                uVar10 = FUN_0001ce00((char *)pbVar12);
                FUN_0003e700((short *)puVar9,(uVar10 & 0xff) + 1,(short *)puVar6);
                FUN_00028fe0((longlong)pbVar16,(longlong)puVar9);
                FUN_00005984(&local_res8);
                puVar9 = puVar6;
              }
              FUN_00028504((longlong *)pbVar16,uVar4,puVar9,1);
              pbVar12 = (byte *)FUN_0001004c(pbVar16,0xd,lVar7,uVar4);
              if (pbVar12 == (byte *)0x0) {
                return 0;
              }
              if (pbVar12 != param_1) {
                param_1 = pbVar12;
              }
            }
          }
          param_1[0x6b] = 0;
          goto LAB_000547dd;
        }
      }
    }
LAB_00054789:
    if ((*(uint *)(param_1 + 0x3c) >> 5 & 1) != 0) {
      FUN_000540b4((longlong)param_1,psVar18,(short *)ppuVar20);
    }
  }
  else {
    pbVar16 = param_1 + 0x20;
    FUN_00028fe0((longlong)pbVar16,0);
    pcVar5 = FUN_00028504((longlong *)pbVar16,uVar4,param_3,1);
    if (pcVar5 == (char *)0x0) {
      bVar1 = false;
      psVar18 = (short *)0x0;
      psVar19 = (short *)0x0;
      goto LAB_000543a4;
    }
    if (((0x20031 < *(uint *)(DAT_000824c0 + 8)) &&
        ((pcVar5 == (char *)0x8000000000000003 || (pcVar5 == (char *)0xa000000000000002)))) ||
       (lVar7 = Candidate_PasswordInputDialog((longlong)param_1,0x42,(longlong *)&local_res10),
       psVar18 = local_res10, lVar7 != 0)) goto LAB_000547dd;
    if (*local_res10 != 0) {
      FUN_00028fe0((longlong)pbVar16,(longlong)local_res10);
      uVar10 = FUN_0001ce00((char *)pbVar12);
      puVar6 = (ushort *)FUN_0003eea8(uVar10 & 0xff,(uVar10 & 0xff) * 2 + 2);
      if (puVar6 == (ushort *)0x0) {
        return 0x8000000000000006;
      }
      local_res8 = puVar6;
      uVar10 = FUN_0001ce00((char *)pbVar12);
      psVar13 = psVar18;
      FUN_0003e700((short *)puVar6,(uVar10 & 0xff) + 1,psVar18);
      FUN_00028fe0((longlong)pbVar16,(longlong)puVar6);
      FUN_00005984(&local_res8);
      pcVar5 = FUN_00028504((longlong *)pbVar16,uVar4,psVar13,1);
      if (pcVar5 != (char *)0x8000000000000006) {
        if (pcVar5 != (char *)0x0) goto LAB_000547dd;
        goto LAB_00054347;
      }
    }
  }
LAB_00054328:
  puVar14 = &DAT_0006b458;
LAB_0005432f:
  FUN_00019ef4(puVar14,1);
LAB_000547dd:
  FUN_00005984(&local_res10);
  FUN_00005984(&local_res18);
  FUN_00005984(&local_res20);
  return 0;
}

