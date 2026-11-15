
undefined8 Observed_FrameDraw(longlong *param_1)

{
  longlong *plVar1;
  ushort uVar2;
  short *psVar3;
  ulonglong uVar4;
  longlong lVar5;
  char *pcVar6;
  undefined7 extraout_var;
  char cVar7;
  byte bVar8;
  uint uVar9;
  longlong *plVar10;
  int iVar11;
  longlong lVar12;
  ulonglong uVar13;
  byte bVar14;
  byte bVar15;
  ushort uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  int iVar21;
  char *pcVar22;
  longlong lVar23;
  uint uVar24;
  ulonglong uVar25;
  longlong lVar26;
  short sVar27;
  ushort uVar28;
  uint uVar29;
  short *psVar30;
  uint uVar31;
  bool bVar32;
  bool bVar33;
  longlong *local_res8;
  short local_res10 [4];
  char local_res18;
  char local_res20;
  char in_stack_ffffffffffffff50;
  char local_98;
  char local_97;
  char local_96 [2];
  uint local_94;
  uint local_90;
  uint local_8c;
  uint local_88;
  uint local_84;
  uint local_80;
  int local_7c;
  short *local_78;
  char *local_70;
  uint local_64;
  ulonglong local_60;
  ulonglong local_58;
  longlong local_50;
  
  uVar17 = 0;
  local_94 = 0;
  pcVar22 = (char *)0x0;
  local_8c = 0;
  local_88 = 0;
  local_64 = 0;
  local_90 = 0;
  local_7c = 0;
  local_80 = 0;
  local_res18 = '\0';
  local_res20 = '\0';
  local_70 = (char *)0x0;
  if ((*(char *)((longlong)param_1 + 0x24) == '\0') || (*(int *)((longlong)param_1 + 0x3c) == 0)) {
    return 0x8000000000000003;
  }
  plVar10 = param_1;
  local_res8 = param_1;
  if (*(int *)((longlong)param_1 + 0x44) == -1) {
LAB_000205e5:
    local_res18 = '\x01';
  }
  else {
    plVar10 = (longlong *)(ulonglong)*(uint *)((longlong)param_1 + 0x44);
    plVar1 = (longlong *)(param_1[9] + (longlong)plVar10 * 8);
    if (plVar1 != (longlong *)0x0) {
      plVar10 = (longlong *)*plVar1;
      if ((*(byte *)((longlong)plVar10 + 0x3c) & 1) == 0) {
        if (*(char *)((longlong)plVar10 + 0x6b) == '\x01') {
          *(undefined1 *)((longlong)plVar10 + 0x6b) = 0;
        }
      }
      else {
        if (*(char *)((longlong)plVar10 + 0x6b) == '\x01') {
          (**(code **)(*plVar10 + 0x18))();
          return 0;
        }
        plVar10 = plVar10 + 4;
        bVar14 = FUN_00049128((longlong)plVar10);
        if (bVar14 == 0) {
          plVar10 = (longlong *)*plVar1;
          lVar23 = (**(code **)(*plVar10 + 0x30))(plVar10,1);
          if ((lVar23 != 0) && ((int)param_1[4] != 2)) {
            *(undefined4 *)((longlong)param_1 + 0x44) = 0xffffffff;
            goto LAB_000205e5;
          }
        }
      }
    }
  }
  pcVar6 = (char *)0x0;
  uVar24 = 0;
  if (param_1[10] != 0) {
    plVar10 = (longlong *)(ulonglong)*(ushort *)((longlong)param_1 + 0x2c);
    uVar2 = *(ushort *)((longlong)param_1 + 0x2a);
    local_84 = (uint)*(ushort *)((longlong)param_1 + 0x2c);
    pcVar6 = pcVar22;
    uVar24 = uVar17;
    if ((int)param_1[4] != 2) {
      if (uVar2 == 0) goto LAB_00020961;
      uVar2 = uVar2 - 1;
    }
    if ((uVar2 != 0) && (uVar2 != 0)) {
      uVar25 = (ulonglong)uVar2;
      do {
        uVar13 = 0;
        psVar30 = (short *)param_1[10];
        bVar14 = *(byte *)(param_1 + 6) | *(byte *)((longlong)param_1 + 0x31);
        lVar23 = (longlong)plVar10 * DAT_00093a70 + (ulonglong)*(ushort *)((longlong)param_1 + 0x2e)
        ;
        local_res10[0] = CONCAT11(local_res10[0]._1_1_,bVar14);
        local_50 = 0;
        DAT_000affe8 = 1;
        local_78 = psVar30;
        if ((psVar30 != (short *)0x0) && (plVar10 < DAT_00093a68)) {
          sVar27 = *psVar30;
          psVar3 = psVar30;
          while (sVar27 != 0) {
            psVar3 = psVar3 + 1;
            uVar13 = uVar13 + 1;
            sVar27 = *psVar3;
          }
          local_60 = uVar13;
          local_58 = uVar25;
          uVar4 = FUN_0004bf6c(psVar30);
          if ((uVar13 != 0) && (uVar4 / 0x13 != 0)) {
            if (bVar14 != 0) {
              FUN_00001600((undefined1 *)(DAT_000babe0 + 4 + lVar23),uVar4 / 0x13,bVar14);
            }
            uVar4 = 0;
            if (uVar13 != 0) {
              lVar26 = lVar23 * 2 + 0x3d0904;
              lVar12 = local_50;
              do {
                psVar30 = psVar30 + uVar4;
                sVar27 = *psVar30;
                param_1 = local_res8;
                uVar25 = local_58;
                if ((((sVar27 == 10) || (sVar27 == 0xc)) || (sVar27 == 0xd)) ||
                   ((sVar27 == 0x2028 || (sVar27 == 0x2029)))) break;
                if (1 < (ushort)(sVar27 + 0x10U)) {
                  lVar5 = FUN_0004d5d8(psVar30,local_96,&local_97,&local_98);
                  if (sVar27 == 0x40) {
                    if (psVar30[1] == 0x3b) {
                      cVar7 = (char)local_78[uVar4 + 2] * '\n' + -0x10 + (char)local_78[uVar4 + 3];
                      if (cVar7 == '\x1e') {
LAB_0002084f:
                        bVar15 = 0;
                      }
                      else if (cVar7 == '\x1f') {
                        bVar15 = 4;
                      }
                      else if (cVar7 == ' ') {
                        bVar15 = 10;
                      }
                      else if (cVar7 == '!') {
                        bVar15 = 0xe;
                      }
                      else if (cVar7 == '\"') {
                        bVar15 = 1;
                      }
                      else if (cVar7 == '#') {
                        bVar15 = 5;
                      }
                      else if (cVar7 == '$') {
                        bVar15 = 3;
                      }
                      else {
                        if (cVar7 != '%') goto LAB_0002084f;
                        bVar15 = 7;
                      }
                      lVar12 = 1;
                      bVar14 = bVar14 & 0xf0 | bVar15;
                      uVar4 = uVar4 + 4;
                      goto LAB_0002091d;
                    }
                  }
                  else if ((sVar27 == 0x20) && (lVar12 == 1)) {
                    lVar12 = 0;
                    bVar14 = (byte)local_res10[0];
                  }
                  if (lVar5 == 0) {
                    *(short *)(DAT_000babe0 + lVar26) = sVar27;
                    if (bVar14 != 0) {
                      *(byte *)(lVar23 + 4 + DAT_000babe0) = bVar14;
                    }
                    bVar32 = FUN_00018624(*psVar30);
                    if (CONCAT71(extraout_var,bVar32) == 1) {
                      lVar23 = lVar23 + 2;
                      lVar26 = lVar26 + 4;
                    }
                    else {
                      lVar23 = lVar23 + 1;
                      lVar26 = lVar26 + 2;
                    }
                  }
                  else {
                    bVar14 = (byte)local_res10[0];
                    if (local_98 != -1) {
                      uVar25 = 0;
                      do {
                        bVar14 = (byte)uVar25;
                        if ((&DAT_000a8410)[uVar25] == local_98) break;
                        bVar15 = (byte)uVar25 + 1;
                        uVar25 = (ulonglong)bVar15;
                        bVar14 = 0;
                      } while (bVar15 < 8);
                      bVar14 = bVar14 << 4 | (byte)local_res10[0] & 0xf;
                    }
                    if (local_97 != -1) {
                      uVar25 = 0;
                      do {
                        bVar15 = (byte)uVar25;
                        if ((&DAT_000a8418)[uVar25] == local_97) break;
                        bVar8 = (byte)uVar25 + 1;
                        uVar25 = (ulonglong)bVar8;
                        bVar15 = 0;
                      } while (bVar8 < 8);
                      bVar14 = bVar14 & 0xf0 | bVar15;
                    }
                    if (local_96[0] != -1) {
                      bVar14 = bVar14 & 0xf7 | local_96[0] << 3;
                    }
                    uVar4 = uVar4 + lVar5;
                  }
                }
LAB_0002091d:
                uVar4 = uVar4 + 1;
                param_1 = local_res8;
                uVar25 = local_58;
                psVar30 = local_78;
              } while (uVar4 < local_60);
            }
          }
        }
        local_84 = local_84 + 1;
        plVar10 = (longlong *)(ulonglong)local_84;
        DAT_000affe8 = 0;
        uVar25 = uVar25 - 1;
      } while (uVar25 != 0);
      pcVar6 = (char *)(ulonglong)local_90;
      local_58 = 0;
      uVar24 = local_90;
    }
  }
LAB_00020961:
  if ((int)param_1[4] == 0) {
    pcVar6 = (char *)FUN_00059b50(plVar10,(ulonglong)*(uint *)((longlong)param_1 + 0x3c));
    plVar10 = (longlong *)param_1[9];
    local_70 = pcVar6;
    if (*(int *)((longlong)param_1 + 0x3c) != 0) {
      uVar25 = 0;
      do {
        bVar14 = 2;
        if ((*(byte *)(*plVar10 + 0x3c) & 1) != 0) {
          bVar14 = FUN_00049128(*plVar10 + 0x20);
        }
        uVar17 = (int)uVar25 + 1;
        pcVar6[uVar25] = bVar14;
        plVar10 = plVar10 + 1;
        uVar25 = (ulonglong)uVar17;
        uVar24 = local_90;
      } while (uVar17 < *(uint *)((longlong)param_1 + 0x3c));
    }
  }
  uVar2 = *(ushort *)((longlong)param_1 + 0x2c);
  uVar16 = 0;
  plVar10 = (longlong *)param_1[9];
  uVar17 = 0;
  uVar28 = uVar2;
  if (*(int *)((longlong)param_1 + 0x3c) != 0) {
    do {
      if ((*(byte *)(*plVar10 + 0x3c) & 1) != 0) {
        iVar11 = 0;
        if (((int)param_1[4] == 0) && (pcVar6 != (char *)0x0)) {
          bVar14 = pcVar6[uVar16];
        }
        else {
          bVar14 = FUN_00049128(*plVar10 + 0x20);
          iVar11 = (int)param_1[4];
        }
        if ((bVar14 == 0) || (bVar14 == 3)) {
          if (iVar11 == 0) {
            local_res10[0] = 0;
            (**(code **)(*(longlong *)*plVar10 + 0x50))((longlong *)*plVar10,param_1,local_res10);
            sVar27 = 1;
            if (local_res10[0] != 0) {
              sVar27 = local_res10[0];
            }
            local_res10[0] = sVar27;
            (**(code **)(*(longlong *)*plVar10 + 0x40))
                      ((longlong *)*plVar10,((short)param_1[5] - (ushort)DAT_00093cd0) + -2);
          }
          uVar2 = uVar2 + *(short *)(*plVar10 + 0x66);
        }
      }
      uVar17 = *(uint *)((longlong)param_1 + 0x3c);
      uVar16 = uVar16 + 1;
      plVar10 = plVar10 + 1;
    } while (uVar16 < uVar17);
    uVar28 = *(ushort *)((longlong)param_1 + 0x2c);
    plVar10 = (longlong *)param_1[9];
    uVar24 = local_90;
  }
  pcVar22 = local_70;
  uVar25 = 0;
  uVar18 = (uint)uVar28;
  if (((char)param_1[0xb] == '\0') || (*(ushort *)((longlong)param_1 + 0x2a) + uVar18 < uVar2 + 1))
  {
    uVar25 = (ulonglong)*(uint *)((longlong)param_1 + 0x5c);
  }
  else {
    *(undefined4 *)((longlong)param_1 + 0x5c) = 0;
  }
  *(uint *)(param_1 + 0xc) = (uint)uVar25;
  plVar10 = plVar10 + uVar25;
  if ((uint)uVar25 < uVar17) {
    do {
      sVar27 = (short)uVar18;
      iVar11 = (int)uVar25;
      if ((plVar10 != (longlong *)0x0) && ((*(byte *)(*plVar10 + 0x3c) & 1) != 0)) {
        iVar21 = 0;
        if ((int)param_1[4] == 0) {
          bVar14 = pcVar22[uVar25];
        }
        else {
          bVar14 = FUN_00049128(*plVar10 + 0x20);
          iVar21 = (int)param_1[4];
        }
        if ((bVar14 == 0) || (bVar14 == 3)) {
          if (iVar21 == 0) {
            local_res8 = (longlong *)((ulonglong)local_res8 & 0xffffffffffff0000);
            (**(code **)(*(longlong *)*plVar10 + 0x50))((longlong *)*plVar10,param_1,&local_res8);
            uVar25 = 1;
            if ((short)local_res8 != 0) {
              uVar25 = (ulonglong)local_res8 & 0xffff;
            }
            uVar2 = (ushort)uVar25;
            if (*(ushort *)((longlong)param_1 + 0x2a) <= uVar2) {
              uVar2 = *(ushort *)((longlong)param_1 + 0x2a) - 1;
              uVar25 = (ulonglong)uVar2;
            }
            local_res8 = (longlong *)CONCAT62(local_res8._2_6_,uVar2);
            (**(code **)(*(longlong *)*plVar10 + 0x40))
                      ((longlong *)*plVar10,((short)param_1[5] - (ushort)DAT_00093cd0) + -2,uVar25);
          }
          uVar18 = (uint)(ushort)(sVar27 + *(short *)(*plVar10 + 0x66));
          if ((1 < *(uint *)((longlong)param_1 + 0x3c)) &&
             (pcVar6 = local_70, uVar24 = local_90,
             (uint)*(ushort *)((longlong)param_1 + 0x2a) +
             (uint)*(ushort *)((longlong)param_1 + 0x2c) < uVar18 + 1)) break;
          *(int *)(param_1 + 0xc) = iVar11;
          if (bVar14 != 0) goto LAB_00020c14;
        }
        else {
LAB_00020c14:
          if (*(int *)((longlong)param_1 + 0x44) == iVar11) {
            (**(code **)(*(longlong *)*plVar10 + 0x30))((longlong *)*plVar10,0);
            local_res18 = '\x01';
          }
        }
        plVar1 = (longlong *)*plVar10;
        (**(code **)(*plVar1 + 0x38))(plVar1,(short)plVar1[0xc],sVar27);
      }
      uVar25 = (ulonglong)(iVar11 + 1U);
      plVar10 = plVar10 + 1;
      pcVar6 = local_70;
      uVar24 = local_90;
    } while (iVar11 + 1U < *(uint *)((longlong)param_1 + 0x3c));
  }
  if (local_res18 != '\0') {
    uVar17 = *(uint *)((longlong)param_1 + 0x5c);
    uVar25 = (ulonglong)uVar17;
    plVar10 = (longlong *)(param_1[9] + uVar25 * 8);
    bVar33 = uVar17 == *(uint *)(param_1 + 0xc);
    bVar32 = uVar17 < *(uint *)(param_1 + 0xc);
    while (bVar32 || bVar33) {
      uVar17 = (uint)uVar25;
      if (((plVar10 != (longlong *)0x0) &&
          (plVar1 = (longlong *)*plVar10, (*(byte *)((longlong)plVar1 + 0x3c) & 1) != 0)) &&
         (lVar23 = (**(code **)(*plVar1 + 0x30))(plVar1,1), lVar23 == 0)) {
        *(uint *)((longlong)param_1 + 0x44) = uVar17;
        if (uVar17 <= *(uint *)(param_1 + 0xc)) goto LAB_00020cae;
        break;
      }
      uVar17 = uVar17 + 1;
      uVar25 = (ulonglong)uVar17;
      plVar10 = plVar10 + 1;
      bVar33 = uVar17 == *(uint *)(param_1 + 0xc);
      bVar32 = uVar17 < *(uint *)(param_1 + 0xc);
    }
    *(undefined4 *)((longlong)param_1 + 0x44) = 0xffffffff;
  }
LAB_00020cae:
  uVar25 = (ulonglong)*(uint *)((longlong)param_1 + 0x5c);
  plVar10 = (longlong *)(param_1[9] + uVar25 * 8);
  while( true ) {
    uVar13 = 0;
    if (*(uint *)(param_1 + 0xc) < (uint)uVar25) break;
    if ((plVar10 != (longlong *)0x0) && ((*(byte *)(*plVar10 + 0x3c) & 1) != 0)) {
      (**(code **)(*(longlong *)*plVar10 + 0x18))();
    }
    uVar25 = (ulonglong)((uint)uVar25 + 1);
    plVar10 = plVar10 + 1;
  }
  uVar2 = *(ushort *)((longlong)param_1 + 0x2c);
  uVar17 = 0;
  uVar28 = uVar2;
  if (*(int *)((longlong)param_1 + 0x3c) != 0) {
    do {
      lVar23 = *(longlong *)(param_1[9] + uVar13 * 8);
      if ((lVar23 != 0) && ((*(byte *)(lVar23 + 0x3c) & 1) != 0)) {
        if ((int)param_1[4] == 0) {
          bVar14 = pcVar6[uVar13];
        }
        else {
          bVar14 = FUN_00049128(lVar23 + 0x20);
        }
        if ((bVar14 == 0) || (bVar14 == 3)) {
          uVar28 = uVar28 + *(short *)(*(longlong *)(param_1[9] + uVar13 * 8) + 0x66);
          local_80 = (uint)uVar13;
        }
      }
      uVar17 = *(uint *)((longlong)param_1 + 0x3c);
      uVar18 = (uint)uVar13 + 1;
      uVar13 = (ulonglong)uVar18;
    } while (uVar18 < uVar17);
    uVar2 = *(ushort *)((longlong)param_1 + 0x2c);
  }
  uVar18 = (uint)uVar2;
  if ((int)param_1[4] == 0) {
    cVar7 = (char)param_1[0xb];
    uVar31 = 0;
    uVar29 = (uint)uVar28;
    uVar19 = uVar29 - uVar18;
    if ((cVar7 != '\0') && (uVar29 + 1 <= *(ushort *)((longlong)param_1 + 0x2a) + uVar18)) {
      local_res20 = '\x01';
      *(undefined1 *)(param_1 + 0xb) = 0;
      cVar7 = '\0';
    }
    if (((1 < uVar17) && (cVar7 == '\0')) &&
       (*(ushort *)((longlong)param_1 + 0x2a) + uVar18 < uVar29 + 1)) {
      *(undefined1 *)(param_1 + 0xb) = 1;
    }
    uVar28 = *(ushort *)((longlong)param_1 + 0x2a);
    uVar17 = *(uint *)((longlong)param_1 + 0x5c);
    uVar18 = uVar28 - 2;
    if (uVar17 != 0) {
      plVar10 = (longlong *)param_1[9];
      uVar25 = (ulonglong)uVar17;
      pcVar22 = pcVar6;
      local_8c = uVar31;
      do {
        lVar23 = *plVar10;
        if (((lVar23 != 0) && ((*(byte *)(lVar23 + 0x3c) & 1) != 0)) &&
           ((*pcVar22 == '\0' || (*pcVar22 == '\x03')))) {
          local_8c = local_8c + *(ushort *)(lVar23 + 0x66);
        }
        plVar10 = plVar10 + 1;
        pcVar22 = pcVar22 + 1;
        uVar25 = uVar25 - 1;
      } while (uVar25 != 0);
      uVar24 = 0;
    }
    uVar29 = *(uint *)(param_1 + 0xc);
    if (uVar29 != 0) {
      plVar10 = (longlong *)param_1[9];
      uVar25 = (ulonglong)uVar29;
      local_88 = uVar31;
      do {
        lVar23 = *plVar10;
        if (((lVar23 != 0) && ((*(byte *)(lVar23 + 0x3c) & 1) != 0)) &&
           ((*pcVar6 == '\0' || (*pcVar6 == '\x03')))) {
          local_88 = local_88 + *(ushort *)(lVar23 + 0x66);
        }
        plVar10 = plVar10 + 1;
        pcVar6 = pcVar6 + 1;
        uVar25 = uVar25 - 1;
      } while (uVar25 != 0);
      uVar17 = *(uint *)((longlong)param_1 + 0x5c);
      pcVar6 = local_70;
    }
    uVar9 = uVar28 - 1;
    if ((uVar9 < uVar19) && ((uVar19 - uVar28) + 1 < 2)) {
      uVar19 = uVar19 + 1;
      local_7c = 1;
    }
    uVar20 = local_64;
    if (uVar19 != 0) {
      uVar31 = (uint)uVar2 + (uVar9 * local_8c) / uVar19;
      local_94 = (uVar9 * local_88) / uVar19 + (uint)uVar2;
      uVar24 = (uVar9 * uVar18) / uVar19;
      uVar20 = (uint)(uVar18 >> 1 < ((uVar9 * uVar18) % uVar19) * uVar18);
    }
    if (((((uVar29 < *(int *)((longlong)param_1 + 0x3c) - 1U) && (uVar18 < uVar31)) ||
         (uVar29 == local_80)) || ((uVar17 != 0 && (uVar31 == uVar2)))) &&
       ((uVar17 = local_8c + uVar2, uVar17 < (uVar28 - 2 & 0xffff) && (local_7c != 0)))) {
      local_94 = uVar17 + 1 + uVar24;
      uVar31 = uVar17;
    }
    if ((local_94 - uVar31 < 2) || (uVar24 == 0)) {
      uVar24 = 1;
    }
    uVar17 = local_94;
    if ((local_94 - uVar31) - 1 != uVar24) {
      iVar11 = (uint)uVar2 + (uint)uVar28;
      if (iVar11 - 2U < uVar31 + 1 + uVar24) {
        uVar31 = (iVar11 - uVar24) - 3;
      }
      uVar17 = uVar31 + 1 + uVar24;
    }
    FUN_00021050((longlong)param_1,uVar31,uVar17,uVar20,uVar24,in_stack_ffffffffffffff50,local_res20
                );
    uVar18 = (uint)*(ushort *)((longlong)param_1 + 0x2c);
  }
  uVar25 = (ulonglong)uVar18;
  uVar13 = (ulonglong)*(ushort *)((longlong)param_1 + 0x2a) + (ulonglong)uVar18;
  if (DAT_00093ad0 == 0xffff) {
    DAT_00093ad0 = uVar25;
  }
  if (DAT_00093ac8 == 0xffff) {
    DAT_00093ac8 = uVar13;
  }
  if (uVar25 < DAT_00093ad0) {
    DAT_00093ad0 = uVar25;
  }
  if (DAT_00093ac8 < uVar13) {
    DAT_00093ac8 = uVar13;
  }
  pcVar22 = DAT_000afe40;
  if (((int)param_1[4] == 0) && (pcVar22 = pcVar6, DAT_000afe40 != (char *)0x0)) {
    (**(code **)(DAT_000afbc8 + 0x48))();
  }
  DAT_000afe40 = pcVar22;
  return 0;
}

