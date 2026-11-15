
ulonglong FUN_000325b4(undefined8 param_1,ulonglong param_2)

{
  short *psVar1;
  short sVar2;
  uint uVar3;
  longlong *plVar4;
  char cVar5;
  ushort uVar6;
  ulonglong uVar7;
  undefined8 uVar8;
  longlong lVar9;
  longlong *plVar10;
  uint *puVar11;
  short *psVar12;
  short *psVar13;
  longlong lVar14;
  ulonglong uVar15;
  int iVar16;
  ulonglong *puVar17;
  ulonglong uVar18;
  undefined8 *puVar19;
  short *psVar20;
  undefined8 **ppuVar21;
  undefined8 **ppuVar22;
  longlong lVar23;
  ulonglong uVar24;
  char *pcVar25;
  uint uVar26;
  longlong lVar27;
  char *pcVar28;
  undefined1 *puVar29;
  uint *puVar30;
  undefined8 **ppuVar31;
  ulonglong uVar32;
  ulonglong uVar33;
  ushort uVar34;
  ulonglong local_res8;
  undefined8 local_res10;
  uint local_res18;
  uint local_res20;
  undefined8 local_a8;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined8 *local_88;
  char *local_80;
  ulonglong local_78;
  undefined1 *local_70;
  undefined8 local_68;
  undefined8 local_60;
  uint *local_58;
  undefined8 **local_50;
  
  uVar32 = 0;
  local_98 = 0xf22fc20c;
  local_68 = 0;
  local_94 = 0x45eb8cf4;
  local_90 = 0x4ead068e;
  local_8c = 0xd35db950;
  local_a8._0_4_ = 0x337f4407;
  local_a8._4_4_ = 0x4b835aee;
  local_a0 = 0xad4ea7b2;
  local_9c = 0xcd8830ca;
  if (((DAT_001936b0 != 0) || (DAT_00193690 != 0)) || (DAT_001936a0 != 0)) {
    FUN_00032404();
  }
  uVar7 = FUN_0004af68();
  if ((-1 < (longlong)uVar7) && (uVar7 = FUN_00033560(param_1,param_2), -1 < (longlong)uVar7)) {
    DAT_0018f1a0 = FUN_000014c8(CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190) * 0x30);
    if (DAT_0018f1a0 != 0) {
      uVar33 = 1;
      uVar7 = uVar32;
      uVar15 = uVar32;
      if (CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190) != 1) {
        do {
          local_res8 = FUN_00031e04(*(undefined8 *)(DAT_00183788 + uVar15 * 8),param_2,&local_68);
          if (local_res8 == 0) {
LAB_00032708:
            lVar9 = uVar15 * 0x30;
            if (*(uint **)(lVar9 + DAT_0018f1a0) == (uint *)0x0) {
              *(undefined8 *)(lVar9 + 8 + DAT_0018f1a0) = 0;
            }
            else {
              lVar27 = FUN_00031ac4(*(uint **)(lVar9 + DAT_0018f1a0));
              if (lVar27 < 0) {
                *(undefined8 *)(lVar9 + 8 + DAT_0018f1a0) = 0;
                puVar17 = (ulonglong *)(DAT_0018f1a0 + lVar9);
                goto LAB_000326c4;
              }
              *(undefined8 *)(lVar9 + 8 + DAT_0018f1a0) = *(undefined8 *)(DAT_00183788 + uVar15 * 8)
              ;
              if (*(longlong *)(DAT_0018f1a0 + lVar9) != 0) {
                FUN_00031f6c((longlong *)(DAT_0018f1a0 + lVar9));
              }
            }
          }
          else {
            uVar8 = FUN_0004bd54(local_res8 + 4);
            if ((char)uVar8 != '\0') {
              lVar9 = FUN_00031e04(*(undefined8 *)(DAT_00183788 + uVar15 * 8),param_2,
                                   (undefined8 *)(DAT_0018f1a0 + 0x18 + uVar15 * 0x30));
              *(longlong *)(uVar15 * 0x30 + DAT_0018f1a0) = lVar9;
              FUN_000013d0((longlong *)&local_res8);
              goto LAB_00032708;
            }
            puVar17 = &local_res8;
LAB_000326c4:
            FUN_000013d0((longlong *)puVar17);
          }
          uVar26 = (int)uVar15 + 1;
          uVar7 = (ulonglong)uVar26;
          uVar15 = (ulonglong)uVar26;
        } while ((ulonglong)uVar26 < CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190) - 1U);
      }
      DAT_0018f178 = (undefined1 *)FUN_000014c8(0x87);
      if (DAT_0018f178 != (undefined1 *)0x0) {
        lVar27 = uVar7 * 0x30;
        local_70 = DAT_0018f178;
        lVar9 = FUN_000014c8(((ulonglong)*DAT_001937c0 +
                             CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190)) * 0xf + 0x1b);
        *(longlong *)(lVar27 + DAT_0018f1a0) = lVar9;
        if (*(longlong *)(lVar27 + DAT_0018f1a0) != 0) {
          uVar15 = uVar32;
          if ((uVar7 < CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190)) && (DAT_0018f1a0 != 0)) {
            uVar15 = *(longlong *)(DAT_0018f1a0 + uVar7 * 0x30) + 4;
          }
          (**(code **)(DAT_00180188 + 0x160))(uVar15 + 2,DAT_001937d0 + 0x14,0x10);
          puVar11 = DAT_001937c0;
          DAT_00193680 = 0;
          if (*(longlong *)(lVar27 + DAT_0018f1a0) != 0) {
            puVar29 = (undefined1 *)(*(longlong *)(lVar27 + DAT_0018f1a0) + 0x1b);
            lVar9 = DAT_0018f1a0;
            uVar7 = DAT_00193680;
            if (*DAT_001937c0 != 0) {
              uVar15 = CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190);
              do {
                lVar23 = (ulonglong)puVar11[uVar33 + 1] + DAT_001937d0;
                if (*(short *)(lVar23 + 0x12) == 0) {
                  uVar32 = uVar32 + 1;
                  plVar10 = (longlong *)(DAT_001937c8 + (ulonglong)*(ushort *)(lVar23 + 8) * 0x14);
                  uVar6 = FUN_00033664(plVar10,(short)plVar10[2],
                                       *(short *)((longlong)plVar10 + 0x12),*(short *)(lVar23 + 10))
                  ;
                  uVar7 = (ulonglong)uVar6;
                  uVar24 = 0;
                  if (uVar7 != uVar15 - 1) {
                    uVar18 = uVar24;
                    if ((uVar7 < uVar15) && (lVar9 != 0)) {
                      uVar18 = *(longlong *)(lVar9 + uVar7 * 0x30) + 4;
                    }
                    if (uVar18 != 0) {
                      puVar29[1] = puVar29[1] & 0x8f;
                      puVar29[1] = puVar29[1] | 0xf;
                      *puVar29 = 0xf;
                      *(undefined2 *)(puVar29 + 2) = *(undefined2 *)(uVar18 + 0x12);
                      *(undefined2 *)(puVar29 + 4) = *(undefined2 *)(uVar18 + 0x14);
                      lVar23 = (ulonglong)puVar11[1] + DAT_001937d0;
                      uVar8 = *(undefined8 *)(DAT_0018f1a0 + 8 + uVar7 * 0x30);
                      lVar9 = *(longlong *)(lVar27 + DAT_0018f1a0);
                      if (*(int *)(lVar23 + 0x1c) != 0) {
                        do {
                          puVar19 = (undefined8 *)
                                    ((ulonglong)*(uint *)(lVar23 + 0x20 + uVar24 * 4) + DAT_001937d8
                                    );
                          *(uint *)((longlong)puVar19 + 0x1c) =
                               *(uint *)((longlong)puVar19 + 0x1c) & 0xfffffffe;
                          if ((longlong)puVar29 - lVar9 == puVar19[5]) {
                            puVar19[5] = puVar29;
LAB_00032963:
                            *puVar19 = uVar8;
                          }
                          else if (*(short *)((longlong)puVar19 + 0x14) == 0) goto LAB_00032963;
                          uVar26 = (int)uVar24 + 1;
                          uVar24 = (ulonglong)uVar26;
                        } while (uVar26 < *(uint *)(lVar23 + 0x1c));
                      }
                      puVar29 = puVar29 + 0xf;
                      lVar9 = DAT_0018f1a0;
                    }
                  }
                }
                uVar26 = (int)uVar33 + 1;
                uVar33 = (ulonglong)uVar26;
                uVar7 = uVar32;
              } while (uVar26 <= *puVar11);
            }
            DAT_00193680 = uVar7;
            *(undefined8 *)(lVar27 + 8 + lVar9) = *(undefined8 *)(lVar9 + 8);
          }
          uVar32 = 0;
          DAT_0018f128 = FUN_000014c8(0x10);
          if (DAT_0018f128 != 0) {
            uVar7 = uVar32;
            if (*DAT_001937b8 != 0) {
              do {
                FUN_0003048c((ulonglong)DAT_001937b8[uVar7 + 1] + (longlong)DAT_001937b8);
                uVar26 = (int)uVar7 + 1;
                uVar7 = (ulonglong)uVar26;
              } while (uVar26 < *DAT_001937b8);
            }
            uVar7 = uVar32;
            if (*DAT_00193798 != 0) {
              do {
                FUN_000301a4((ulonglong)DAT_00193798[uVar7 + 1] + (longlong)DAT_00193798);
                uVar26 = (int)uVar7 + 1;
                uVar7 = (ulonglong)uVar26;
              } while (uVar26 < *DAT_00193798);
            }
            uVar7 = DAT_0018f188;
            if (DAT_0018f198 == 0) {
              DAT_0018f188 = (ulonglong)*DAT_001937c0;
              DAT_0018f198 = FUN_000014c8(DAT_0018f188 << 4);
              uVar7 = uVar32;
            }
            else {
              DAT_0018f198 = FUN_00001450(DAT_0018f198,DAT_0018f188 << 4,
                                          (*DAT_001937c0 + DAT_0018f188) * 0x10);
              DAT_0018f188 = DAT_0018f188 + *DAT_001937c0;
            }
            if ((DAT_0018f198 != 0) && (uVar15 = uVar32, *DAT_001937c0 != 0)) {
              do {
                (**(code **)(DAT_00180188 + 0x160))
                          ((ulonglong)(uint)((int)uVar7 + (int)uVar15) * 0x10 + DAT_0018f198,
                           DAT_001937c8 +
                           (ulonglong)
                           *(ushort *)((ulonglong)DAT_001937c0[uVar15 + 1] + 8 + DAT_001937d0) *
                           0x14,0x10);
                uVar26 = (int)uVar15 + 1;
                uVar15 = (ulonglong)uVar26;
              } while (uVar26 < *DAT_001937c0);
            }
            local_res10 = (longlong *)((ulonglong)local_res10._4_4_ << 0x20);
            if (*DAT_001937c0 != 0) {
              do {
                uVar7 = 1;
                lVar9 = (ulonglong)DAT_001937c0[uVar32 + 1] + DAT_001937d0;
                if ((int)uVar32 == 0) {
                  uVar6 = (short)DAT_0018f190 - 1;
                  local_res8 = CONCAT62(local_res8._2_6_,uVar6);
                }
                else {
                  plVar10 = (longlong *)(DAT_001937c8 + (ulonglong)*(ushort *)(lVar9 + 8) * 0x14);
                  uVar6 = FUN_00033664(plVar10,(short)plVar10[2],
                                       *(short *)((longlong)plVar10 + 0x12),*(short *)(lVar9 + 10));
                  local_res8 = CONCAT62(local_res8._2_6_,uVar6);
                }
                if (*(int *)(lVar9 + 0x1c) == 0) {
                  iVar16 = 0;
                }
                else {
                  iVar16 = *(int *)(lVar9 + 0x1c) + -1;
                }
                uVar26 = iVar16 * 4 + 0x28;
                local_res18 = uVar26;
                plVar10 = (longlong *)FUN_000014c8((ulonglong)uVar26);
                DAT_00193650 = plVar10;
                if (plVar10 == (longlong *)0x0) goto LAB_0003266e;
                (**(code **)(DAT_00180188 + 0x160))(plVar10,lVar9,uVar26);
                lVar27 = DAT_001937a0;
                puVar11 = DAT_00193798;
                lVar9 = DAT_0018f1a0;
                uVar15 = (ulonglong)uVar6;
                local_78 = uVar15;
                if (uVar15 == CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190) - 1U) {
                  *DAT_00193650 = 0;
LAB_00032c96:
                  uVar32 = local_78;
                  ppuVar21 = (undefined8 **)0x0;
                  if ((*(byte *)((longlong)DAT_00193650 + 0x14) & 0x80) != 0) {
                    FUN_00036250(plVar10,uVar6);
                  }
                  lVar9 = DAT_001937d8;
                  if (*(int *)((longlong)DAT_00193650 + 0x1c) == 0) {
                    uVar26 = (uint)*(ushort *)(DAT_001937d8 + 0x3a) * 2 + 0x40;
                    puVar19 = (undefined8 *)FUN_000014c8((ulonglong)uVar26);
                    local_88 = puVar19;
                    (**(code **)(DAT_00180188 + 0x160))(puVar19,lVar9,uVar26);
                    FUN_0003006c(puVar19,uVar26);
                    ppuVar21 = &local_88;
                    FUN_000013d0((longlong *)ppuVar21);
                  }
                  else {
                    local_res8 = local_res8 & 0xffffffff00000000;
                    do {
                      uVar7 = 0;
                      pcVar28 = (char *)((ulonglong)
                                         *(uint *)((longlong)DAT_00193650 +
                                                  (longlong)ppuVar21 * 4 + 0x20) + DAT_001937d8);
                      if (*(short *)(pcVar28 + 0x3a) == 1) {
                        iVar16 = (uint)(byte)pcVar28[0x10] * 4 + 2;
                      }
                      else {
                        iVar16 = ((byte)pcVar28[0x10] + 1) * (uint)*(ushort *)(pcVar28 + 0x3a) * 2;
                      }
                      uVar26 = iVar16 + 0x40;
                      local_res20 = uVar26;
                      local_80 = pcVar28;
                      local_50 = ppuVar21;
                      puVar19 = (undefined8 *)FUN_000014c8((ulonglong)uVar26);
                      if (puVar19 == (undefined8 *)0x0) goto LAB_0003266e;
                      pcVar25 = pcVar28;
                      local_88 = puVar19;
                      (**(code **)(DAT_00180188 + 0x160))(puVar19,pcVar28,uVar26);
                      if (*DAT_00193650 != 0) {
                        lVar9 = uVar32 * 0x30;
                        *puVar19 = *(undefined8 *)(DAT_0018f1a0 + 8 + lVar9);
                        if (puVar19[5] == 0) {
                          pcVar25 = (char *)puVar19[6];
                          if (pcVar25 != (char *)0x0) {
                            puVar19[6] = pcVar25 + *(longlong *)(DAT_0018f1a0 + lVar9);
                          }
                        }
                        else {
                          puVar19[5] = puVar19[5] + *(longlong *)(DAT_0018f1a0 + lVar9);
                          if (*(char *)puVar19[5] == '\x06') {
                            uVar8 = FUN_0002a6cc((longlong)puVar19);
                            *(short *)((longlong)puVar19 + 0x14) = (short)uVar8;
                          }
                          if (puVar19[6] != 0) {
                            puVar19[6] = puVar19[6] + puVar19[5];
                          }
                          if ((*(uint *)((longlong)puVar19 + 0x1c) & 0x10000) != 0) {
                            pcVar25 = (char *)puVar19[5];
                            uVar32 = uVar7;
                            while( true ) {
                              if (*pcVar25 == 'b') break;
                              uVar26 = (uint)uVar32 + 1;
                              if ((byte)pcVar25[1] < 0x80) {
                                uVar26 = (uint)uVar32;
                              }
                              uVar3 = uVar26 - 1;
                              if (*pcVar25 != ')') {
                                uVar3 = uVar26;
                              }
                              uVar32 = (ulonglong)uVar3;
                              if (uVar3 == 0) goto LAB_00032e1a;
                              pcVar25 = pcVar25 + ((byte)pcVar25[1] & 0x7f);
                            }
                            pcVar25 = pcVar25 + 2;
                            (**(code **)(DAT_00180188 + 0x160))(&DAT_00193710,pcVar25,0x10);
                            FUN_000315a8(puVar19);
                          }
                        }
LAB_00032e1a:
                        local_60 = 0;
                        lVar27 = *(longlong *)(DAT_0018f1a0 + 8 + lVar9);
                        if (*(uint *)(puVar19 + 1) < *DAT_00193658) {
                          lVar23 = (ulonglong)DAT_00193658[(ulonglong)*(uint *)(puVar19 + 1) + 1] +
                                   DAT_00193670;
                          if (*(longlong *)(lVar23 + 0x70) == 0) {
                            *(longlong *)(lVar23 + 0x70) = lVar27;
                          }
                          if ((((*(uint *)(lVar23 + 0x68) & 0x1000) != 0) &&
                              (DAT_0018f1a8 != lVar27)) &&
                             (puVar11 = (uint *)FUN_00031e04(lVar27,pcVar25,&local_60),
                             pcVar28 = local_80, local_58 = puVar11, puVar11 != (uint *)0x0)) {
                            lVar23 = DAT_0018f1a8;
                            if ((*(char *)((longlong)puVar11 + 3) == '\x02') &&
                               (puVar30 = puVar11 + 1, lVar23 = lVar27, (*puVar11 & 0xffffff) != 4))
                            {
                              do {
                                if ((*puVar30 & 0x7f00) == 0) break;
                                puVar30 = (uint *)((longlong)(puVar11 + 1) + uVar7);
                                if ((char)*puVar30 == '&') {
                                  FUN_0002c8e4((char *)puVar30,lVar27);
                                }
                                uVar7 = uVar7 + (*(byte *)((longlong)puVar30 + 1) & 0x7f);
                              } while (uVar7 < (ulonglong)(*puVar11 & 0xffffff) - 4);
                            }
                            DAT_0018f1a8 = lVar23;
                            FUN_000013d0((longlong *)&local_58);
                            pcVar28 = local_80;
                          }
                        }
                        psVar13 = (short *)0x0;
                        if ((*(uint *)(puVar19 + 1) < *DAT_001937f0) &&
                           (lVar27 = (ulonglong)DAT_001937f0[(ulonglong)*(uint *)(puVar19 + 1) + 1]
                                     + (longlong)DAT_001937f0, lVar27 != 0)) {
                          if (*(longlong *)(lVar27 + 0x70) == 0) {
                            *(undefined8 *)(lVar27 + 0x70) =
                                 *(undefined8 *)(DAT_0018f1a0 + 8 + lVar9);
                          }
                          if ((*(uint *)(lVar27 + 0x68) & 0x2000) != 0) {
                            psVar1 = (short *)(lVar27 + 0x10);
                            psVar12 = psVar1;
                            psVar20 = psVar13;
                            if (*psVar1 != 0) {
                              do {
                                psVar12 = psVar12 + 1;
                                psVar20 = (short *)((longlong)psVar20 + 1);
                              } while (*psVar12 != 0);
                              if (psVar20 != (short *)0x0) goto LAB_00032f89;
                            }
                            if (*(short *)(lVar27 + 0x6c) != -1) {
                              psVar13 = (short *)FUN_000484c8(*(longlong *)(lVar27 + 0x70),
                                                              *(short *)(lVar27 + 0x6c),(short *)0x0
                                                             );
                            }
                            if (psVar13 != (short *)0x0) {
                              FUN_000b07bc(psVar1,0x28,psVar13);
                            }
                          }
                        }
                      }
LAB_00032f89:
                      lVar9 = DAT_001937c8;
                      uVar34 = 0;
                      uVar6 = *(ushort *)(pcVar28 + 0x26);
                      if (uVar6 != *(ushort *)(DAT_00193650 + 1)) {
                        lVar27 = CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190);
                        uVar32 = 0;
                        if (lVar27 != 1) {
                          do {
                            lVar23 = DAT_0018f1a0;
                            puVar11 = *(uint **)(DAT_0018f1a0 + uVar32 * 0x30);
                            if ((puVar11 != (uint *)0x0) && ((*puVar11 & 0xffffff) != 4)) {
                              plVar10 = (longlong *)(lVar9 + (ulonglong)uVar6 * 0x14);
                              lVar14 = FUN_000b1b20(plVar10,(longlong *)((longlong)puVar11 + 6),0x10
                                                   );
                              if ((lVar14 == 0) &&
                                 ((*(short *)(lVar23 + 0x10 + uVar32 * 0x30) == (short)plVar10[2] &&
                                  (puVar19 = local_88, pcVar28 = local_80,
                                  *(short *)(lVar23 + 0x22 + uVar32 * 0x30) ==
                                  *(short *)((longlong)plVar10 + 0x12))))) break;
                            }
                            uVar34 = uVar34 + 1;
                            uVar32 = (ulonglong)uVar34;
                            puVar19 = local_88;
                            pcVar28 = local_80;
                          } while (uVar32 < lVar27 - 1U);
                        }
                        uVar32 = (ulonglong)uVar34;
                        *puVar19 = *(undefined8 *)(DAT_0018f1a0 + 8 + uVar32 * 0x30);
                        if (puVar19[5] == 0) {
                          if (puVar19[6] != 0) {
                            lVar9 = *(longlong *)(DAT_0018f1a0 + uVar32 * 0x30) +
                                    *(longlong *)(pcVar28 + 0x30);
                            goto LAB_00033097;
                          }
                        }
                        else {
                          lVar9 = *(longlong *)(DAT_0018f1a0 + uVar32 * 0x30) +
                                  *(longlong *)(pcVar28 + 0x28);
                          puVar19[5] = lVar9;
                          if (puVar19[6] != 0) {
                            lVar9 = *(longlong *)(pcVar28 + 0x30) + lVar9;
LAB_00033097:
                            puVar19[6] = lVar9;
                          }
                        }
                        *(short *)((longlong)puVar19 + 0x26) = (short)DAT_00193650[1];
                      }
                      uVar26 = FUN_0003006c(puVar19,local_res20);
                      *(uint *)((longlong)DAT_00193650 + (longlong)local_50 * 4 + 0x20) = uVar26;
                      FUN_000013d0((longlong *)&local_88);
                      uVar26 = (int)local_res8 + 1;
                      ppuVar21 = (undefined8 **)(ulonglong)uVar26;
                      local_res8 = CONCAT44(local_res8._4_4_,uVar26);
                      uVar32 = local_78;
                    } while (uVar26 < *(uint *)((longlong)DAT_00193650 + 0x1c));
                  }
                  plVar10 = DAT_00193650;
                  ppuVar31 = (undefined8 **)0x0;
                  if ((uVar32 < CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190)) &&
                     (DAT_0018f1a0 != 0)) {
                    ppuVar31 = (undefined8 **)(*(longlong *)(DAT_0018f1a0 + uVar32 * 0x30) + 4);
                  }
                  if (DAT_00193728 == 0) {
                    ppuVar21 = (undefined8 **)((longlong)ppuVar31 + 2);
                    ppuVar22 = ppuVar21;
                    lVar9 = FUN_000b1b20((longlong *)ppuVar21,(longlong *)&local_98,0x10);
                    if (lVar9 != 0) {
                      if (ppuVar31 == (undefined8 **)0x0) {
                        cVar5 = '\0';
                      }
                      else {
                        ppuVar22 = ppuVar31;
                        uVar8 = FUN_00031b40((longlong)ppuVar31,(longlong *)&local_98);
                        cVar5 = (char)uVar8;
                      }
                      if ((cVar5 == '\0') &&
                         (lVar9 = FUN_000b1b20((longlong *)ppuVar21,&local_a8,0x10),
                         ppuVar22 = ppuVar21, lVar9 != 0)) {
                        if (ppuVar31 == (undefined8 **)0x0) {
                          cVar5 = '\0';
                        }
                        else {
                          uVar8 = FUN_00031b40((longlong)ppuVar31,&local_a8);
                          cVar5 = (char)uVar8;
                          ppuVar21 = ppuVar31;
                        }
                        ppuVar22 = ppuVar21;
                        if (cVar5 == '\0') goto LAB_000331ee;
                      }
                    }
                    ppuVar21 = ppuVar22;
                    if (*(short *)((longlong)plVar10 + 0x12) == 0) {
                      *(uint *)((longlong)plVar10 + 0x14) = *(uint *)((longlong)plVar10 + 0x14) | 1;
                      plVar10 = DAT_00193650;
                    }
                  }
LAB_000331ee:
                  plVar4 = local_res10;
                  iVar16 = (int)local_res10;
                  if ((int)local_res10 == 0) {
                    uVar32 = FUN_000305f8(&DAT_00193668,&DAT_00193698,(uint *)&DAT_00193690,plVar10,
                                          local_res18);
                  }
                  else {
                    uVar32 = FUN_00030318(ppuVar21,local_res18);
                    lVar9 = DAT_001937b0;
                    plVar10 = DAT_00193650;
                    uVar7 = 0;
                    sVar2 = *(short *)((longlong)DAT_00193650 + 10);
                    do {
                      if ((sVar2 == *(short *)((longlong)&DAT_0010c560 + uVar7)) &&
                         (((*(longlong *)((longlong)&DAT_0010c568 + uVar7) == 0 ||
                           (*plVar10 == *(longlong *)((longlong)&DAT_0010c568 + uVar7))) &&
                          (lVar27 = FUN_000b1b20((longlong *)
                                                 ((ulonglong)
                                                  *(uint *)(lVar9 + 4 +
                                                           (ulonglong)*(ushort *)(plVar10 + 1) * 4)
                                                 + lVar9),(longlong *)(&DAT_0010c550 + uVar7),0x10),
                          lVar27 == 0)))) {
                        local_res8 = local_res8 & 0xffffffff00000000;
                        FUN_000305f8(&DAT_00193668,&DAT_00193698,(uint *)&DAT_00193690,&local_res8,4
                                    );
                        if (DAT_00193680 == 7) {
                          local_res8 = local_res8 & 0xffffffff00000000;
                          FUN_000305f8(&DAT_00193668,&DAT_00193698,(uint *)&DAT_00193690,&local_res8
                                       ,4);
                        }
                        local_res10 = (longlong *)FUN_000014c8(0x40);
                        puVar29 = local_70;
                        if (local_res10 == (longlong *)0x0) goto LAB_0003266e;
                        *local_res10 = *DAT_00193650;
                        *(undefined2 *)((longlong)local_res10 + 0x14) = 1;
                        *(short *)(local_res10 + 3) = (short)plVar4;
                        *(uint *)((longlong)local_res10 + 0x1c) =
                             *(uint *)((longlong)local_res10 + 0x1c) | 1;
                        local_70[1] = local_70[1] & 0x8f;
                        local_70[1] = local_70[1] | 0xf;
                        *local_70 = 0xf;
                        *(undefined2 *)(local_70 + 2) =
                             *(undefined2 *)((longlong)DAT_00193650 + 0xe);
                        *(undefined2 *)(local_70 + 4) = 0;
                        local_res10[5] = (longlong)local_70;
                        uVar26 = FUN_0003006c(local_res10,0x40);
                        local_res8 = CONCAT44(local_res8._4_4_,uVar26);
                        FUN_000305f8(&DAT_00193668,&DAT_00193698,(uint *)&DAT_00193690,&local_res8,4
                                    );
                        FUN_000013d0(&local_res10);
                        local_70 = puVar29 + 0xf;
                        DAT_00193680 = DAT_00193680 + 1;
                        break;
                      }
                      uVar7 = uVar7 + 0x20;
                    } while (uVar7 < 0x120);
                  }
                  if ((longlong)uVar32 < 0) {
                    return uVar32;
                  }
                  FUN_000013d0((longlong *)&DAT_00193650);
                }
                else {
                  uVar26 = 1;
                  iVar16 = (int)uVar32;
                  if (1 < *DAT_00193798) {
                    sVar2 = *(short *)(DAT_0018f1a0 + 0x10 + uVar15 * 0x30);
                    do {
                      uVar26 = (uint)uVar7;
                      plVar10 = (longlong *)((ulonglong)puVar11[uVar7 + 1] + (longlong)puVar11);
                      if (((short)plVar10[2] == sVar2) &&
                         (*(short *)((longlong)plVar10 + 0x12) ==
                          *(short *)(lVar9 + 0x22 + uVar15 * 0x30))) {
                        puVar30 = *(uint **)(lVar9 + uVar15 * 0x30);
                        lVar23 = FUN_000b1b20(plVar10,(longlong *)((longlong)puVar30 + 6),0x10);
                        if ((lVar23 == 0) &&
                           (*(uint *)(lVar27 + (ulonglong)(uVar26 - 1) * 8) != (*puVar30 & 0xffffff)
                           )) break;
                      }
                      uVar26 = uVar26 + 1;
                      uVar7 = (ulonglong)uVar26;
                    } while (uVar26 < *puVar11);
                    uVar6 = (ushort)local_res8;
                    iVar16 = (int)local_res10;
                  }
                  if (*puVar11 <= uVar26) {
                    *(undefined1 *)(lVar9 + 0x20 + local_78 * 0x30) = 1;
                    plVar10 = *(longlong **)(DAT_0018f1a0 + 8 + local_78 * 0x30);
                    *DAT_00193650 = (longlong)plVar10;
                    goto LAB_00032c96;
                  }
                  puVar19 = (undefined8 *)(local_78 * 0x30 + lVar9);
                  if (*(char *)(puVar19 + 4) == '\0') {
                    FUN_000306e4(puVar19);
                  }
                  if (DAT_00193650 != (longlong *)0x0) {
                    FUN_000013d0((longlong *)&DAT_00193650);
                  }
                }
                uVar26 = iVar16 + 1;
                uVar32 = (ulonglong)uVar26;
                local_res10 = (longlong *)CONCAT44(local_res10._4_4_,uVar26);
              } while (uVar26 < *DAT_001937c0);
            }
            uVar7 = 0;
            local_res8 = local_res8 & 0xffffffff00000000;
            local_a8._0_4_ = 0xb63bf800;
            local_a8._4_4_ = 0x4f55f267;
            local_a0 = 0x7fe91792;
            local_9c = 0x4698b6b3;
            DAT_0018f180 = 0;
            (**(code **)(DAT_00180198 + 0x58))
                      (u_DynamicPageCount_0016d2a8,&local_a8,2,4,&local_res8);
            FUN_0001b74c(0x12);
            uVar32 = uVar7;
            do {
              *(undefined2 *)(uVar32 + DAT_0018f128) = 0;
              uVar32 = uVar32 + 2;
            } while ((longlong)uVar32 < 0x10);
            FUN_00029f5c();
            lVar9 = DAT_0018f1a0;
            uVar32 = uVar7;
            if (CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190) != 1) {
              do {
                lVar27 = uVar32 * 0x30;
                if ((*(longlong *)(lVar27 + 8 + lVar9) != 0) &&
                   (*(char *)(lVar27 + 0x20 + lVar9) == '\0')) {
                  lVar9 = FUN_00031ac4(*(uint **)(lVar27 + lVar9));
                  if (lVar9 == 0) {
                    puVar19 = FUN_000306e4((longlong *)(DAT_0018f1a0 + lVar27));
                    lVar9 = DAT_0018f1a0;
                    if (*(char *)(lVar27 + 0x20 + DAT_0018f1a0) != '\0') {
                      uVar15 = uVar7;
                      if ((uVar32 < CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190)) &&
                         (DAT_0018f1a0 != 0)) {
                        uVar15 = *(longlong *)(DAT_0018f1a0 + uVar32 * 0x30) + 4;
                      }
                      if (uVar15 == 0) goto LAB_0003351c;
                    }
                    if (puVar19 == (undefined8 *)0x0) {
                      FUN_000364c4();
                      lVar9 = DAT_0018f1a0;
                    }
                  }
                  else {
                    FUN_000013d0((longlong *)(DAT_0018f1a0 + lVar27));
                    *(undefined8 *)(lVar27 + 8 + DAT_0018f1a0) = 0;
                    *(undefined8 *)(lVar27 + 0x18 + DAT_0018f1a0) = 0;
                    lVar9 = DAT_0018f1a0;
                  }
                }
LAB_0003351c:
                uVar32 = (ulonglong)((int)uVar32 + 1);
              } while (uVar32 < CONCAT62(DAT_0018f190._2_6_,(short)DAT_0018f190) - 1U);
            }
            FUN_00031fe8();
            FUN_00032298();
            uVar32 = FUN_000320d4();
            return uVar32;
          }
        }
      }
    }
LAB_0003266e:
    uVar7 = 0x8000000000000009;
  }
  return uVar7;
}

