/* 0x16426 */

undefined8 FUN_00015b1c(void)

{
  ushort uVar1;
  short sVar2;
  longlong *plVar3;
  longlong lVar4;
  short *psVar5;
  short *psVar6;
  ulonglong uVar7;
  short *psVar8;
  undefined8 uVar9;
  byte *pbVar10;
  longlong lVar11;
  short *psVar12;
  short **ppsVar13;
  uint *puVar14;
  wchar_t *pwVar15;
  longlong lVar16;
  short *psVar17;
  ulonglong uVar18;
  ulonglong *puVar19;
  uint uVar20;
  ulonglong uVar21;
  longlong *plVar22;
  byte *pbVar23;
  char *pcVar24;
  uint uVar25;
  uint *puVar26;
  char cVar27;
  ulonglong local_res8;
  ulonglong local_res10;
  uint local_res18;
  ulonglong local_res20;
  short *local_128;
  undefined4 local_120;
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  uint local_110;
  uint local_10c;
  undefined4 local_108 [2];
  longlong local_100;
  undefined4 local_f8;
  undefined4 local_f4;
  undefined4 local_f0;
  undefined4 local_ec;
  undefined4 *local_e8;
  undefined4 local_e0 [2];
  short *local_d8;
  longlong local_d0;
  uint *local_c8;
  ulonglong local_c0;
  short *local_b8;
  short *local_b0;
  longlong *local_a8;
  undefined8 local_a0;
  ulonglong local_98;
  longlong local_90;
  
  uVar18 = 0;
  local_a0 = 0;
  local_res8 = 0;
  local_e0[0] = 1;
  local_res10 = FUN_0000130c(u_ConfigPreserveHappened_0016c680,&DAT_0010a3d8,(undefined4 *)0x0,
                             (longlong *)&local_res8);
  if (local_res10 == 0) {
    local_res8 = local_res8 & 0xffffffffffffff00;
  }
  else {
    FUN_000013d0((longlong *)&local_res10);
    local_res8 = CONCAT71(local_res8._1_7_,1);
  }
  local_res10 = local_res10 & 0xffffffffffffff00;
  FUN_00107490((undefined4 *)&local_98,0,0x48);
  local_108[0] = 7;
  local_120 = 0xc5912ed9;
  local_11c = 0x4bff83c2;
  local_118 = 0x1f233699;
  local_114 = 0xe8f385eb;
  local_d0 = 0;
  if (DAT_00193728 == 0) {
    local_e8 = (undefined4 *)
               FUN_0000130c(u_ConstructDefaults4FirstBoot_0016c600,&local_120,(undefined4 *)0x0,
                            &local_d0);
    if (local_e8 == (undefined4 *)0x0) {
      (**(code **)(DAT_00180198 + 0x58))
                (u_ConstructDefaults4FirstBoot_0016c600,&local_120,3,8,&local_d0);
    }
  }
  else {
    local_e8 = local_e0;
  }
  DAT_00180210 = (longlong *)FUN_000014c8((ulonglong)*DAT_001937f0 << 4);
  if ((DAT_00180210 == (longlong *)0x0) ||
     (plVar3 = (longlong *)FUN_000014c8((ulonglong)*DAT_001937f0 << 4), DAT_001801f0 = plVar3,
     plVar3 == (longlong *)0x0)) {
    uVar9 = 0x8000000000000009;
  }
  else {
    plVar22 = DAT_00180210;
    uVar7 = uVar18;
    if (*DAT_001937f0 != 0) {
      do {
        puVar19 = (ulonglong *)(plVar3 + 1);
        lVar4 = FUN_0001a908(uVar7,puVar19);
        *plVar3 = lVar4;
        if (*puVar19 == 0) {
          *plVar22 = 0;
LAB_00015cd5:
          plVar22[1] = *puVar19;
        }
        else {
          lVar4 = FUN_000014c8(*puVar19);
          *plVar22 = lVar4;
          if (lVar4 != 0) {
            if (*plVar3 == 0) {
              lVar4 = FUN_000014c8(*puVar19);
              *plVar3 = lVar4;
              if (lVar4 == 0) goto LAB_00015cdc;
            }
            (**(code **)(DAT_00180188 + 0x160))(*plVar22,*plVar3);
            goto LAB_00015cd5;
          }
        }
LAB_00015cdc:
        uVar25 = (int)uVar7 + 1;
        uVar7 = (ulonglong)uVar25;
        plVar3 = plVar3 + 2;
        plVar22 = plVar22 + 2;
      } while (uVar25 < *DAT_001937f0);
    }
    local_10c = 0;
    puVar14 = DAT_001937e8;
    if (*DAT_001937e8 != 0) {
      do {
        uVar7 = 0;
        uVar25 = (uint)uVar18;
        local_a8 = (longlong *)((ulonglong)puVar14[uVar18 + 1] + DAT_001938e0);
        if (*local_a8 != 0) {
          if (DAT_0018f048 != 0) {
            *(uint *)(DAT_0018f048 + 0x28) = uVar25;
          }
          local_110 = 0;
          if (*(int *)((longlong)local_a8 + 0x1c) != 0) {
            do {
              psVar6 = (short *)0x0;
              plVar3 = (longlong *)
                       ((ulonglong)*(uint *)((longlong)local_a8 + uVar7 * 4 + 0x20) + DAT_001937f8);
              uVar25 = *(uint *)(plVar3 + 1);
              if ((((uVar25 != 1) && (1 < uVar25 - 7)) && (*(short *)((longlong)plVar3 + 0x3a) != 0)
                  ) && (((*(byte *)((longlong)plVar3 + 0x1c) & 0x40) == 0 &&
                        (pbVar10 = (byte *)plVar3[5], pbVar10 != (byte *)0x0)))) {
                uVar18 = (ulonglong)*(ushort *)((longlong)plVar3 + 0x3a);
                puVar14 = (uint *)(plVar3 + 8);
                puVar26 = (uint *)((longlong)puVar14 + uVar18);
                pbVar23 = pbVar10;
                local_c8 = puVar26;
                uVar1 = FUN_00026e08(pbVar10);
                local_res18 = (uint)uVar1;
                if (*(short *)((longlong)plVar3 + 0x14) == 0x13) {
                  local_128 = (short *)0x0;
                  local_b8 = (short *)0x0;
                  local_res20 = local_res20 & 0xffffffff00000000;
                  uVar1 = FUN_00026d98((char *)pbVar10);
                  sVar2 = (short)*puVar14;
                  uVar18 = (ulonglong)uVar1;
                  psVar8 = psVar6;
                  if (sVar2 != 0) {
                    if (sVar2 == -1) {
                      local_d8 = (short *)0x0;
                    }
                    else {
                      local_d8 = (short *)FUN_000484c8(*plVar3,sVar2,(short *)0x0);
                    }
                    lVar4 = 0;
                    if (local_d8 == (short *)0x0) goto LAB_00016179;
                    psVar8 = local_d8;
                    lVar11 = lVar4;
                    if (*local_d8 == 0) {
LAB_00015e67:
                      uVar7 = 2;
                      FUN_000013d0((longlong *)&local_d8);
                      local_d8 = (short *)FUN_000014c8(2);
                    }
                    else {
                      do {
                        psVar8 = psVar8 + 1;
                        lVar11 = lVar11 + 1;
                      } while (*psVar8 != 0);
                      psVar8 = local_d8;
                      if (lVar11 == 0) goto LAB_00015e67;
                      do {
                        psVar8 = psVar8 + 1;
                        lVar4 = lVar4 + 1;
                      } while (*psVar8 != 0);
                      uVar7 = lVar4 * 2;
                      if (uVar18 < (ulonglong)(lVar4 * 2)) {
                        local_d8[uVar1 >> 1] = 0;
                        uVar7 = uVar18;
                      }
                    }
                    psVar8 = local_d8;
                    psVar5 = (short *)FUN_000014c8(uVar18 + 2);
                    local_b0 = psVar5;
                    FUN_0001b00c(0,(longlong)DAT_00180210,*(uint *)(plVar3 + 1),local_res18,uVar18,
                                 (undefined4 *)psVar5);
                    if (psVar5 == (short *)0x0) {
LAB_00015eeb:
                      FUN_0010749e((undefined4 *)psVar5,uVar18,0);
                      FUN_0001b00c(1,(longlong)DAT_00180210,*(uint *)(plVar3 + 1),local_res18,uVar18
                                   ,(undefined4 *)psVar5);
                      FUN_0001b00c(1,(longlong)DAT_00180210,*(uint *)(plVar3 + 1),local_res18,uVar7,
                                   (undefined4 *)psVar8);
                    }
                    else {
                      sVar2 = *psVar5;
                      psVar12 = psVar5;
                      psVar17 = psVar8;
                      while ((sVar2 != 0 && (sVar2 == *psVar17))) {
                        psVar12 = psVar12 + 1;
                        psVar17 = psVar17 + 1;
                        sVar2 = *psVar12;
                      }
                      if (*psVar12 != *psVar17) goto LAB_00015eeb;
                    }
                    if (psVar8 != (short *)0x0) {
                      FUN_000013d0((longlong *)&local_d8);
                    }
                    if (psVar5 != (short *)0x0) {
                      FUN_000013d0((longlong *)&local_b0);
                    }
                    psVar8 = (short *)(local_res20 & 0xffffffff);
                    puVar26 = local_c8;
                  }
                  cVar27 = (char)psVar8;
                  psVar8 = psVar6;
                  if ((short)*puVar26 != 0) {
                    if (((char)local_res8 != '\0') &&
                       (lVar4 = FUN_00016520(*plVar3,*(undefined2 *)((longlong)plVar3 + 0x3c)),
                       -1 < lVar4)) {
                      cVar27 = '\x01';
                    }
                    psVar6 = (short *)0x0;
                    if ((short)*puVar26 != -1) {
                      psVar6 = (short *)FUN_000484c8(*plVar3,(short)*puVar26,(short *)0x0);
                    }
                    lVar4 = 0;
                    local_128 = psVar6;
                    if (psVar6 == (short *)0x0) goto LAB_00016179;
                    psVar8 = psVar6;
                    lVar11 = lVar4;
                    if (*psVar6 == 0) {
LAB_00016025:
                      uVar7 = 2;
                      FUN_000013d0((longlong *)&local_128);
                      local_128 = (short *)FUN_000014c8(2);
                    }
                    else {
                      do {
                        psVar8 = psVar8 + 1;
                        lVar11 = lVar11 + 1;
                      } while (*psVar8 != 0);
                      psVar8 = psVar6;
                      if (lVar11 == 0) goto LAB_00016025;
                      do {
                        psVar8 = psVar8 + 1;
                        lVar4 = lVar4 + 1;
                      } while (*psVar8 != 0);
                      uVar7 = lVar4 * 2;
                      if (uVar18 < (ulonglong)(lVar4 * 2)) {
                        psVar6[uVar1 >> 1] = 0;
                        uVar7 = uVar18;
                      }
                    }
                    psVar8 = local_128;
                    psVar6 = (short *)FUN_000014c8(uVar18 + 2);
                    uVar25 = local_res18;
                    local_b8 = psVar6;
                    FUN_0001b00c(0,(longlong)DAT_001801f0,*(uint *)(plVar3 + 1),local_res18,uVar18,
                                 (undefined4 *)psVar6);
                    if (psVar6 != (short *)0x0) {
                      sVar2 = *psVar6;
                      psVar5 = psVar8;
                      psVar12 = psVar6;
                      while ((sVar2 != 0 && (sVar2 == *psVar5))) {
                        psVar12 = psVar12 + 1;
                        psVar5 = psVar5 + 1;
                        sVar2 = *psVar12;
                      }
                      if (*psVar12 == *psVar5) {
                        FUN_000013d0((longlong *)&local_128);
                        psVar8 = local_128;
                        goto LAB_00016112;
                      }
                    }
                    FUN_0010749e((undefined4 *)psVar6,uVar18,0);
                    FUN_0001b00c(1,(longlong)DAT_001801f0,*(uint *)(plVar3 + 1),uVar25,uVar18,
                                 (undefined4 *)psVar6);
                    FUN_0001b00c(1,(longlong)DAT_001801f0,*(uint *)(plVar3 + 1),uVar25,uVar7,
                                 (undefined4 *)psVar8);
                  }
LAB_00016112:
                  if (local_e8 == (undefined4 *)0x0) {
                    if (psVar8 == (short *)0x0) goto LAB_0001644e;
                    if (cVar27 != '\0') goto LAB_0001643a;
                    lVar11 = 0;
                    uVar25 = *(uint *)(plVar3 + 1);
                    local_c0 = 0;
                    lVar4 = lVar11;
                    if (uVar25 < *DAT_001937f0) {
                      lVar4 = (ulonglong)DAT_001937f0[(ulonglong)uVar25 + 1] +
                              (longlong)DAT_001937f0;
                    }
                    uVar7 = FUN_0001a908((ulonglong)uVar25,&local_c0);
                    local_res20 = uVar7;
                    if (uVar7 != 0) {
                      psVar5 = psVar8;
                      lVar16 = lVar11;
                      if (*psVar8 == 0) {
LAB_00016335:
                        FUN_000013d0((longlong *)&local_128);
                        psVar8 = (short *)FUN_000014c8(2);
                        uVar21 = 2;
                        local_128 = psVar8;
                      }
                      else {
                        do {
                          psVar5 = psVar5 + 1;
                          lVar16 = lVar16 + 1;
                        } while (*psVar5 != 0);
                        psVar5 = psVar8;
                        if (lVar16 == 0) goto LAB_00016335;
                        do {
                          psVar5 = psVar5 + 1;
                          lVar11 = lVar11 + 1;
                        } while (*psVar5 != 0);
                        uVar21 = lVar11 * 2;
                        if (uVar18 < (ulonglong)(lVar11 * 2)) {
                          uVar21 = uVar18;
                        }
                      }
                      if (psVar6 != (short *)0x0) {
                        (**(code **)(DAT_00180188 + 0x160))(local_res18 + uVar7,psVar6,uVar18);
                      }
                      (**(code **)(DAT_00180188 + 0x160))(local_res18 + uVar7,psVar8,uVar21);
                      if ((DAT_0018f169 != '\0') && ((char)local_res10 == '\0')) {
                        local_f8 = 0x71202eee;
                        local_f4 = 0x40d95f53;
                        local_f0 = 0xc9e3dab;
                        local_ec = 0x5766d926;
                        uVar9 = (**(code **)(DAT_00180188 + 0x18))(0x1f);
                        (**(code **)(DAT_00180188 + 0x20))(4);
                        FUN_0000176c(&local_f8);
                        (**(code **)(DAT_00180188 + 0x18))(0x1f);
                        (**(code **)(DAT_00180188 + 0x20))(uVar9);
                        local_res10 = CONCAT71(local_res10._1_7_,1);
                      }
                      (**(code **)(DAT_00180198 + 0x58))
                                (lVar4 + 0x10,lVar4,*(undefined4 *)(lVar4 + 0x60),local_c0,uVar7);
                      FUN_000013d0((longlong *)&local_res20);
                      goto LAB_0001643a;
                    }
                    ppsVar13 = &local_128;
                  }
                  else {
LAB_0001643a:
                    if (psVar8 != (short *)0x0) {
                      FUN_000013d0((longlong *)&local_128);
                    }
LAB_0001644e:
                    if (psVar6 == (short *)0x0) goto LAB_00016179;
                    ppsVar13 = &local_b8;
                  }
                  FUN_000013d0((longlong *)ppsVar13);
                }
                else {
                  uVar20 = (uint)uVar1;
                  if ((*(uint *)((longlong)plVar3 + 0x1c) & 0x80000) == 0) {
                    FUN_0001b00c(1,(longlong)DAT_00180210,uVar25,local_res18,uVar18,puVar14);
                    FUN_0001b00c(1,(longlong)DAT_001801f0,*(uint *)(plVar3 + 1),uVar20,
                                 (ulonglong)*(ushort *)((longlong)plVar3 + 0x3a),puVar26);
                  }
                  else {
                    uVar1 = FUN_00026d98((char *)pbVar10);
                    FUN_0001b2a4(1,(longlong)DAT_00180210,uVar25,(ulonglong)uVar20,(ulonglong)uVar1,
                                 puVar14,(char *)pbVar23);
                    pcVar24 = (char *)plVar3[5];
                    uVar1 = FUN_00026d98(pcVar24);
                    FUN_0001b2a4(1,(longlong)DAT_001801f0,*(uint *)(plVar3 + 1),(ulonglong)uVar20,
                                 (ulonglong)uVar1,puVar26,pcVar24);
                  }
                }
              }
LAB_00016179:
              local_110 = local_110 + 1;
              uVar7 = (ulonglong)local_110;
              puVar14 = DAT_001937e8;
              uVar25 = local_10c;
            } while (local_110 < *(uint *)((longlong)local_a8 + 0x1c));
          }
        }
        local_10c = uVar25 + 1;
        uVar18 = (ulonglong)local_10c;
      } while (local_10c < *puVar14);
    }
    uVar25 = 0;
    local_100 = 0;
    local_res8 = FUN_0000130c(u_StdDefaults_0016c638,&DAT_0010ab08,local_108,&local_100);
    if ((local_res8 != 0) && (local_100 != 0)) {
      local_90 = local_100;
      local_98 = local_res8;
      FUN_0004c604(&local_98);
      plVar3 = DAT_001801f0;
      uVar20 = uVar25;
      if (*DAT_001937f0 != 0) {
        do {
          FUN_000159a0(uVar20,(longlong)&local_98,plVar3);
          uVar20 = uVar20 + 1;
          plVar3 = plVar3 + 2;
        } while (uVar20 < *DAT_001937f0);
      }
      FUN_000013d0((longlong *)&local_res8);
    }
    local_100 = 0;
    puVar19 = (ulonglong *)&DAT_0010ab08;
    pwVar15 = u_MfgDefaults_0016c650;
    local_res8 = FUN_0000130c(u_MfgDefaults_0016c650,&DAT_0010ab08,local_108,&local_100);
    if ((local_res8 != 0) && (pwVar15 = (wchar_t *)0x0, local_100 != 0)) {
      local_90 = local_100;
      local_98 = local_res8;
      FUN_0004c604(&local_98);
      plVar3 = DAT_00180210;
      if (*DAT_001937f0 != 0) {
        do {
          puVar19 = &local_98;
          FUN_000159a0(uVar25,(longlong)puVar19,plVar3);
          uVar25 = uVar25 + 1;
          plVar3 = plVar3 + 2;
        } while (uVar25 < *DAT_001937f0);
      }
      pwVar15 = (wchar_t *)&local_res8;
      FUN_000013d0((longlong *)pwVar15);
    }
    FUN_00035a30((ulonglong)pwVar15,(ulonglong)puVar19);
    FUN_0003681c();
    uVar9 = local_a0;
  }
  if ((local_e8 != (undefined4 *)0x0) && (DAT_00193728 == 0)) {
    FUN_000013d0((longlong *)&local_e8);
  }
  return uVar9;
}


/* 0x1b6dd */

undefined8 FUN_0001b564(uint param_1,uint param_2,longlong param_3,uint *param_4,char *param_5)

{
  longlong lVar1;
  undefined8 *puVar2;
  longlong lVar3;
  ulonglong uVar4;
  uint uVar5;
  uint local_res8 [2];
  uint local_res10 [2];
  ulonglong local_58;
  longlong local_50 [3];
  
  uVar4 = 0;
  local_58 = 0;
  local_res8[0] = 0;
  local_res10[0] = 0;
  local_50[2] = 0;
  local_50[1] = 0;
  local_50[0] = 0;
  if ((((param_1 < *DAT_001937f0) && (param_3 != 0)) &&
      (lVar3 = (ulonglong)DAT_001937f0[(ulonglong)param_1 + 1] + (longlong)DAT_001937f0, lVar3 != 0)
      ) && ((puVar2 = (undefined8 *)FUN_0001a908((ulonglong)param_1,&local_58),
            puVar2 != (undefined8 *)0x0 && (param_2 >> 3 <= local_58)))) {
    if (param_5 != (char *)0x0) {
      FUN_0001b1c4(local_50 + 2,local_50 + 1,local_50,param_5);
    }
    if (param_3 == 1) {
      uVar4 = (ulonglong)(byte)*param_4;
    }
    else if (param_3 == 2) {
      uVar4 = (ulonglong)(ushort)*param_4;
    }
    else if (param_3 == 4) {
      uVar4 = (ulonglong)*param_4;
    }
    lVar1 = (longlong)puVar2 + (ulonglong)(param_2 >> 3);
    (**(code **)(DAT_00180188 + 0x160))(local_res8,lVar1,local_50[0]);
    uVar5 = ~(uint)(-2L << ((byte)local_50[1] & 0x3f));
    local_res10[0] =
         ~((uint)(-1L << ((byte)local_50[2] & 0x3f)) & uVar5) & local_res8[0] |
         (uint)(uVar4 << ((byte)local_50[2] & 0x3f)) & uVar5;
    (**(code **)(DAT_00180188 + 0x160))(lVar1,local_res10);
    if (((*(uint *)(lVar3 + 0x68) & 0x1000) == 0) &&
       ((0x39 < param_1 || ((0x3ff800003fcfffeU >> ((ulonglong)param_1 & 0x3f) & 1) == 0)))) {
      FUN_0002785c(lVar3,puVar2,0,local_58);
    }
    else {
      (**(code **)(DAT_00180198 + 0x58))
                (lVar3 + 0x10,lVar3,*(undefined4 *)(lVar3 + 0x60),local_58,puVar2);
    }
    return 0;
  }
  return 0x8000000000000002;
}


/* 0x2a3e7 */

longlong FUN_0002a18c(uint param_1)

{
  undefined8 *puVar1;
  byte bVar2;
  ushort uVar3;
  longlong lVar4;
  uint *puVar5;
  uint *puVar6;
  byte *pbVar7;
  uint **ppuVar8;
  longlong lVar9;
  ulonglong uVar10;
  uint uVar11;
  ulonglong uVar12;
  uint local_res10 [2];
  uint local_res18 [2];
  uint local_res20;
  uint *local_68;
  ulonglong local_60;
  undefined8 *local_58;
  uint *local_50 [2];
  
  local_res18[0] = 0;
  puVar5 = (uint *)0x0;
  local_60 = 0;
  local_res10[0] = 0;
  lVar9 = 0;
  local_68 = (uint *)0x0;
  FUN_0002a780(param_1);
  lVar4 = FUN_0002a144(param_1,local_res18);
  if ((-1 < lVar4) && (local_res20 = 0, local_res18[0] != 0)) {
    do {
      lVar4 = FUN_0002a0b0(param_1,local_res20,(longlong *)&local_58);
      puVar1 = local_58;
      if (lVar4 < 0) {
        return lVar4;
      }
      pbVar7 = (byte *)local_58[5];
      if (pbVar7 != (byte *)0x0) {
        if ((*(uint *)((longlong)local_58 + 0x1c) & 0x80000) == 0) {
          puVar5 = (uint *)FUN_0001a908((ulonglong)*(uint *)(local_58 + 1),&local_60);
          local_68 = puVar5;
          if (puVar5 != (uint *)0x0) {
            lVar9 = 0;
            if (*(uint *)(puVar1 + 1) < *DAT_001937f0) {
              lVar9 = (ulonglong)DAT_001937f0[(ulonglong)*(uint *)(puVar1 + 1) + 1] +
                      (longlong)DAT_001937f0;
            }
            if ((lVar9 != 0) && ((*(byte *)(lVar9 + 0x68) & 2) == 0)) {
              if ((*(uint *)(lVar9 + 0x68) & 0x2000) == 0) {
                pbVar7 = (byte *)puVar1[5];
                goto LAB_0002a26d;
              }
              uVar12 = 0;
              goto LAB_0002a276;
            }
          }
        }
        else {
LAB_0002a26d:
          uVar3 = FUN_00026e08(pbVar7);
          uVar12 = (ulonglong)uVar3;
LAB_0002a276:
          if (*(short *)((longlong)puVar1 + 0x14) == 0xf) {
            local_50[0] = (uint *)0x0;
            FUN_0002731c(puVar1,local_50,local_res10);
            bVar2 = 0;
            if (*(char *)puVar1[5] == '#') {
              bVar2 = ((char *)puVar1[5])[0xd];
            }
            local_res10[0] = local_res10[0] * bVar2;
          }
          else {
            uVar3 = FUN_00026d98((char *)puVar1[5]);
            local_res10[0] = (uint)uVar3;
          }
          uVar11 = (uint)uVar12;
          if (((((*(uint *)((longlong)puVar1 + 0x1c) & 0x80000) == 0) &&
               (local_60 < uVar11 + local_res10[0])) || (uVar11 == 0xffff)) ||
             ((local_60 < uVar11 + local_res10[0] || (local_res10[0] == 0)))) {
            ppuVar8 = &local_68;
          }
          else {
            uVar10 = (ulonglong)local_res10[0];
            puVar6 = (uint *)FUN_000014c8((ulonglong)local_res10[0]);
            if (puVar6 == (uint *)0x0) {
              return -0x7ffffffffffffff7;
            }
            local_50[0] = puVar6;
            if ((*(uint *)((longlong)puVar1 + 0x1c) & 0x80000) == 0) {
              lVar4 = FUN_0001ae7c(*(uint *)(puVar1 + 1),uVar11,uVar10,puVar6,'\0');
              if (-1 < lVar4) {
                (**(code **)(DAT_00180188 + 0x160))(uVar12 + (longlong)puVar5,puVar6);
                if ((lVar9 == 0) ||
                   (((*(uint *)(lVar9 + 0x68) & 0x1000) == 0 &&
                    ((0x39 < *(uint *)(puVar1 + 1) ||
                     ((0x3ff800003fcfffeU >> ((ulonglong)*(uint *)(puVar1 + 1) & 0x3f) & 1) == 0))))
                   )) {
                  FUN_0002785c(lVar9,(undefined8 *)puVar5,0,local_60);
                }
                else {
                  (**(code **)(DAT_00180198 + 0x58))
                            (lVar9 + 0x10,lVar9,*(undefined4 *)(lVar9 + 0x60),local_60,puVar5);
                }
              }
            }
            else {
              lVar4 = FUN_0001b2a4(0,DAT_001801c0,*(uint *)(puVar1 + 1),uVar12,uVar10,puVar6,
                                   (char *)puVar1[5]);
              if (-1 < lVar4) {
                FUN_0001b564(*(uint *)(puVar1 + 1),uVar11,uVar10,puVar6,(char *)puVar1[5]);
              }
            }
            FUN_000013d0((longlong *)&local_68);
            ppuVar8 = local_50;
          }
          FUN_000013d0((longlong *)ppuVar8);
          puVar5 = local_68;
        }
      }
      local_res20 = local_res20 + 1;
    } while (local_res20 < local_res18[0]);
  }
  return lVar4;
}

