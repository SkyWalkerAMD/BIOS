
undefined8 FUN_00044250(void)

{
  longlong lVar1;
  byte bVar2;
  short sVar3;
  int iVar4;
  uint uVar5;
  byte *pbVar6;
  bool bVar7;
  longlong lVar8;
  uint uVar9;
  undefined8 *puVar10;
  ushort *puVar11;
  longlong lVar12;
  ushort *puVar13;
  undefined8 uVar14;
  ushort *puVar15;
  ushort *puVar16;
  longlong *plVar17;
  ulonglong uVar18;
  uint *puVar19;
  longlong *plVar20;
  ushort uVar21;
  longlong *plVar22;
  ulonglong uVar23;
  ulonglong uVar24;
  ulonglong uVar25;
  ushort uVar26;
  ulonglong uVar27;
  longlong *plVar28;
  uint uVar29;
  uint local_res18;
  uint local_res20;
  ushort *local_108;
  ulonglong local_100;
  ushort *local_f8;
  ulonglong local_f0;
  undefined8 local_d0;
  ushort local_88 [4];
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  longlong local_70;
  short *local_68;
  char local_60 [8];
  ulonglong local_58;
  longlong local_50;
  
  lVar12 = DAT_000afd20;
  lVar8 = DAT_000afce8;
  uVar27 = 0;
  local_50 = DAT_000afd20;
  local_d0 = 0x8000000000000003;
  local_70 = 0;
  bVar7 = false;
  if (DAT_000baa68 == 0) {
    puVar10 = FUN_00007758(u_EvaluateDefaults4FirstBoot_000a9360,&DAT_00093318,(undefined4 *)0x0,
                           &local_70);
    if (puVar10 != (undefined8 *)0x0) {
      (**(code **)(DAT_000afbc8 + 0x48))(puVar10);
      return 0x8000000000000003;
    }
    (**(code **)(DAT_000afbd8 + 0x58))
              (u_EvaluateDefaults4FirstBoot_000a9360,&DAT_00093318,3,8,&local_70);
  }
  local_res20 = 0;
  puVar19 = DAT_000baaf0;
  uVar14 = 0x8000000000000003;
  if (*DAT_000baaf0 != 0) {
    do {
      uVar23 = 0;
      plVar22 = (longlong *)((ulonglong)puVar19[uVar27 + 1] + DAT_000babc0);
      if ((*plVar22 != 0) && (local_res18 = 0, *(int *)((longlong)plVar22 + 0x1c) != 0)) {
        do {
          local_108 = (ushort *)0x4;
          puVar16 = (ushort *)0x0;
          plVar28 = (longlong *)
                    ((ulonglong)*(uint *)((longlong)plVar22 + uVar23 * 4 + 0x20) + DAT_000bab08);
          pbVar6 = (byte *)plVar28[5];
          if ((pbVar6 != (byte *)0x0) &&
             ((iVar4 = (int)plVar28[1], iVar4 != 1 && (iVar4 != 7 && iVar4 != 8)))) {
            uVar21 = 0;
            if (*(short *)((longlong)plVar28 + 0x3a) == 0) {
              if ((*(byte *)((longlong)plVar28 + 0x1c) & 0x40) != 0) goto LAB_00044b3a;
            }
            else if ((*(byte *)((longlong)plVar28 + 0x1c) & 0x40) == 0) {
              if ((*(short *)((longlong)plVar28 + 0x14) != 0x13) || ((lVar8 == 0 && (lVar12 == 0))))
              goto LAB_00044ae4;
              bVar2 = *pbVar6;
              local_68 = (short *)((ulonglong)*(ushort *)((longlong)plVar28 + 0x3a) +
                                  (longlong)(plVar28 + 8));
              if (bVar2 == 5) {
LAB_00044514:
                uVar26 = 1 << (pbVar6[0xd] & 3);
LAB_00044523:
                local_108 = (ushort *)(ulonglong)uVar26;
                if (bVar2 < 0xe) {
                  if (bVar2 != 0xd) goto LAB_00044540;
                }
                else {
LAB_0004440b:
                  if ((((bVar2 != 0xf) && (bVar2 != 0x1a)) && (bVar2 != 0x1b)) &&
                     ((bVar2 != 0x1c && (bVar2 != 0x23)))) goto LAB_0004442b;
                }
LAB_00044426:
                uVar21 = *(ushort *)(pbVar6 + 10);
              }
              else {
                if (bVar2 != 6) {
                  if (bVar2 == 7) goto LAB_00044514;
                  if (bVar2 == 8) {
                    local_108 = (ushort *)(ulonglong)(ushort)(*(short *)(pbVar6 + 0xf) * 2);
                    goto LAB_00044540;
                  }
                  if (bVar2 != 0x1a) {
                    if (bVar2 == 0x1b) {
                      local_108 = (ushort *)0x3;
                    }
                    else {
                      uVar26 = uVar21;
                      if (bVar2 != 0x1c) goto LAB_00044523;
                      local_108 = (ushort *)((ulonglong)pbVar6[0xe] * 2);
                    }
                  }
                  goto LAB_0004440b;
                }
                local_108 = (ushort *)0x1;
LAB_00044540:
                if (((bVar2 == 5) || (bVar2 == 6)) ||
                   ((bVar2 == 7 || ((bVar2 == 8 || (bVar2 == 0xc)))))) goto LAB_00044426;
              }
LAB_0004442b:
              uVar9 = (uint)uVar21;
              if ((lVar12 != 0) && (sVar3 = (short)plVar28[8], sVar3 != 0)) {
                if ((sVar3 == -1) ||
                   (puVar11 = (ushort *)FUN_0004bc70(*plVar28,sVar3,(short *)0x0),
                   puVar11 == (ushort *)0x0)) goto LAB_00044ae4;
                puVar13 = puVar11;
                puVar15 = puVar16;
                if (*puVar11 == 0) {
LAB_00044579:
                  local_100 = 2;
                  (**(code **)(DAT_000afbc8 + 0x48))();
                  local_f8 = (ushort *)FUN_00059b50(puVar11,2);
                  puVar16 = puVar11;
                }
                else {
                  do {
                    puVar13 = puVar13 + 1;
                    puVar15 = (ushort *)((longlong)puVar15 + 1);
                  } while (*puVar13 != 0);
                  puVar13 = puVar11;
                  if (puVar15 == (ushort *)0x0) goto LAB_00044579;
                  do {
                    puVar13 = puVar13 + 1;
                    puVar16 = (ushort *)((longlong)puVar16 + 1);
                  } while (*puVar13 != 0);
                  local_100 = (longlong)puVar16 * 2;
                  local_f8 = puVar11;
                  if (local_108 < local_100) {
                    *(undefined2 *)((longlong)puVar11 + ((ulonglong)local_108 & 0xfffffffffffffffe))
                         = 0;
                    local_100 = (ulonglong)local_108;
                  }
                }
                puVar16 = (ushort *)FUN_00059b50(puVar16,(longlong)local_108 + 2);
                FUN_0001cde4(0,DAT_000afd20,*(uint *)(plVar28 + 1),uVar9,(longlong)local_108,
                             (undefined1 *)puVar16);
                if ((puVar16 == (ushort *)0x0) ||
                   (lVar12 = FUN_00059000(puVar16,local_f8), lVar12 != 0)) {
                  if (local_108 != (ushort *)0x0) {
                    FUN_00001600((undefined1 *)puVar16,(longlong)local_108,0);
                  }
                  FUN_0001cde4(1,DAT_000afd20,*(uint *)(plVar28 + 1),(uint)uVar21,
                               (longlong)local_108,(undefined1 *)puVar16);
                  lVar12 = DAT_000afd20;
                  uVar29 = *(uint *)(plVar28 + 1);
                  plVar20 = (longlong *)(ulonglong)uVar29;
                  if (*DAT_000baaf8 <= uVar29) goto LAB_00044793;
                  if (local_f8 != (ushort *)0x0) {
                    if (local_100 != 0) {
                      uVar27 = (ulonglong)uVar29;
                      plVar17 = (longlong *)
                                ((ulonglong)DAT_000baaf8[(longlong)plVar20 + 1] +
                                (longlong)DAT_000baaf8);
                      if ((plVar17 != (longlong *)0x0) &&
                         ((uVar23 = (ulonglong)uVar21, uVar21 != 0xffff ||
                          ((*plVar17 == 0x465e18879b9b610b &&
                           (uVar23 = 0, plVar17[1] == -0x58bba01f26cce44e)))))) {
                        puVar10 = *(undefined8 **)(DAT_000afd20 + uVar27 * 0x10);
                        uVar18 = 0;
                        if ((*(uint *)(plVar17 + 0xd) & 0x2000) == 0) {
                          uVar18 = uVar23;
                        }
                        if (puVar10 == (undefined8 *)0x0) {
                          uVar23 = local_100 + uVar18;
                          puVar10 = FUN_00059b50(plVar17,uVar23);
                          *(undefined8 **)(lVar12 + uVar27 * 0x10) = puVar10;
                          if (puVar10 == (undefined8 *)0x0) goto LAB_000447a9;
                          *(ulonglong *)(lVar12 + 8 + uVar27 * 0x10) = uVar23;
                        }
                        else {
                          uVar23 = *(ulonglong *)(DAT_000afd20 + 8 + uVar27 * 0x10);
                        }
                        lVar1 = lVar12 + uVar27 * 0x10;
                        if (uVar23 == 0) {
                          puVar10 = FUN_0001c6d0((ulonglong)plVar20,(ulonglong *)(lVar1 + 8));
                          *(undefined8 **)(lVar12 + uVar27 * 0x10) = puVar10;
                          if (puVar10 == (undefined8 *)0x0) goto LAB_000447a9;
                          uVar23 = *(ulonglong *)(lVar1 + 8);
                          plVar17 = plVar20;
                        }
                        uVar24 = uVar18 + local_100;
                        if (uVar23 < uVar24) {
                          puVar10 = FUN_00059b50(plVar17,uVar24);
                          if (puVar10 == (undefined8 *)0x0) goto LAB_000447a9;
                          (**(code **)(DAT_000afbc8 + 0x160))
                                    (puVar10,*(undefined8 *)(lVar12 + uVar27 * 0x10),
                                     *(undefined8 *)(lVar1 + 8));
                          if (*(longlong *)(lVar12 + uVar27 * 0x10) != 0) {
                            (**(code **)(DAT_000afbc8 + 0x48))();
                          }
                          *(undefined8 **)(lVar12 + uVar27 * 0x10) = puVar10;
                          *(ulonglong *)(lVar1 + 8) = uVar24;
                        }
                        (**(code **)(DAT_000afbc8 + 0x160))((longlong)puVar10 + uVar18,local_f8);
                      }
                    }
                    goto LAB_000447a9;
                  }
                }
                else {
LAB_00044793:
                  if (local_f8 != (ushort *)0x0) {
LAB_000447a9:
                    (**(code **)(DAT_000afbc8 + 0x48))(local_f8);
                  }
                }
                if (puVar16 != (ushort *)0x0) {
                  (**(code **)(DAT_000afbc8 + 0x48))(puVar16);
                }
              }
              uVar29 = (uint)uVar21;
              puVar16 = (ushort *)0x0;
              if ((((lVar8 == 0) || (sVar3 = *local_68, sVar3 == 0)) || (sVar3 == -1)) ||
                 (puVar11 = (ushort *)FUN_0004bc70(*plVar28,sVar3,(short *)0x0),
                 puVar11 == (ushort *)0x0)) goto LAB_00044ae4;
              puVar13 = puVar11;
              puVar15 = puVar16;
              if (*puVar11 == 0) {
LAB_00044870:
                local_f0 = 2;
                (**(code **)(DAT_000afbc8 + 0x48))();
                local_f8 = (ushort *)FUN_00059b50(puVar11,2);
                puVar16 = puVar11;
              }
              else {
                do {
                  puVar13 = puVar13 + 1;
                  puVar15 = (ushort *)((longlong)puVar15 + 1);
                } while (*puVar13 != 0);
                puVar13 = puVar11;
                if (puVar15 == (ushort *)0x0) goto LAB_00044870;
                do {
                  puVar13 = puVar13 + 1;
                  puVar16 = (ushort *)((longlong)puVar16 + 1);
                } while (*puVar13 != 0);
                local_f0 = (longlong)puVar16 * 2;
                local_f8 = puVar11;
                if (local_108 < local_f0) {
                  *(undefined2 *)((longlong)puVar11 + ((ulonglong)local_108 & 0xfffffffffffffffe)) =
                       0;
                  local_f0 = (ulonglong)local_108;
                }
              }
              puVar16 = (ushort *)FUN_00059b50(puVar16,(longlong)local_108 + 2);
              FUN_0001cde4(0,DAT_000afce8,*(uint *)(plVar28 + 1),uVar29,(longlong)local_108,
                           (undefined1 *)puVar16);
              if ((puVar16 == (ushort *)0x0) ||
                 (lVar12 = FUN_00059000(puVar16,local_f8), lVar12 != 0)) {
                if (local_108 != (ushort *)0x0) {
                  FUN_00001600((undefined1 *)puVar16,(longlong)local_108,0);
                }
                FUN_0001cde4(1,DAT_000afce8,*(uint *)(plVar28 + 1),uVar29,(longlong)local_108,
                             (undefined1 *)puVar16);
                lVar12 = DAT_000afce8;
                uVar5 = *(uint *)(plVar28 + 1);
                uVar27 = (ulonglong)uVar5;
                if (((*DAT_000baaf8 <= uVar5) || (local_f8 == (ushort *)0x0)) || (local_f0 == 0)) {
                  local_d0 = 0x8000000000000002;
                  goto LAB_00044aab;
                }
                uVar23 = (ulonglong)uVar5;
                plVar28 = (longlong *)((ulonglong)DAT_000baaf8[uVar27 + 1] + (longlong)DAT_000baaf8)
                ;
                if (plVar28 == (longlong *)0x0) {
LAB_00044951:
                  local_d0 = 0x8000000000000002;
                }
                else {
                  if (uVar29 == 0xffff) {
                    if ((*plVar28 != 0x465e18879b9b610b) || (plVar28[1] != -0x58bba01f26cce44e))
                    goto LAB_00044951;
                    uVar9 = 0;
                  }
                  uVar18 = 0;
                  puVar10 = *(undefined8 **)(DAT_000afce8 + uVar23 * 0x10);
                  uVar24 = 0;
                  if ((*(uint *)(plVar28 + 0xd) & 0x2000) == 0) {
                    uVar24 = (ulonglong)uVar9;
                  }
                  if (puVar10 == (undefined8 *)0x0) {
                    uVar25 = local_f0 + uVar24;
                    puVar10 = FUN_00059b50(0,uVar25);
                    *(undefined8 **)(lVar12 + uVar23 * 0x10) = puVar10;
                    if (puVar10 == (undefined8 *)0x0) goto LAB_00044951;
                    *(ulonglong *)(lVar12 + 8 + uVar23 * 0x10) = uVar25;
                  }
                  else {
                    uVar25 = *(ulonglong *)(DAT_000afce8 + 8 + uVar23 * 0x10);
                  }
                  lVar1 = lVar12 + uVar23 * 0x10;
                  if (uVar25 == 0) {
                    puVar10 = FUN_0001c6d0(uVar27,(ulonglong *)(lVar1 + 8));
                    *(undefined8 **)(lVar12 + uVar23 * 0x10) = puVar10;
                    if (puVar10 == (undefined8 *)0x0) goto LAB_00044951;
                    uVar25 = *(ulonglong *)(lVar1 + 8);
                    uVar18 = uVar27;
                  }
                  uVar27 = uVar24 + local_f0;
                  if (uVar25 < uVar27) {
                    puVar10 = FUN_00059b50(uVar18,uVar27);
                    if (puVar10 == (undefined8 *)0x0) goto LAB_00044951;
                    (**(code **)(DAT_000afbc8 + 0x160))
                              (puVar10,*(undefined8 *)(lVar12 + uVar23 * 0x10),
                               *(undefined8 *)(lVar1 + 8));
                    if (*(longlong *)(lVar12 + uVar23 * 0x10) != 0) {
                      (**(code **)(DAT_000afbc8 + 0x48))();
                    }
                    *(undefined8 **)(lVar12 + uVar23 * 0x10) = puVar10;
                    *(ulonglong *)(lVar1 + 8) = uVar27;
                  }
                  (**(code **)(DAT_000afbc8 + 0x160))((longlong)puVar10 + uVar24,local_f8,local_f0);
                  local_d0 = 0;
                }
LAB_00044ab0:
                (**(code **)(DAT_000afbc8 + 0x48))(local_f8);
              }
              else {
LAB_00044aab:
                if (local_f8 != (ushort *)0x0) goto LAB_00044ab0;
              }
              if (puVar16 != (ushort *)0x0) {
LAB_00044ac5:
                (**(code **)(DAT_000afbc8 + 0x48))(puVar16);
              }
            }
            else {
LAB_00044b3a:
              if ((*(byte *)((longlong)plVar22 + 0x14) & 0x20) == 0) {
                local_88[0] = 0;
                local_88[1] = 0;
                local_88[2] = 0;
                local_88[3] = 0;
                local_58 = 0;
                bVar2 = *pbVar6;
                local_f8 = (ushort *)0x0;
                local_f0 = 0;
                uVar26 = uVar21;
                if (bVar2 < 0xe) {
                  if ((((bVar2 == 0xd) || ((bVar2 == 5 || (bVar2 == 6)))) || (bVar2 == 7)) ||
                     ((bVar2 == 8 || (bVar2 == 0xc)))) {
LAB_00044b94:
                    uVar26 = *(ushort *)(pbVar6 + 10);
                  }
                }
                else if ((((bVar2 == 0xf) || (bVar2 == 0x1a)) || (bVar2 == 0x1b)) ||
                        ((bVar2 == 0x1c || (bVar2 == 0x23)))) goto LAB_00044b94;
                uVar29 = (uint)uVar26;
                uVar9 = FUN_000499cc((longlong)plVar28,local_88);
                local_100 = (ulonglong)(uVar9 & 0xffff);
                if (local_100 != 0) {
                  local_108 = local_88;
                  if (*(short *)((longlong)plVar28 + 0x14) != 0x13) {
                    local_60[0] = '\0';
                    local_60[1] = '\0';
                    local_60[2] = '\0';
                    local_60[3] = '\0';
                    local_60[4] = '\0';
                    local_60[5] = '\0';
                    local_60[6] = '\0';
                    local_60[7] = '\0';
                    lVar12 = FUN_0001cde4(0,DAT_000afce8,*(uint *)(plVar28 + 1),uVar29,local_100,
                                          local_60);
                    if ((lVar12 < 0) ||
                       (lVar12 = FUN_000015e0(local_60,(char *)local_88,local_100), lVar12 != 0)) {
                      DAT_000aff90 = 1;
                      goto LAB_00044eae;
                    }
                    goto LAB_00044ae4;
                  }
                  if ((local_88[0] == 0xffff) ||
                     (local_108 = (ushort *)FUN_0004bc70(*plVar28,local_88[0],(short *)0x0),
                     puVar11 = local_108, local_108 == (ushort *)0x0)) goto LAB_00044ae4;
                  for (; *puVar11 != 0; puVar11 = puVar11 + 1) {
                    puVar16 = (ushort *)((longlong)puVar16 + 1);
                  }
                  pbVar6 = (byte *)plVar28[5];
                  local_100 = (longlong)puVar16 * 2 + 2;
                  if (pbVar6 != (byte *)0x0) {
                    uVar9 = (uint)*pbVar6;
                    if (uVar9 == 5) {
LAB_00044c84:
                      puVar16 = (ushort *)(ulonglong)(pbVar6[0xd] & 3);
                      uVar21 = 1 << (sbyte)(pbVar6[0xd] & 3);
                    }
                    else if (uVar9 == 6) {
                      uVar21 = 1;
                      puVar16 = (ushort *)0x0;
                    }
                    else {
                      if (uVar9 == 7) goto LAB_00044c84;
                      if (uVar9 == 8) {
                        uVar21 = *(short *)(pbVar6 + 0xf) * 2;
                        puVar16 = (ushort *)0x0;
                      }
                      else if (uVar9 == 0x1a) {
                        uVar21 = 4;
                        puVar16 = (ushort *)0x0;
                      }
                      else {
                        uVar9 = uVar9 - 0x1b;
                        puVar16 = (ushort *)(ulonglong)uVar9;
                        if (uVar9 == 0) {
                          uVar21 = 3;
                        }
                        else if (uVar9 == 1) {
                          uVar21 = (ushort)pbVar6[0xe] * 2;
                        }
                      }
                    }
                  }
                  local_f0 = (ulonglong)uVar21;
                  if (local_f0 < local_100) {
                    *(undefined2 *)((longlong)local_108 + (local_f0 & 0xfffffffffffffffe)) = 0;
                    local_100 = local_f0;
                  }
                  local_f8 = (ushort *)FUN_00059b50(puVar16,local_f0 + 2);
                  uVar9 = (uint)uVar26;
                  FUN_0001cde4(0,DAT_000afce8,*(uint *)(plVar28 + 1),(uint)uVar26,local_f0,
                               (undefined1 *)local_f8);
                  uVar27 = 0;
                  if ((local_f8 != (ushort *)0x0) &&
                     (lVar12 = FUN_00059000(local_f8,local_108), lVar12 == 0)) {
                    (**(code **)(DAT_000afbc8 + 0x48))(local_108);
                    (**(code **)(DAT_000afbc8 + 0x48))(local_f8);
                    goto LAB_00044ae4;
                  }
                  if (local_f0 != 0) {
                    FUN_00001600((undefined1 *)local_f8,local_f0,0);
                  }
                  FUN_0001ccbc(*(uint *)(plVar28 + 1),uVar9,local_f0,local_f8);
                  lVar12 = DAT_000afce8;
                  uVar5 = *(uint *)(plVar28 + 1);
                  plVar20 = (longlong *)(ulonglong)uVar5;
                  if (((uVar5 < *DAT_000baaf8) && (local_f8 != (ushort *)0x0)) && (local_f0 != 0)) {
                    uVar23 = (ulonglong)uVar5;
                    plVar17 = (longlong *)
                              ((ulonglong)DAT_000baaf8[(longlong)plVar20 + 1] +
                              (longlong)DAT_000baaf8);
                    if (plVar17 != (longlong *)0x0) {
                      if (uVar9 == 0xffff) {
                        if ((*plVar17 != 0x465e18879b9b610b) || (plVar17[1] != -0x58bba01f26cce44e))
                        goto LAB_00044eae;
                        uVar9 = 0;
                      }
                      puVar10 = *(undefined8 **)(DAT_000afce8 + uVar23 * 0x10);
                      if ((*(uint *)(plVar17 + 0xd) & 0x2000) == 0) {
                        uVar27 = (ulonglong)uVar9;
                      }
                      if (puVar10 == (undefined8 *)0x0) {
                        uVar18 = uVar27 + local_f0;
                        puVar10 = FUN_00059b50(plVar17,uVar18);
                        *(undefined8 **)(lVar12 + uVar23 * 0x10) = puVar10;
                        if (puVar10 == (undefined8 *)0x0) goto LAB_00044eae;
                        *(ulonglong *)(lVar12 + 8 + uVar23 * 0x10) = uVar18;
                      }
                      else {
                        uVar18 = *(ulonglong *)(DAT_000afce8 + 8 + uVar23 * 0x10);
                      }
                      lVar1 = lVar12 + uVar23 * 0x10;
                      if (uVar18 == 0) {
                        puVar10 = FUN_0001c6d0((ulonglong)plVar20,(ulonglong *)(lVar1 + 8));
                        *(undefined8 **)(lVar12 + uVar23 * 0x10) = puVar10;
                        if (puVar10 == (undefined8 *)0x0) goto LAB_00044eae;
                        uVar18 = *(ulonglong *)(lVar1 + 8);
                        plVar17 = plVar20;
                      }
                      uVar24 = uVar27 + local_f0;
                      if (uVar18 < uVar24) {
                        puVar10 = FUN_00059b50(plVar17,uVar24);
                        if (puVar10 == (undefined8 *)0x0) goto LAB_00044eae;
                        (**(code **)(DAT_000afbc8 + 0x160))
                                  (puVar10,*(undefined8 *)(lVar12 + uVar23 * 0x10),
                                   *(undefined8 *)(lVar1 + 8));
                        if (*(longlong *)(lVar12 + uVar23 * 0x10) != 0) {
                          (**(code **)(DAT_000afbc8 + 0x48))();
                        }
                        *(undefined8 **)(lVar12 + uVar23 * 0x10) = puVar10;
                        *(ulonglong *)(lVar1 + 8) = uVar24;
                      }
                      (**(code **)(DAT_000afbc8 + 0x160))
                                ((longlong)puVar10 + uVar27,local_f8,local_f0);
                    }
                  }
LAB_00044eae:
                  uVar27 = 0;
                  FUN_0001ccbc(*(uint *)(plVar28 + 1),uVar29,local_100,local_108);
                  lVar12 = DAT_000afce8;
                  uVar9 = *(uint *)(plVar28 + 1);
                  plVar20 = (longlong *)(ulonglong)uVar9;
                  if ((uVar9 < *DAT_000baaf8) && (local_100 != 0)) {
                    uVar23 = (ulonglong)uVar9;
                    plVar17 = (longlong *)
                              ((ulonglong)DAT_000baaf8[(longlong)plVar20 + 1] +
                              (longlong)DAT_000baaf8);
                    if ((plVar17 != (longlong *)0x0) &&
                       ((uVar9 = uVar29, uVar29 != 0xffff ||
                        ((*plVar17 == 0x465e18879b9b610b &&
                         (uVar9 = 0, plVar17[1] == -0x58bba01f26cce44e)))))) {
                      puVar10 = *(undefined8 **)(DAT_000afce8 + uVar23 * 0x10);
                      if ((*(uint *)(plVar17 + 0xd) & 0x2000) == 0) {
                        uVar27 = (ulonglong)uVar9;
                      }
                      if (puVar10 == (undefined8 *)0x0) {
                        uVar18 = uVar27 + local_100;
                        puVar10 = FUN_00059b50(plVar17,uVar18);
                        *(undefined8 **)(lVar12 + uVar23 * 0x10) = puVar10;
                        if (puVar10 == (undefined8 *)0x0) goto LAB_00045084;
                        *(ulonglong *)(lVar12 + 8 + uVar23 * 0x10) = uVar18;
                      }
                      else {
                        uVar18 = *(ulonglong *)(DAT_000afce8 + 8 + uVar23 * 0x10);
                      }
                      lVar1 = lVar12 + uVar23 * 0x10;
                      if (uVar18 == 0) {
                        puVar10 = FUN_0001c6d0((ulonglong)plVar20,(ulonglong *)(lVar1 + 8));
                        *(undefined8 **)(lVar12 + uVar23 * 0x10) = puVar10;
                        if (puVar10 == (undefined8 *)0x0) goto LAB_00045084;
                        uVar18 = *(ulonglong *)(lVar1 + 8);
                        plVar17 = plVar20;
                      }
                      uVar24 = local_100 + uVar27;
                      if (uVar18 < uVar24) {
                        puVar10 = FUN_00059b50(plVar17,uVar24);
                        if (puVar10 == (undefined8 *)0x0) goto LAB_00045084;
                        (**(code **)(DAT_000afbc8 + 0x160))
                                  (puVar10,*(undefined8 *)(lVar12 + uVar23 * 0x10),
                                   *(undefined8 *)(lVar1 + 8));
                        if (*(longlong *)(lVar12 + uVar23 * 0x10) != 0) {
                          (**(code **)(DAT_000afbc8 + 0x48))();
                        }
                        *(undefined8 **)(lVar12 + uVar23 * 0x10) = puVar10;
                        *(ulonglong *)(lVar1 + 8) = uVar24;
                      }
                      (**(code **)(DAT_000afbc8 + 0x160))
                                ((longlong)puVar10 + uVar27,local_108,local_100);
                    }
                  }
LAB_00045084:
                  puVar10 = FUN_0001c6d0((ulonglong)*(uint *)(plVar28 + 1),&local_58);
                  if (puVar10 != (undefined8 *)0x0) {
                    if (local_f8 != (ushort *)0x0) {
                      (**(code **)(DAT_000afbc8 + 0x160))
                                ((ulonglong)uVar29 + (longlong)puVar10,local_f8,local_f0);
                    }
                    (**(code **)(DAT_000afbc8 + 0x160))
                              ((ulonglong)uVar29 + (longlong)puVar10,local_108,local_100);
                    if ((DAT_000aff78 != '\0') && (!bVar7)) {
                      local_80 = 0x71202eee;
                      local_7c = 0x40d95f53;
                      local_78 = 0xc9e3dab;
                      local_74 = 0x5766d926;
                      uVar14 = (**(code **)(DAT_000afbc8 + 0x18))(0x1f);
                      (**(code **)(DAT_000afbc8 + 0x20))(4);
                      FUN_00010704(&local_80);
                      (**(code **)(DAT_000afbc8 + 0x18))(0x1f);
                      (**(code **)(DAT_000afbc8 + 0x20))(uVar14);
                      bVar7 = true;
                    }
                    Observed_NativeCommit(*(uint *)(plVar28 + 1),(longlong)puVar10,local_58);
                    (**(code **)(DAT_000afbc8 + 0x48))(puVar10);
                  }
                  if (*(short *)((longlong)plVar28 + 0x14) == 0x13) {
                    (**(code **)(DAT_000afbc8 + 0x48))(local_108);
                  }
                  puVar16 = local_f8;
                  if (local_f8 == (ushort *)0x0) goto LAB_00044ae4;
                  goto LAB_00044ac5;
                }
              }
            }
          }
LAB_00044ae4:
          local_res18 = local_res18 + 1;
          uVar23 = (ulonglong)local_res18;
          puVar19 = DAT_000baaf0;
          lVar12 = local_50;
        } while (local_res18 < *(uint *)((longlong)plVar22 + 0x1c));
      }
      local_res20 = local_res20 + 1;
      uVar27 = (ulonglong)local_res20;
      uVar14 = local_d0;
    } while (local_res20 < *puVar19);
  }
  return uVar14;
}

