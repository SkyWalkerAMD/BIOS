
void FUN_00066ce8(uint param_1,uint param_2)

{
  char cVar1;
  byte bVar2;
  short sVar3;
  ushort uVar4;
  undefined2 uVar5;
  longlong lVar6;
  longlong lVar7;
  undefined8 *puVar8;
  undefined8 *puVar9;
  undefined8 *puVar10;
  ulonglong uVar11;
  longlong *plVar12;
  longlong *plVar13;
  short *psVar14;
  short *psVar15;
  byte bVar16;
  undefined4 uVar17;
  longlong *plVar18;
  longlong *plVar19;
  short *psVar20;
  longlong lVar21;
  longlong *plVar22;
  undefined1 uVar23;
  uint uVar24;
  ulonglong uVar25;
  ulonglong uVar26;
  longlong *plVar27;
  longlong *local_res18;
  short *local_res20;
  short local_98;
  uint local_94;
  uint local_90;
  longlong *local_88;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  short local_70 [4];
  ulonglong local_68;
  longlong local_60;
  longlong *local_58;
  undefined8 *local_50;
  undefined8 *local_48;
  longlong local_40;
  
  uVar25 = (ulonglong)param_1;
  uVar11 = (ulonglong)param_2;
  local_98 = 0;
  local_80 = 0x80e1202e;
  local_7c = 0x42642697;
  local_78 = 0x7680c99c;
  local_74 = 0x63583e2c;
  lVar6 = FUN_000b9550(DAT_00180758,0x781e);
  if ((lVar6 != 0) &&
     (lVar21 = DAT_001937b0, local_90 = param_1, local_68 = uVar25, local_40 = lVar6,
     param_1 < (uint)uVar11)) {
    do {
      uVar26 = local_68;
      uVar24 = (uint)uVar25;
      plVar27 = (longlong *)((ulonglong)*(uint *)(DAT_001937e8 + 4 + local_68 * 4) + DAT_001938e0);
      if ((plVar27 == (longlong *)0x0) || (*plVar27 != 0)) {
        local_res18 = plVar27;
        if (((DAT_0018f050 == 0) && (*(short *)((longlong)plVar27 + 10) == 1)) &&
           (plVar19 = (longlong *)
                      ((ulonglong)*(uint *)(lVar21 + 4 + (ulonglong)*(ushort *)(plVar27 + 1) * 4) +
                      lVar21), plVar19 != (longlong *)0x0)) {
          lVar7 = FUN_000b1b20((longlong *)&local_80,plVar19,0x10);
          uVar11 = (ulonglong)param_2;
          if (lVar7 == 0) goto LAB_0006769f;
        }
        if (*(short *)((longlong)plVar27 + 10) == 10000) {
          local_98 = (short)plVar27[2];
        }
        else {
          puVar8 = FUN_000b1010(1,0x58);
          if (puVar8 == (undefined8 *)0x0) {
            return;
          }
          puVar9 = puVar8;
          local_48 = puVar8;
          (**(code **)(DAT_00180188 + 0x160))(puVar8,&DAT_00136a60,0x58);
          *(undefined1 *)(puVar8 + 5) = 4;
          puVar9 = FUN_000b1010(puVar9,0x50);
          if (puVar9 == (undefined8 *)0x0) {
            return;
          }
          *(undefined4 *)puVar9 = 0x1000;
          puVar9[2] = plVar27;
          *(short *)(puVar9 + 9) = (short)plVar27[2];
          *(undefined2 *)((longlong)puVar9 + 0x4a) = *(undefined2 *)((longlong)plVar27 + 10);
          *(undefined4 *)((longlong)puVar9 + 4) = 0x10010;
          *puVar8 = puVar9;
          FUN_000b94b8(lVar6,(longlong)puVar8);
          puVar9 = FUN_000b1010(lVar6,0x58);
          if (puVar9 == (undefined8 *)0x0) {
            return;
          }
          puVar10 = FUN_000b1010(lVar6,0x50);
          lVar6 = DAT_00180188;
          if (puVar10 == (undefined8 *)0x0) {
            return;
          }
          *(undefined4 *)puVar10 = 0x1001;
          puVar10[2] = 0;
          (**(code **)(lVar6 + 0x160))(puVar9,&DAT_00139aa0,0x58);
          *puVar9 = puVar10;
          *(undefined1 *)(puVar9 + 5) = 4;
          puVar10 = puVar8;
          FUN_000b94b8((longlong)puVar8,(longlong)puVar9);
          plVar19 = FUN_000b1010(puVar10,0x58);
          if (plVar19 == (longlong *)0x0) {
            return;
          }
          plVar22 = plVar19;
          local_88 = plVar19;
          (**(code **)(DAT_00180188 + 0x160))(plVar19,&DAT_00136a00,0x58);
          *(undefined1 *)(plVar19 + 5) = 4;
          puVar9 = FUN_000b1010(plVar22,0x50);
          if (puVar9 == (undefined8 *)0x0) {
            return;
          }
          *(undefined4 *)puVar9 = 0x1000;
          puVar9[2] = plVar27;
          *(short *)(puVar9 + 9) = (short)plVar27[2];
          *(undefined2 *)((longlong)puVar9 + 0x4a) = *(undefined2 *)((longlong)plVar27 + 10);
          *(undefined4 *)((longlong)puVar9 + 4) = 0x10011;
          *plVar19 = (longlong)puVar9;
          FUN_000b94b8((longlong)puVar8,(longlong)plVar19);
          if ((*(short *)((longlong)plVar27 + 0x12) != local_98) &&
             (*(short *)((longlong)plVar27 + 0x12) != 0)) {
            FUN_00066870((longlong)plVar19,(longlong *)&local_res18);
            plVar27 = local_res18;
          }
          uVar11 = 0;
          local_94 = 0;
          if (*(int *)((longlong)plVar27 + 0x1c) != 0) {
            do {
              plVar22 = (longlong *)
                        ((ulonglong)*(uint *)((longlong)plVar27 + uVar11 * 4 + 0x20) + DAT_001937f8)
              ;
              sVar3 = FUN_00028634(plVar22,&local_60);
              if (sVar3 == -1) {
                FUN_0006c12c((longlong *)&local_88,plVar22,local_60,'\x01');
                plVar19 = local_88;
              }
              else {
                plVar13 = plVar22;
                cVar1 = FUN_0006d658((longlong)plVar22);
                if (cVar1 == '\0') {
                  plVar12 = FUN_000b1010(plVar13,0x58);
                  if (plVar12 == (longlong *)0x0) {
                    return;
                  }
                  puVar8 = FUN_000b1010(plVar13,0x50);
                  local_50 = FUN_000b1010(plVar13,0x50);
                  puVar9 = FUN_000b1010(plVar13,0x50);
                  uVar23 = 0;
                  local_res18 = (longlong *)((ulonglong)local_res18 & 0xffffffffffffff00);
                  bVar2 = FUN_00036f08((longlong)plVar22);
                  if (bVar2 == 0) {
                    uVar23 = 0;
LAB_0006703d:
                    local_res18 = (longlong *)CONCAT71(local_res18._1_7_,uVar23);
                  }
                  else {
                    if (bVar2 < 3) {
LAB_00067028:
                      uVar23 = 2;
                      goto LAB_0006703d;
                    }
                    if (bVar2 == 3) {
                      uVar23 = 1;
                      local_res18 = (longlong *)CONCAT71(local_res18._1_7_,1);
                    }
                    else if (bVar2 == 7) goto LAB_00067028;
                  }
                  *(undefined4 *)puVar8 = 0x1000;
                  puVar8[6] = &LAB_000682f8;
                  *(undefined4 *)((longlong)puVar8 + 4) = 0x10012;
                  puVar8[2] = plVar22;
                  *(undefined1 *)(puVar8 + 3) = uVar23;
                  *plVar12 = (longlong)puVar8;
                  *(undefined4 *)(plVar12 + 2) = 0x7d4;
                  *(undefined2 *)(plVar12 + 5) = 0x104;
                  *(undefined4 *)((longlong)plVar12 + 0x2c) = 0x10000;
                  if ((((plVar22 != (longlong *)0x0) && ((char *)plVar22[5] != (char *)0x0)) &&
                      (*(char *)plVar22[5] == '\x02')) ||
                     ((*(short *)((longlong)plVar22 + 0x14) == 8 ||
                      (*(short *)((longlong)plVar22 + 0x14) == 3)))) {
                    *(undefined4 *)((longlong)plVar12 + 0x2c) = 0x10020;
                  }
                  uVar17 = *(undefined4 *)((longlong)plVar12 + 0x2c);
                  if (*(short *)((longlong)plVar22 + 0x14) == 4 ||
                      *(short *)((longlong)plVar22 + 0x14) == 5) {
                    uVar17 = 0x10021;
                  }
                  *(undefined4 *)((longlong)plVar12 + 0x2c) = uVar17;
                  if ((*(short *)((longlong)plVar27 + 10) == 0x28a8) &&
                     (((((char *)plVar22[5] != (char *)0x0 && (*(char *)plVar22[5] == '\x02')) ||
                       (*(short *)((longlong)plVar22 + 0x14) == 8)) ||
                      (*(short *)((longlong)plVar22 + 0x14) == 3)))) {
                    *(undefined4 *)((longlong)plVar12 + 0x2c) = 0x10020;
                  }
                  FUN_000b94b8((longlong)plVar19,(longlong)plVar12);
                  if (*(short *)((longlong)plVar22 + 0x14) == 1) {
                    puVar8 = FUN_000b1010(plVar19,0x50);
                    puVar10 = FUN_000b1010(plVar19,0x58);
                    lVar6 = DAT_00180188;
                    *(undefined4 *)((longlong)puVar8 + 4) = 0;
                    *(undefined4 *)puVar8 = 0x1000;
                    puVar8[2] = plVar22;
                    *(undefined1 *)(puVar8 + 3) = local_res18._0_1_;
                    (**(code **)(lVar6 + 0x160))(puVar10,&DAT_001369a0);
                    *puVar10 = puVar8;
                    plVar19 = plVar12;
                    FUN_000b94b8((longlong)plVar12,(longlong)puVar10);
                    *(undefined4 *)((longlong)plVar12 + 0x2c) = 0x10022;
                    uVar23 = local_res18._0_1_;
                  }
                  psVar14 = (short *)0x0;
                  plVar13 = FUN_000b1010(plVar19,0x58);
                  *(undefined4 *)puVar9 = 0x1000;
                  *(undefined4 *)((longlong)puVar9 + 4) = 0x10000;
                  puVar9[2] = plVar22;
                  *(undefined1 *)(puVar9 + 3) = uVar23;
                  *plVar13 = (longlong)puVar9;
                  *(undefined4 *)(plVar13 + 1) = 0x69;
                  *(undefined4 *)((longlong)plVar13 + 0xc) = 0xc9;
                  *(undefined4 *)(plVar13 + 2) = 0x3e9;
                  *(undefined1 *)(plVar13 + 5) = 4;
                  uVar4 = *(ushort *)((longlong)plVar22 + 0x14);
                  if ((uVar4 < 0x1c) && ((0x8002002U >> (uVar4 & 0x1f) & 1) != 0)) {
                    *(undefined4 *)(plVar13 + 2) = 0x3ea;
                    *(undefined1 *)((longlong)plVar13 + 0x29) = 1;
                    *(undefined4 *)((longlong)plVar13 + 0x2c) = 0x10002;
                  }
                  else if (uVar4 == 8) {
                    *(undefined4 *)((longlong)plVar13 + 0x2c) = 0x1000d;
                  }
                  else if (((char *)plVar22[5] == (char *)0x0) || (*(char *)plVar22[5] != '\x02')) {
                    if (uVar4 == 3) {
                      *(undefined4 *)((longlong)plVar13 + 0x2c) = 0x10006;
                    }
                    else if (uVar4 == 10) {
                      *(undefined4 *)((longlong)plVar13 + 0x2c) = 0x10009;
                    }
                    else if (uVar4 == 6) {
                      *(undefined4 *)((longlong)plVar13 + 0x2c) = 0x1000b;
                    }
                    else {
                      *(undefined4 *)((longlong)plVar13 + 0x2c) = 0x10001;
                    }
                  }
                  else {
                    *(undefined4 *)((longlong)plVar13 + 0x2c) = 0x10005;
                  }
                  local_58 = plVar13;
                  if (*(short *)((longlong)plVar22 + 0x14) == 3) {
                    sVar3 = 0;
                    if (*(char *)plVar22[5] == '\x03') {
                      sVar3 = *(short *)((char *)plVar22[5] + 2);
                    }
                    if (sVar3 != -1) {
                      psVar14 = (short *)FUN_000484c8(*plVar22,sVar3,(short *)0x0);
                    }
                    psVar20 = &DAT_00170078;
                    for (psVar15 = psVar14; (*psVar15 != 0 && (*psVar15 == *psVar20));
                        psVar15 = psVar15 + 1) {
                      psVar20 = psVar20 + 1;
                    }
                    if (*psVar15 == *psVar20) {
                      *(undefined4 *)((longlong)plVar13 + 0x2c) = 0x7848;
                      *(undefined4 *)(plVar13 + 2) = 0x3fa;
                    }
                    local_res20 = psVar14;
                    FUN_000013d0((longlong *)&local_res20);
                  }
                  if (*(short *)((longlong)plVar27 + 10) == 0x28a8) {
                    if (((char *)plVar22[5] == (char *)0x0) || (*(char *)plVar22[5] != '\x02')) {
                      if ((*(short *)((longlong)plVar22 + 0x14) == 3) &&
                         (*(int *)((longlong)plVar13 + 0x2c) != 0x7848)) {
                        *(undefined4 *)((longlong)plVar13 + 0x2c) = 0x1001e;
                      }
                    }
                    else {
                      *(undefined4 *)((longlong)plVar13 + 0x2c) = 0x1001d;
                    }
                  }
                  FUN_000b94b8((longlong)plVar12,(longlong)plVar13);
                  plVar18 = plVar27;
                  lVar6 = FUN_000418f8((longlong)plVar27);
                  if (((char)lVar6 != '\0') &&
                     ((*(short *)((longlong)plVar22 + 0x14) == 6 ||
                      (*(short *)((longlong)plVar22 + 0x14) == 0x13)))) {
                    local_res20 = (short *)((ulonglong)local_res20 & 0xffffffffffffff00);
                    uVar4 = FUN_00026be4((byte *)plVar22[5]);
                    plVar18 = (longlong *)(ulonglong)uVar4;
                    cVar1 = (*(code *)PTR_FUN_0010b8f0)(plVar18,&local_res20);
                    if (cVar1 != '\0') {
                      plVar18 = plVar13;
                      bVar2 = (byte)local_res20;
                      FUN_000669fc((longlong)plVar13,(byte)local_res20);
                      if (bVar2 < 4) {
                        uVar23 = local_res18._0_1_;
                        uVar24 = 0;
                        do {
                          puVar8 = FUN_000b1010(plVar18,0x58);
                          puVar9 = FUN_000b1010(plVar18,0x50);
                          puVar10 = FUN_000b1010(plVar18,0x18);
                          uVar5 = FUN_00026be4((byte *)plVar22[5]);
                          *(undefined2 *)puVar10 = uVar5;
                          lVar6 = DAT_00180188;
                          *(undefined2 *)((longlong)puVar10 + 2) =
                               *(undefined2 *)((longlong)plVar27 + 10);
                          *(char *)((longlong)puVar10 + 4) = (char)uVar24;
                          puVar10[1] = plVar22;
                          *(undefined4 *)puVar9 = 0x1000;
                          *(undefined4 *)((longlong)puVar9 + 4) = 0x10005;
                          puVar9[2] = puVar10;
                          *(undefined1 *)(puVar9 + 3) = uVar23;
                          (**(code **)(lVar6 + 0x160))(puVar8,&DAT_00133190,0x58);
                          *(undefined4 *)(puVar8 + 1) = 0x75;
                          *(uint *)((longlong)puVar8 + 0x2c) = uVar24 + 0x7842;
                          *puVar8 = puVar9;
                          cVar1 = '\x01';
                          *(undefined1 *)(puVar8 + 5) = 4;
                          *(undefined2 *)((longlong)puVar9 + 0x2c) = 0x301;
                          plVar18 = plVar12;
                          FUN_000b94b8((longlong)plVar12,(longlong)puVar8);
                          bVar2 = (char)uVar24 + cVar1;
                          uVar24 = (uint)bVar2;
                          plVar13 = local_58;
                        } while (bVar2 <= (byte)local_res20);
                      }
                      else {
                        puVar8 = FUN_000b1010(plVar18,0x58);
                        puVar9 = FUN_000b1010(plVar18,0x50);
                        puVar10 = FUN_000b1010(plVar18,0x18);
                        uVar5 = FUN_00026be4((byte *)plVar22[5]);
                        *(undefined2 *)puVar10 = uVar5;
                        *(byte *)((longlong)puVar10 + 4) = (byte)local_res20;
                        *(undefined2 *)((longlong)puVar10 + 2) =
                             *(undefined2 *)((longlong)plVar27 + 10);
                        puVar10[1] = plVar22;
                        *(undefined1 *)(puVar9 + 3) = local_res18._0_1_;
                        lVar6 = DAT_00180188;
                        *(undefined4 *)puVar9 = 0x1000;
                        *(undefined4 *)((longlong)puVar9 + 4) = 0x10005;
                        puVar9[2] = puVar10;
                        (**(code **)(lVar6 + 0x160))(puVar8,&DAT_00133190,0x58);
                        *(undefined4 *)(puVar8 + 1) = 0x75;
                        *puVar8 = puVar9;
                        *(undefined1 *)(puVar8 + 5) = 4;
                        *(uint *)((longlong)puVar8 + 0x2c) =
                             0x7847 - (uint)((byte)local_res20 != -1);
                        *(undefined2 *)((longlong)puVar9 + 0x2c) = 0x301;
                        plVar18 = plVar12;
                        FUN_000b94b8((longlong)plVar12,(longlong)puVar8);
                      }
                      uVar23 = local_res18._0_1_;
                    }
                  }
                  plVar19 = local_88;
                  if ((((char *)plVar22[5] == (char *)0x0) || (*(char *)plVar22[5] != '\x02')) &&
                     (*(int *)((longlong)plVar13 + 0x2c) != 0x7848)) {
                    if ((*(short *)((longlong)plVar22 + 0x14) != 1) &&
                       (*(short *)((longlong)plVar22 + 0x14) != 0xd)) {
                      plVar19 = FUN_000b1010(plVar18,0x58);
                      puVar8 = FUN_000b1010(plVar18,0x50);
                      bVar16 = 0;
                      *(undefined4 *)puVar8 = 0x1000;
                      *(undefined4 *)((longlong)puVar8 + 4) = 0x10002;
                      puVar8[2] = plVar22;
                      *(undefined1 *)(puVar8 + 3) = uVar23;
                      bVar2 = *(byte *)((longlong)plVar22 + 0x1d);
                      if (bVar2 == 0) {
                        if ((*(uint *)((longlong)plVar22 + 0x1c) >> 5 & 1) != 0) {
                          local_70[0] = 0;
                          local_70[1] = 0x28d8;
                          local_70[2] = 0x28d9;
                          local_70[3] = 0x28da;
                          do {
                            if (local_70[bVar16] == *(short *)((longlong)plVar27 + 10)) {
                              if (*(short *)((longlong)plVar22 + 0x14) == 6) {
                                *(undefined2 *)((longlong)puVar8 + 0x2c) = 0x301;
                              }
                              break;
                            }
                            bVar16 = bVar16 + 1;
                          } while (bVar16 < 4);
                        }
                      }
                      else {
                        if (*(short *)((longlong)plVar22 + 0x14) == 4 ||
                            *(short *)((longlong)plVar22 + 0x14) == 5) {
                          bVar16 = 5;
                        }
                        else {
                          if (*(short *)((longlong)plVar22 + 0x14) == 0x1b) {
                            *(byte *)((longlong)puVar8 + 0x2c) = bVar2;
                            goto LAB_000675d9;
                          }
                          bVar16 = 10;
                        }
                        *(byte *)((longlong)puVar8 + 0x2c) = bVar2 / bVar16;
                      }
LAB_000675d9:
                      *plVar19 = (longlong)puVar8;
                      FUN_0006b6fc(plVar19,(longlong)plVar22);
                      *(undefined1 *)(plVar19 + 5) = 4;
                      if ((*(short *)((longlong)plVar27 + 10) == 0x28a8) &&
                         (*(short *)((longlong)plVar22 + 0x14) == 3)) {
                        *(undefined4 *)((longlong)plVar19 + 0x2c) = 0x1001f;
                      }
                      FUN_000b94b8((longlong)plVar12,(longlong)plVar19);
                      plVar18 = plVar12;
                    }
                    puVar8 = FUN_000b1010(plVar18,0x58);
                    *(undefined4 *)local_50 = 0x1000;
                    *(undefined4 *)((longlong)local_50 + 4) = 0x10001;
                    local_50[2] = plVar22;
                    *(undefined1 *)(local_50 + 3) = uVar23;
                    *puVar8 = local_50;
                    *(undefined4 *)(puVar8 + 1) = 0x69;
                    *(undefined4 *)((longlong)puVar8 + 0xc) = 0xc9;
                    *(undefined4 *)(puVar8 + 2) = 0x3e9;
                    *(undefined1 *)(puVar8 + 5) = 4;
                    *(undefined4 *)((longlong)puVar8 + 0x2c) = 0x10003;
                    plVar19 = local_88;
                  }
                }
              }
              local_94 = local_94 + 1;
              uVar11 = (ulonglong)local_94;
              puVar8 = local_48;
              uVar26 = local_68;
              uVar24 = local_90;
            } while (local_94 < *(uint *)((longlong)plVar27 + 0x1c));
          }
          FUN_0006da0c((longlong)puVar8,(int *)&DAT_001331f0);
          uVar11 = (ulonglong)param_2;
          lVar21 = DAT_001937b0;
          lVar6 = local_40;
        }
      }
LAB_0006769f:
      local_90 = uVar24 + 1;
      uVar25 = (ulonglong)local_90;
      local_68 = uVar26 + 1;
    } while (local_90 < (uint)uVar11);
  }
  return;
}

