ulonglong FUN_0002f3ac(longlong param_1,longlong param_2,ulonglong param_3,longlong *param_4,
                      uint *param_5,uint *param_6)
{
  bool bVar1;
  ushort uVar2;
  bool bVar3;
  bool bVar4;
  char cVar5;
  longlong lVar6;
  ushort uVar7;
  undefined2 uVar8;
  uint uVar9;
  byte *pbVar10;
  longlong *plVar11;
  undefined8 uVar12;
  ushort uVar13;
  int iVar14;
  uint uVar15;
  longlong lVar16;
  int iVar17;
  longlong lVar18;
  uint uVar19;
  byte *pbVar20;
  undefined2 *puVar21;
  undefined1 *puVar22;
  ushort uVar23;
  ulonglong uVar24;
  undefined2 uVar25;
  ulonglong uVar26;
  byte *pbVar27;
  ulonglong uVar28;
  byte bVar29;
  bool bVar30;
  undefined2 local_b0;
  byte *local_a0;
  byte local_98;
  char local_97;
  uint local_94;
  ushort local_90;
  short local_8e;
  undefined2 local_8c;
  undefined2 local_8a;
  int local_88;
  longlong local_80;
  longlong local_78;
  uint local_70;
  uint local_6c;
  ulonglong local_68;
  longlong *local_60;
  longlong *local_58;
  undefined8 *local_50;
  longlong local_48;
  longlong local_40;
  byte *local_38;
  uVar24 = 0;
  bVar3 = true;
  local_a0 = (byte *)0x0;
  bVar4 = false;
  local_98 = 0;
  local_8e = 0;
  local_6c = 0;
  local_88 = 0;
  local_58 = (longlong *)0x0;
  local_50 = (undefined8 *)0x0;
  local_68 = 0;
  local_40 = 0;
  local_97 = '\0';
  local_8a = 0;
  local_78 = 0;
  if (param_3 != 0) {
    do {
      uVar24 = local_68;
      uVar23 = 0;
      uVar13 = 0;
      bVar1 = true;
      FUN_0010749e(&local_94,4,0);
      pbVar20 = (byte *)(param_2 + uVar24);
      uVar7 = 0;
      local_80 = CONCAT44(local_80._4_4_,0xffff);
      DAT_0018f164 = 0;
      local_94 = local_94 | 1;
      local_38 = pbVar20;
      if (0x7f < pbVar20[1]) {
        FUN_00039610(*pbVar20);
      }
      bVar29 = *pbVar20;
      uVar2 = uVar7;
      if (bVar29 < 0x2a) {
        if (bVar29 == 0x29) {
          FUN_0003967c(&local_98);
          if (local_98 == 1) {
LAB_0002f70f:
            local_40 = 1;
            uVar24 = uVar24 + (pbVar20[1] & 0x7f);
            local_68 = uVar24;
          }
          else {
            if (local_98 != 10) {
              if (local_98 < 0x10) {
LAB_0002f6e2:
                uVar13 = 0;
                goto LAB_0002f724;
              }
              if ((0x1e < local_98) || ((0x4203ffffU >> (local_98 & 0x1f) & 1) == 0)) {
                if (local_98 == 0x5d) goto LAB_0002f70f;
                if (local_98 != 99) goto LAB_0002f6e2;
              }
            }
            local_88 = local_88 + -1;
            uVar13 = ~-(ushort)(local_88 != 0) & 0x8001;
          }
LAB_0002f724:
          bVar1 = false;
          uVar2 = uVar13;
        }
        else if (bVar29 < 0x11) {
          if (bVar29 == 0x10) {
            uVar13 = 0x16;
            uVar2 = 0x16;
          }
          else if (bVar29 < 0xb) {
            if (bVar29 == 10) {
LAB_0002f680:
              uVar23 = 0x8000;
              uVar7 = 0x8000;
LAB_0002f688:
              bVar1 = false;
              uVar13 = uVar23;
              uVar2 = uVar7;
            }
            else if (bVar29 == 2) {
              uVar13 = 8;
              uVar2 = uVar13;
            }
            else {
              uVar13 = 3;
              uVar2 = uVar13;
              if (bVar29 != 3) {
                if (bVar29 < 5) goto LAB_0002f688;
                uVar13 = 6;
                uVar2 = uVar13;
                if (6 < bVar29) {
                  if (bVar29 == 7) {
                    uVar13 = 0xb;
                    uVar2 = uVar13;
                  }
                  else {
                    if (bVar29 != 8) goto LAB_0002f688;
                    uVar13 = 0xd;
                    uVar2 = uVar13;
                  }
                }
              }
            }
          }
          else if (bVar29 == 0xb) {
            local_97 = '\x01';
            uVar13 = uVar7;
          }
          else if (bVar29 == 0xc) {
            uVar13 = 0x1b;
            uVar2 = uVar13;
          }
          else if (bVar29 == 0xd) {
            uVar13 = 0x1c;
            uVar2 = uVar13;
          }
          else {
            if (bVar29 != 0xf) goto LAB_0002f688;
            uVar13 = 1;
            uVar7 = FUN_0002d124((ulonglong)*(ushort *)(uVar24 + 0xd + param_2));
            local_80 = CONCAT62(local_80._2_6_,uVar7);
            uVar2 = uVar13;
            if (0x10 < (pbVar20[1] & 0x7f)) {
              local_8a = *(undefined2 *)(uVar24 + 0xf + param_2);
            }
          }
        }
        else if (bVar29 < 0x1c) {
          if (bVar29 == 0x1b) {
            uVar13 = 5;
            uVar2 = uVar13;
          }
          else if (bVar29 == 0x11) {
            uVar13 = 0x15;
            uVar2 = uVar13;
          }
          else if (bVar29 == 0x18) {
            local_a0 = pbVar20 + 3;
            uVar13 = 0x1d;
            uVar2 = 0x1d;
          }
          else {
            if (bVar29 == 0x19) goto LAB_0002f680;
            if (bVar29 != 0x1a) goto LAB_0002f688;
            uVar13 = 4;
            uVar2 = uVar13;
          }
        }
        else if (bVar29 == 0x1c) {
          uVar13 = 0x13;
          uVar2 = uVar13;
        }
        else {
          if (bVar29 == 0x1e) goto LAB_0002f680;
          if (bVar29 != 0x23) {
            if (bVar29 - 0x24 < 3) {
              FUN_0002c8e4((char *)pbVar20,param_1);
              goto LAB_0002f660;
            }
            goto LAB_0002f688;
          }
          uVar13 = 0xf;
          uVar2 = uVar13;
        }
      }
      else if (bVar29 == 0x5f) {
        lVar18 = FUN_000b1b20((longlong *)(pbVar20 + 2),(longlong *)&DAT_0010a588,0x10);
        bVar1 = false;
        uVar13 = 0;
        if (lVar18 == 0) {
          bVar4 = true;
        }
      }
      else if (bVar29 == 0x61) {
        *(uint *)(*param_4 + 0x14) = *(uint *)(*param_4 + 0x14) | 0x10;
        uVar13 = uVar7;
      }
      else if (bVar29 == 0x62) {
        *(uint *)(*param_4 + 0x14) = *(uint *)(*param_4 + 0x14) | 0x80;
        (**(code **)(DAT_00180188 + 0x160))(&DAT_00193700,pbVar20 + 2,0x10);
LAB_0002f660:
        bVar1 = false;
        uVar13 = 0;
      }
      else {
        if (bVar29 != 99) goto LAB_0002f688;
        uVar13 = 0x20;
        uVar2 = uVar13;
      }
      if (0x14 < uVar13) {
        if (((uVar13 < 0x17) || (uVar13 == 0x20)) || (uVar13 == 0x8000)) {
          if ((bVar3) && (bVar3 = false, local_a0 = pbVar20, DAT_0018f151 == '\x01')) {
            local_a0 = DAT_0018f158;
          }
          local_88 = local_88 + 1;
        }
        else if (uVar13 == 0x8001) {
          bVar3 = true;
          local_a0 = (byte *)0x0;
          local_88 = 0;
        }
      }
      if (local_40 == 1) {
        return uVar24;
      }
      if (bVar1) {
        bVar29 = *pbVar20;
        local_70 = local_70 & 0xffff0000;
        local_90 = 0;
        if (4 < bVar29) {
          if (bVar29 < 9) {
LAB_0002f854:
            local_90 = *(ushort *)(pbVar20 + 6);
          }
          else if (0xb < bVar29) {
            if (((bVar29 & 0xf0) == 0) && (bVar29 != 0xe)) goto LAB_0002f854;
            if (bVar29 == 0x18) {
              local_90 = (ushort)pbVar20[2];
            }
            else if (((byte)(bVar29 - 0x1a) < 3) || (bVar29 == 0x23)) goto LAB_0002f854;
          }
        }
        lVar16 = 0;
        local_8c = 0;
        bVar30 = false;
        pbVar10 = pbVar20;
        lVar18 = lVar16;
        if (0x7f < pbVar20[1]) {
          do {
            if (*pbVar10 == 0x27) {
              local_8c = *(undefined2 *)(pbVar20 + lVar18 + 2);
              bVar30 = true;
            }
            else if (*pbVar10 == 0x29) {
              lVar16 = lVar16 + -1;
            }
            else if (0x7f < pbVar10[1]) {
              lVar16 = lVar16 + 1;
            }
            lVar18 = lVar18 + (ulonglong)(pbVar10[1] & 0x7f);
            pbVar10 = pbVar20 + lVar18;
          } while ((lVar16 != 0) || (bVar30));
        }
        bVar29 = *pbVar20;
        local_b0 = 0;
        if (bVar29 < 0xd) {
          if ((bVar29 != 0xc) &&
             ((((bVar29 != 3 && (bVar29 != 5)) && (bVar29 != 6)) && (bVar29 != 7)))) {
            if (bVar29 == 8) {
LAB_0002f8f2:
              local_b0 = *(undefined2 *)(pbVar20 + 4);
            }
            goto LAB_0002f93b;
          }
LAB_0002f928:
          local_b0 = *(undefined2 *)(pbVar20 + 4);
        }
        else {
          if ((bVar29 == 0xd) || (bVar29 == 0xf)) goto LAB_0002f928;
          if (0x19 < bVar29) {
            if (bVar29 < 0x1c) goto LAB_0002f928;
            if ((bVar29 == 0x1c) || (bVar29 == 0x23)) goto LAB_0002f8f2;
          }
        }
LAB_0002f93b:
        uVar25 = 0;
        if (0x23 < bVar29) goto LAB_0002f98c;
        if (bVar29 == 0x23) {
LAB_0002f988:
          uVar25 = *(undefined2 *)(pbVar20 + 2);
        }
        else if (bVar29 < 9) {
          if (((bVar29 == 8) || (((bVar29 == 2 || (bVar29 == 3)) || (bVar29 == 5)))) ||
             ((bVar29 == 6 || (bVar29 == 7)))) goto LAB_0002f988;
        }
        else if ((((bVar29 == 0xc) || (bVar29 == 0xd)) || (bVar29 == 0xf)) ||
                ((0x19 < bVar29 && ((bVar29 < 0x1c || (bVar29 == 0x1c)))))) goto LAB_0002f988;
LAB_0002f98c:
        if (bVar4) {
          local_94 = local_94 | 0x80000;
          bVar4 = false;
        }
        DAT_0018f160 = FUN_0002dabc(param_1,pbVar20,(ushort *)&local_70,&local_58,&local_50,
                                    &local_78,&local_94,(char *)local_a0);
        uVar19 = local_70;
        if (local_97 != '\0') {
          local_94 = local_94 | 0x10;
        }
        uVar7 = (ushort)local_70;
        if ((ushort)local_70 == 1) {
          iVar14 = (uint)DAT_0018f160 * 4 + 2;
        }
        else {
          iVar14 = (DAT_0018f160 + 1) * (local_70 & 0xffff) * 2;
        }
        local_70 = iVar14 + 0x40;
        plVar11 = (longlong *)FUN_000014c8((ulonglong)local_70);
        bVar29 = DAT_0018f160;
        pbVar20 = (byte *)0x0;
        if (plVar11 == (longlong *)0x0) {
          return param_3;
        }
        if ((uVar2 == 0x15) || (pbVar10 = local_38, uVar13 = uVar2, uVar2 == 0x20)) {
          uVar13 = 9;
          pbVar10 = pbVar20;
        }
        if (uVar13 == 0x16) {
          uVar13 = 0x16;
          pbVar10 = pbVar20;
        }
        *plVar11 = param_1;
        *(undefined4 *)(plVar11 + 1) = DAT_0018f164;
        *(ushort *)((longlong)plVar11 + 0xc) = local_90;
        *(undefined2 *)((longlong)plVar11 + 0xe) = local_8c;
        *(byte *)(plVar11 + 2) = bVar29;
        *(ushort *)((longlong)plVar11 + 0x14) = uVar13 & 0xfff;
        if (DAT_00193638 == (undefined2 *)0x0) {
          uVar8 = 1;
        }
        else {
          uVar8 = *DAT_00193638;
        }
        *(undefined2 *)((longlong)plVar11 + 0x16) = uVar8;
        *(short *)(plVar11 + 3) = (short)local_80;
        *(undefined2 *)((longlong)plVar11 + 0x12) = local_8a;
        *(uint *)((longlong)plVar11 + 0x1c) = local_94;
        *(undefined2 *)(plVar11 + 4) = local_b0;
        *(undefined2 *)((longlong)plVar11 + 0x22) = 0;
        *(short *)((longlong)plVar11 + 0x24) = local_8e;
        *(undefined2 *)((longlong)plVar11 + 0x26) = *(undefined2 *)(*param_4 + 8);
        pbVar27 = local_a0;
        if (DAT_0018f151 == '\x01') {
          pbVar27 = DAT_0018f158;
        }
        plVar11[5] = (longlong)pbVar10;
        plVar11[6] = (longlong)pbVar27;
        *(ushort *)(plVar11 + 7) = uVar7;
        *(ushort *)((longlong)plVar11 + 0x3a) = uVar7;
        *(undefined2 *)((longlong)plVar11 + 0x3c) = uVar25;
        if (bVar4) {
          *(uint *)((longlong)plVar11 + 0x1c) = *(uint *)((longlong)plVar11 + 0x1c) | 0x80000;
          bVar4 = false;
        }
        if ((0x7f < local_38[1]) && (uVar13 != 0)) {
          bVar30 = true;
          if (*local_38 == 2) {
            bVar30 = local_38[local_38[1] & 0x7f] == 0x29;
          }
          if ((pbVar10 != (byte *)0x0) && (bVar30)) {
            bVar30 = true;
            pbVar27 = (byte *)0x0;
            do {
              uVar15 = (uint)pbVar20;
              bVar29 = pbVar10[(longlong)pbVar27];
              if (bVar29 == 0x22) {
LAB_0002fb9f:
                *(uint *)((longlong)plVar11 + 0x1c) = *(uint *)((longlong)plVar11 + 0x1c) | 0x20000;
LAB_0002fba4:
                uVar15 = (uint)pbVar20;
                bVar30 = false;
              }
              else if (bVar29 == 0x29) {
                uVar9 = uVar15 - 1;
                if (uVar15 == 0) {
                  uVar9 = uVar15;
                }
                uVar15 = uVar9;
                pbVar20 = (byte *)0x0;
                if (uVar15 == 0) goto LAB_0002fba4;
              }
              else if (bVar29 == 0x2d || bVar29 == 0x2e) goto LAB_0002fb9f;
              pbVar20 = pbVar10 + 1 + (longlong)pbVar27;
              pbVar27 = pbVar27 + (*pbVar20 & 0x7f);
              uVar9 = uVar15 + 1;
              if (*pbVar20 < 0x80) {
                uVar9 = uVar15;
              }
              pbVar20 = (byte *)(ulonglong)uVar9;
              bVar29 = DAT_0018f160;
            } while (bVar30);
          }
        }
        uVar24 = 0;
        local_60 = plVar11;
        if (uVar7 != 0) {
          local_80 = local_78;
          uVar15 = uVar19 & 0xffff;
          if (uVar15 == 1) {
            uVar26 = (ulonglong)uVar7;
            *(char *)(plVar11 + 8) = (char)*local_58;
            *(undefined1 *)(uVar26 + 0x40 + (longlong)plVar11) = *(undefined1 *)local_50;
            if (bVar29 != 0) {
              puVar22 = (undefined1 *)((longlong)plVar11 + uVar26 * 2 + 0x42);
              do {
                (**(code **)(DAT_00180188 + 0x160))(puVar22 + -2,local_80,2);
                uVar24 = uVar24 + 1;
                *puVar22 = *(undefined1 *)(local_80 + 8);
                puVar22 = puVar22 + uVar26 * 2 + 2;
                local_80 = *(longlong *)(local_80 + 0x10);
              } while (uVar24 < DAT_0018f160);
            }
          }
          else if (uVar15 == 2) {
            uVar26 = (ulonglong)uVar7;
            *(short *)(plVar11 + 8) = (short)*local_58;
            *(undefined2 *)(uVar26 + 0x40 + (longlong)plVar11) = *(undefined2 *)local_50;
            if (bVar29 != 0) {
              puVar21 = (undefined2 *)((longlong)plVar11 + uVar26 * 2 + 0x42);
              do {
                (**(code **)(DAT_00180188 + 0x160))(puVar21 + -1,local_80,2);
                uVar24 = uVar24 + 1;
                *puVar21 = *(undefined2 *)(local_80 + 8);
                puVar21 = (undefined2 *)((longlong)puVar21 + uVar26 + 2);
                local_80 = *(longlong *)(local_80 + 0x10);
              } while (uVar24 < DAT_0018f160);
            }
          }
          else if (uVar15 == 4) {
            uVar26 = (ulonglong)uVar7;
            *(int *)(plVar11 + 8) = (int)*local_58;
            *(undefined4 *)(uVar26 + 0x40 + (longlong)plVar11) = *(undefined4 *)local_50;
            if (bVar29 != 0) {
              lVar18 = (longlong)plVar11 + (uVar26 + 0x20) * 2;
              local_48 = uVar26 * 2;
              do {
                (**(code **)(DAT_00180188 + 0x160))(lVar18,local_80,2);
                uVar24 = uVar24 + 1;
                *(undefined4 *)((8 - uVar26) + lVar18) = *(undefined4 *)(local_80 + 8);
                lVar18 = lVar18 + local_48;
                local_80 = *(longlong *)(local_80 + 0x10);
              } while (uVar24 < DAT_0018f160);
            }
          }
          else if (uVar15 == 8) {
            uVar26 = (ulonglong)uVar7;
            plVar11[8] = *local_58;
            *(undefined8 *)(uVar26 + 0x40 + (longlong)plVar11) = *local_50;
            if (bVar29 != 0) {
              lVar18 = (longlong)plVar11 + (uVar26 + 0x20) * 2;
              local_48 = uVar26 * 2;
              do {
                (**(code **)(DAT_00180188 + 0x160))(lVar18,local_80,2);
                uVar24 = uVar24 + 1;
                *(undefined8 *)((0x10 - uVar26) + lVar18) = *(undefined8 *)(local_80 + 8);
                lVar18 = lVar18 + local_48;
                local_80 = *(longlong *)(local_80 + 0x10);
              } while (uVar24 < DAT_0018f160);
            }
          }
          else {
            uVar19 = uVar19 & 0xffff;
            (**(code **)(DAT_00180188 + 0x160))(plVar11 + 8,local_58,uVar19);
            (**(code **)(DAT_00180188 + 0x160))
                      ((longlong)plVar11 + (ulonglong)uVar7 + 0x40,local_50,uVar19);
          }
        }
        plVar11 = local_60;
        lVar6 = local_78;
        lVar18 = local_78;
        lVar16 = local_48;
        if (((char *)local_60[5] != (char *)0x0) && (*(char *)local_60[5] == '\x06')) {
          uVar12 = FUN_0002a6cc((longlong)local_60);
          *(short *)((longlong)plVar11 + 0x14) = (short)uVar12;
          lVar18 = local_78;
          lVar16 = local_48;
        }
        while (local_48 = lVar6, local_48 != 0) {
          lVar18 = *(longlong *)(local_48 + 0x10);
          FUN_000013d0(&local_48);
          lVar6 = lVar18;
          lVar16 = local_48;
        }
        local_78 = lVar18;
        local_48 = lVar16;
        local_6c = FUN_0003006c(plVar11,local_70);
        FUN_000305f8(param_4,param_5,param_6,&local_6c,4);
        FUN_000013d0((longlong *)&local_60);
        if ((uVar13 & 0xf000) != 0) {
          local_6c = 0;
          FUN_000305f8(param_4,param_5,param_6,&local_6c,4);
        }
        local_8e = local_8e + 1;
        pbVar20 = local_38;
      }
      FUN_000013d0((longlong *)&local_58);
      FUN_000013d0((longlong *)&local_50);
      uVar24 = local_68;
      cVar5 = DAT_0018f151;
      uVar28 = (ulonglong)(pbVar20[1] & 0x7f);
      uVar26 = uVar28;
      if (((0x7f < pbVar20[1]) && (uVar13 != 0)) && (bVar1)) {
        iVar14 = 0;
        bVar1 = true;
        if ((*pbVar20 != 2) || (pbVar20[uVar28] == 0x29)) {
          lVar18 = local_68 + param_2;
          do {
            if (*(char *)(lVar18 + uVar26) == '\t') {
LAB_0002ff8f:
              bVar29 = *(byte *)(lVar18 + 1 + uVar26);
              iVar17 = iVar14;
LAB_0002ff9b:
              uVar26 = uVar26 + (bVar29 & 0x7f);
              iVar14 = iVar17;
            }
            else {
              if (*(char *)(lVar18 + uVar26) != ')') {
                bVar29 = *(byte *)(lVar18 + 1 + uVar26);
                iVar17 = iVar14 + 1;
                if (bVar29 < 0x80) {
                  iVar17 = iVar14;
                }
                goto LAB_0002ff9b;
              }
              if (iVar14 != 0) {
                iVar14 = iVar14 + -1;
                goto LAB_0002ff8f;
              }
              bVar1 = false;
            }
          } while (bVar1);
        }
      }
      if (((DAT_0018f168 != '\0') || (DAT_0018f150 != '\0')) || (DAT_0018f148 != '\0')) {
        DAT_0018f161 = 1;
        DAT_0018f168 = '\0';
        DAT_0018f150 = '\0';
        DAT_0018f148 = '\0';
        DAT_0018f151 = 0;
        FUN_0002f3ac(param_1,uVar28 + local_68 + param_2,uVar26 - uVar28,param_4,param_5,param_6);
        DAT_0018f161 = 0;
      }
      uVar24 = uVar24 + uVar26;
      DAT_0018f151 = cVar5;
      local_68 = uVar24;
    } while (uVar24 < param_3);
  }
  return uVar24;
}