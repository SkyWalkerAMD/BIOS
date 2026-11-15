char FUN_0002dabc(longlong param_1,byte *param_2,ushort *param_3,undefined8 *param_4,
                 undefined8 *param_5,longlong *param_6,uint *param_7,char *param_8)
{
  short *psVar1;
  byte *pbVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  bool bVar6;
  bool bVar7;
  bool bVar8;
  longlong lVar9;
  byte bVar10;
  short sVar11;
  byte *pbVar12;
  byte *pbVar13;
  short *psVar14;
  undefined2 *puVar15;
  longlong lVar16;
  short *psVar17;
  uint uVar18;
  uint uVar19;
  ulonglong uVar20;
  byte *pbVar21;
  byte bVar22;
  int iVar23;
  ulonglong uVar24;
  short *psVar25;
  ulonglong uVar26;
  longlong lVar27;
  ushort *puVar28;
  undefined8 in_stack_ffffffffffffff70;
  byte local_78;
  byte local_77;
  int local_74;
  char local_6c;
  byte local_6b;
  ushort local_68 [2];
  uint local_64;
  ulonglong *local_60;
  short *local_58;
  byte *local_50;
  byte *local_48;
  longlong local_40;
  local_64 = (uint)param_1 & 0xffffff00;
  local_78 = 0;
  psVar14 = (short *)0x0;
  local_40 = 0;
  local_74 = 0;
  local_6c = '\0';
  bVar5 = false;
  local_60 = (ulonglong *)0x0;
  uVar26 = 1;
  local_6b = 0;
  local_77 = 0;
  local_68[0] = 1;
  local_58 = (short *)0x0;
  bVar4 = false;
  bVar3 = false;
  bVar8 = false;
  bVar7 = false;
  bVar6 = true;
  pbVar12 = (byte *)FUN_000014c8(8);
  if (pbVar12 == (byte *)0x0) {
    return '\0';
  }
  local_48 = pbVar12;
  pbVar13 = (byte *)FUN_000014c8(8);
  local_50 = pbVar13;
  if (pbVar13 == (byte *)0x0) {
    FUN_000013d0((longlong *)pbVar12);
    return '\0';
  }
  do {
    pbVar2 = param_2 + local_74;
    bVar22 = *pbVar2;
    if (0x23 < bVar22) {
      if (bVar22 == 0x29) {
        uVar19 = (uint)local_78;
        if (local_40 != 0) {
          local_40 = local_40 + -1;
        }
        goto LAB_0002dc4b;
      }
      if (bVar22 == 0x50) {
        if (bVar7) {
          *param_7 = *param_7 | 0x40;
          bVar7 = false;
        }
        *param_3 = 0;
      }
      else if (bVar22 == 0x5b) {
        if (bVar6) {
          if (pbVar2[4] == 0xb) {
            *param_3 = (pbVar2[1] & 0x7f) - 5;
          }
          else if (pbVar2[4] == 0xc) {
            *param_3 = 0x16;
          }
          pbVar21 = pbVar2;
          iVar23 = local_74;
          if (0x7f < pbVar2[1]) {
            do {
              iVar23 = iVar23 + (pbVar21[1] & 0x7f);
              pbVar21 = param_2 + iVar23;
              bVar22 = *pbVar21;
              if ((bVar22 == 0x50) || (bVar22 == 0x22)) {
                bVar7 = true;
                break;
              }
            } while (bVar22 != 0x29);
          }
          if ((pbVar2[1] < 0x80) || (pbVar2[4] < 0xc)) {
            sVar11 = *(short *)(pbVar2 + 2);
            if (sVar11 == 0) {
              if (bVar5) {
                if (8 < uVar26 * local_77) {
                  pbVar13 = (byte *)FUN_00001450((longlong)pbVar13,8,uVar26 * local_77);
                  local_64 = ((uint)uVar26 & 0xff) * (uint)local_77;
                  local_50 = pbVar13;
                }
              }
              else if (8 < *param_3) {
                pbVar13 = (byte *)FUN_00001450((longlong)pbVar13,8,(ulonglong)*param_3);
                local_50 = pbVar13;
              }
              FUN_0002ce68(pbVar2[4],(char *)(pbVar2 + 5),param_3,(char *)pbVar13,(longlong)pbVar2);
              if ((*param_3 == 0) && (pbVar2[4] == 8)) {
                *param_7 = *param_7 | 0x40;
              }
              else if ((char)local_64 != '\0') {
                *param_3 = (ushort)local_64 & 0xff;
              }
              bVar3 = true;
            }
            else if ((sVar11 == 0x20) || (sVar11 == 1)) {
              if (bVar5) {
                if (8 < uVar26 * local_77) {
                  pbVar12 = (byte *)FUN_00001450((longlong)pbVar12,8,uVar26 * local_77);
                  local_64 = CONCAT31(local_64._1_3_,(char)uVar26 * local_77);
                  local_48 = pbVar12;
                }
              }
              else if (8 < *param_3) {
                pbVar12 = (byte *)FUN_00001450((longlong)pbVar12,8,(ulonglong)*param_3);
                local_48 = pbVar12;
              }
              FUN_0002ce68(pbVar2[4],(char *)(pbVar2 + 5),param_3,(char *)pbVar12,(longlong)pbVar2);
              if ((*param_3 == 0) && (pbVar2[4] == 8)) {
                *param_7 = *param_7 | 0x40;
              }
              else if ((char)local_64 != '\0') {
                *param_3 = (ushort)local_64 & 0xff;
              }
              bVar4 = true;
            }
          }
          else {
            *param_7 = *param_7 | 0x40;
          }
          if (pbVar2[4] != 0xc) {
            lVar27 = *param_6;
            if (lVar27 == 0) {
              puVar15 = (undefined2 *)FUN_000014c8(0x18);
              *param_6 = (longlong)puVar15;
            }
            else {
              lVar9 = *(longlong *)(lVar27 + 0x10);
              while (lVar16 = lVar9, lVar16 != 0) {
                lVar27 = lVar16;
                lVar9 = *(longlong *)(lVar16 + 0x10);
              }
              puVar15 = (undefined2 *)FUN_000014c8(0x18);
              *(undefined2 **)(lVar27 + 0x10) = puVar15;
            }
            *puVar15 = *(undefined2 *)(pbVar2 + 2);
            if ((bVar5) && (bVar22 = 0xb, pbVar2[4] == 0xb)) {
              puVar28 = local_68;
            }
            else {
              bVar22 = pbVar2[4];
              puVar28 = param_3;
            }
            FUN_0002ce68(bVar22,(char *)(pbVar2 + 5),puVar28,(char *)(puVar15 + 4),(longlong)pbVar2)
            ;
            if ((*param_3 == 0) && (pbVar2[4] == 8)) {
              *param_7 = *param_7 | 0x40;
            }
            else if ((char)local_64 != '\0') {
              *param_3 = (ushort)local_64 & 0xff;
            }
            uVar26 = (ulonglong)local_68[0];
            local_6c = local_6c + '\x01';
          }
          if ((!bVar5) || (pbVar2[4] != 0xb)) goto LAB_0002df32;
          sVar11 = *(short *)(pbVar2 + 2);
          if (sVar11 == 0) {
            FUN_000317b8((longlong)pbVar2,(ulonglong)local_58,local_77,uVar26,local_60,
                         in_stack_ffffffffffffff70,(longlong *)&local_50);
            pbVar13 = local_50;
          }
          else {
            if ((sVar11 != 0x20) && (sVar11 != 1)) goto LAB_0002df32;
            FUN_000317b8((longlong)pbVar2,(ulonglong)local_58,local_77,uVar26,local_60,
                         in_stack_ffffffffffffff70,(longlong *)&local_48);
            pbVar12 = local_48;
          }
        }
      }
      else {
        if (bVar22 != 0x62) {
          if (bVar22 == 99) {
            uVar19 = (uint)local_78;
            if (DAT_0018f161 == '\0') {
              DAT_0018f148 = 1;
            }
          }
          else {
LAB_0002df94:
            uVar19 = (uint)local_78;
          }
          goto LAB_0002dc4b;
        }
        (**(code **)(DAT_00180188 + 0x160))(&DAT_00193710,pbVar2 + 2,0x10);
        *param_7 = *param_7 | 0x10000;
      }
LAB_0002dc41:
      uVar19 = (uint)local_78;
      goto LAB_0002dc4b;
    }
    if (bVar22 == 0x23) {
      lVar27 = param_1;
      DAT_0018f164 = FUN_0002d160((uint)*(ushort *)(pbVar2 + 8),param_1,pbVar2);
      local_77 = pbVar2[0xd];
      local_78 = pbVar2[0xc];
      psVar14 = (short *)(ulonglong)*(ushort *)(pbVar2 + 10);
      local_64 = (uint)CONCAT71((int7)((ulonglong)lVar27 >> 8),local_77);
      bVar5 = true;
      local_58 = psVar14;
      goto LAB_0002df32;
    }
    if (bVar22 < 0x10) {
      if (bVar22 == 0xf) {
        local_78 = pbVar2[0xc];
        uVar19 = (uint)local_78;
      }
      else {
        if (bVar22 == 5) {
          DAT_0018f164 = FUN_0002d160((uint)*(ushort *)(pbVar2 + 8),param_1,pbVar2);
          bVar22 = pbVar2[0xd];
          local_78 = pbVar2[0xc];
LAB_0002df23:
          local_64 = (uint)(byte)('\x01' << (bVar22 & 0xf));
          psVar14 = (short *)(ulonglong)*(ushort *)(pbVar2 + 10);
          goto LAB_0002df32;
        }
        if (bVar22 == 6) {
          DAT_0018f164 = FUN_0002d160((uint)*(ushort *)(param_2 + 8),param_1,param_2);
          bVar22 = param_2[0xd];
          local_78 = param_2[0xc];
          psVar14 = (short *)(ulonglong)*(ushort *)(param_2 + 10);
          bVar10 = bVar22 & 1;
          *pbVar13 = bVar10;
          if (bVar10 != 0) {
            *param_3 = 1;
          }
          bVar22 = bVar22 >> 1 & 1;
          *pbVar12 = bVar22;
          if (bVar22 != 0) {
            *param_3 = 1;
            bVar8 = true;
          }
          *(undefined1 *)((longlong)param_7 + 1) = 0;
          local_64 = CONCAT31(local_64._1_3_,1);
          goto LAB_0002df32;
        }
        if (bVar22 == 7) {
          *(undefined1 *)((longlong)param_7 + 1) = 0;
          local_78 = pbVar2[0xc];
          DAT_0018f164 = FUN_0002d160((uint)*(ushort *)(pbVar2 + 8),param_1,pbVar2);
          bVar22 = pbVar2[0xd];
          goto LAB_0002df23;
        }
        if (bVar22 == 8) goto LAB_0002de39;
        if (bVar22 != 9) {
          if (bVar22 == 0xb) {
            uVar19 = local_78 | 1;
            local_78 = local_78 | 1;
            goto LAB_0002dc4b;
          }
          if (bVar22 == 0xc) {
            local_78 = param_2[0xc];
            DAT_0018f164 = FUN_0002d160((uint)*(ushort *)(param_2 + 8),param_1,param_2);
            if ((param_8 != (char *)0x0) &&
               (sVar11 = FUN_00027464(param_8,(char *)param_2), sVar11 == 0xb)) {
              *(undefined1 *)((longlong)param_7 + 1) = 1;
              goto LAB_0002df32;
            }
          }
          goto LAB_0002dc41;
        }
        bVar22 = pbVar2[4];
        if (((bVar22 & 0x10) != 0) && (!bVar3)) {
          FUN_0002ce68(pbVar2[5],(char *)(pbVar2 + 6),param_3,(char *)pbVar13,(longlong)pbVar2);
          bVar3 = true;
        }
        if (((bVar22 & 0x20) != 0) && (!bVar4)) {
          FUN_0002ce68(pbVar2[5],(char *)(pbVar2 + 6),param_3,(char *)pbVar12,(longlong)pbVar2);
          bVar4 = true;
        }
        if (bVar5) {
          bVar22 = '\x01' << (pbVar2[5] & 3);
          uVar26 = (ulonglong)bVar22;
          local_68[0] = (ushort)bVar22;
          if ((local_60 != (ulonglong *)0x0) ||
             (local_60 = (ulonglong *)FUN_000014c8(((ulonglong)local_77 + 1) * uVar26 * 8),
             local_60 != (ulonglong *)0x0)) {
            uVar24 = (ulonglong)local_6b;
            uVar20 = local_60[uVar24];
            while (uVar20 != 0) {
              uVar24 = (ulonglong)(byte)((char)uVar24 + 1);
              uVar20 = local_60[uVar24];
            }
            if (bVar22 == 1) {
              uVar20 = (ulonglong)pbVar2[6];
LAB_0002de26:
              local_60[uVar24] = uVar20;
            }
            else {
              if (bVar22 == 2) {
                uVar20 = (ulonglong)*(ushort *)(pbVar2 + 6);
                goto LAB_0002de26;
              }
              if (bVar22 == 4) {
                uVar20 = (ulonglong)*(uint *)(pbVar2 + 6);
                goto LAB_0002de26;
              }
              if (bVar22 == 8) {
                local_60[uVar24] = *(ulonglong *)(pbVar2 + 6);
              }
            }
            local_6b = local_6b + 1;
          }
        }
        else {
          uVar26 = (ulonglong)local_68[0];
        }
LAB_0002df32:
        uVar19 = (uint)local_78;
      }
    }
    else if (bVar22 == 0x10) {
      uVar19 = (uint)local_78;
      if (DAT_0018f161 == '\0') {
        DAT_0018f150 = 1;
      }
    }
    else if (bVar22 == 0x11) {
      uVar19 = (uint)local_78;
      if (DAT_0018f161 == '\0') {
        DAT_0018f168 = 1;
      }
    }
    else if (bVar22 == 0x1a) {
      if ((pbVar2[0xd] & 0x30) == 0) {
        DAT_0018f164 = FUN_0002d160((uint)*(ushort *)(pbVar2 + 8),param_1,pbVar2);
        local_78 = pbVar2[0xc];
        psVar14 = (short *)(ulonglong)*(ushort *)(pbVar2 + 10);
      }
      else {
        bVar6 = false;
      }
      uVar19 = (uint)local_78;
      if ((pbVar2[0xd] & 0x30) == 0x10) {
        *(undefined1 *)((longlong)param_7 + 1) = 5;
      }
    }
    else {
      if (bVar22 != 0x1b) {
        if (bVar22 != 0x1c) {
          if (bVar22 == 0x1d) {
            uVar18 = (uint)pbVar2[2] + (uint)pbVar2[2] * 4;
            uVar19 = 0xff;
            if (uVar18 < 0x100) {
              uVar19 = uVar18;
            }
            *(char *)((longlong)param_7 + 1) = (char)uVar19;
          }
          goto LAB_0002df94;
        }
LAB_0002de39:
        local_78 = param_2[0xc];
        DAT_0018f164 = FUN_0002d160((uint)*(ushort *)(param_2 + 8),param_1,param_2);
        psVar14 = (short *)(ulonglong)*(ushort *)(param_2 + 10);
        goto LAB_0002dc41;
      }
      if ((pbVar2[0xd] & 0x30) == 0) {
        DAT_0018f164 = FUN_0002d160((uint)*(ushort *)(pbVar2 + 8),param_1,pbVar2);
        local_78 = pbVar2[0xc];
        psVar14 = (short *)(ulonglong)*(ushort *)(pbVar2 + 10);
      }
      else {
        bVar6 = false;
      }
      uVar19 = (uint)local_78;
      if ((pbVar2[0xd] & 0x30) == 0x10) {
        *(undefined1 *)((longlong)param_7 + 1) = 5;
      }
    }
LAB_0002dc4b:
    lVar27 = local_40 + 1;
    if (pbVar2[1] < 0x80) {
      lVar27 = local_40;
    }
    local_74 = local_74 + (pbVar2[1] & 0x7f);
    local_40 = lVar27;
  } while (lVar27 != 0);
  *param_7 = *param_7 & 0xfffbffc7;
  uVar18 = DAT_0018f164;
  psVar25 = (short *)0x0;
  *param_7 = *param_7 |
             (((uVar19 & 0x40) << 8 | uVar19 & 1) * 2 | uVar19 & 4) << 3 | uVar19 >> 1 & 8;
  if ((uVar18 == 0) ||
     (lVar27 = (ulonglong)*(uint *)(DAT_00193658 + 4 + (ulonglong)uVar18 * 4) + DAT_00193670,
     *(int *)(lVar27 + 0x68) == 0)) goto LAB_0002e500;
  sVar11 = (short)psVar14;
  *(short *)(lVar27 + 0x6c) = sVar11;
  psVar14 = psVar25;
  if (sVar11 != -1) {
    psVar14 = (short *)FUN_000484c8(*(longlong *)(lVar27 + 0x70),sVar11,(short *)0x0);
  }
  local_58 = psVar14;
  if (psVar14 != (short *)0x0) {
    psVar1 = (short *)(lVar27 + 0x10);
    psVar17 = psVar1;
    if (*psVar1 != 0) {
      do {
        psVar17 = psVar17 + 1;
        psVar25 = (short *)((longlong)psVar25 + 1);
      } while (*psVar17 != 0);
      if (psVar25 != (short *)0x0) goto LAB_0002e4f1;
    }
    FUN_000b07bc(psVar1,0x28,psVar14);
  }
LAB_0002e4f1:
  FUN_000013d0((longlong *)&local_58);
LAB_0002e500:
  uVar26 = 8;
  if ((!bVar4) && (!bVar8)) {
    if ((bVar5) && (8 < (ulonglong)local_68[0] * (ulonglong)local_77)) {
      uVar19 = (uint)local_68[0];
      pbVar12 = (byte *)FUN_00001450((longlong)pbVar12,8,(ulonglong)(uVar19 * local_77));
      uVar26 = (ulonglong)(uVar19 * local_77);
    }
    FUN_001073e0((undefined8 *)pbVar12,(undefined8 *)pbVar13,uVar26);
  }
  *param_4 = pbVar12;
  *param_5 = pbVar13;
  if (local_60 != (ulonglong *)0x0) {
    FUN_000013d0((longlong *)&local_60);
    return local_6c;
  }
  return local_6c;
}
