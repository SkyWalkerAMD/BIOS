
void FUN_00069b5c(longlong param_1)

{
  byte *pbVar1;
  short sVar2;
  char cVar3;
  byte bVar4;
  short sVar5;
  ushort uVar6;
  uint uVar7;
  short *psVar8;
  short *psVar9;
  ulonglong uVar10;
  short *psVar11;
  byte *pbVar12;
  ushort *puVar13;
  short *psVar14;
  longlong lVar15;
  longlong lVar16;
  short *psVar17;
  ulonglong uVar18;
  longlong lVar19;
  longlong *plVar20;
  longlong lVar21;
  ushort local_res10 [4];
  uint local_res18;
  short *local_res20;
  short *local_78;
  byte *local_70;
  short *local_68;
  short *local_60;
  longlong local_58;
  undefined8 local_50;
  undefined8 local_48;
  longlong local_40;
  ushort *local_38;
  undefined8 local_30 [2];
  
  uVar10 = 0;
  local_res18 = 0;
  local_res10[0] = 0;
  local_58 = 0;
  local_40 = 0;
  if (*(int *)(param_1 + 0x1c) != 0) {
    do {
      psVar9 = (short *)0x0;
      plVar20 = (longlong *)((ulonglong)*(uint *)(param_1 + 0x20 + uVar10 * 4) + DAT_001937f8);
      local_50 = 0;
      local_48 = 0;
      cVar3 = FUN_0006d658((longlong)plVar20);
      if (((((cVar3 == '\0') && (bVar4 = FUN_00036f08((longlong)plVar20), 2 < (byte)(bVar4 - 1))) &&
           (bVar4 != 7)) &&
          ((sVar5 = FUN_00028634(plVar20,local_30), sVar5 != -1 &&
           (sVar5 = *(short *)(param_1 + 10), sVar5 != 0x2712)))) &&
         ((sVar5 != 0x28a8 && (sVar5 != 0x2ccb)))) {
        uVar6 = *(ushort *)((longlong)plVar20 + 0x14);
        lVar15 = (ulonglong)*(uint *)(DAT_001937e8 + 4 + (ulonglong)*(ushort *)(plVar20 + 3) * 4) +
                 DAT_001938e0;
        if (uVar6 == 1) {
          sVar2 = *(short *)(lVar15 + 10);
          if ((sVar2 != sVar5) &&
             (sVar2 != *(short *)((ulonglong)
                                  *(uint *)(DAT_001937e8 + 4 +
                                           (ulonglong)*(ushort *)(param_1 + 0x12) * 4) + 10 +
                                 DAT_001938e0))) {
            FUN_00069b5c(lVar15);
          }
        }
        else if ((uVar6 < 0x14) && ((0x80c40U >> (uVar6 & 0x1f) & 1) != 0)) {
          if ((uVar6 == 6) || (uVar6 == 10)) {
            lVar15 = FUN_00026e30(plVar20,&local_res20,&local_58,&local_40,local_res10,
                                  (undefined2 *)0x0,(undefined2 *)0x0);
            if (lVar15 < 0) goto LAB_00069c66;
            uVar10 = FUN_00069930((longlong)plVar20,local_40,local_res10[0]);
            sVar5 = FUN_00026be4((byte *)plVar20[5]);
            if (sVar5 != -1) {
              psVar9 = (short *)FUN_000484c8(*plVar20,sVar5,(short *)0x0);
            }
            local_60 = psVar9;
            if ((*(short *)((longlong)plVar20 + 0x14) == 6) && (*(char *)plVar20[5] != '\x06')) {
              sVar5 = *(short *)(local_58 + (uVar10 & 0xffff) * 2);
              if (sVar5 != -1) {
                lVar15 = *plVar20;
                goto LAB_0006a294;
              }
LAB_0006a2b8:
              psVar8 = (short *)0x0;
            }
            else {
              sVar5 = *(short *)(local_58 + (uVar10 & 0xffff) * 2);
              lVar15 = DAT_00193900;
              if (sVar5 == -1) goto LAB_0006a2b8;
LAB_0006a294:
              psVar8 = (short *)FUN_000484c8(lVar15,sVar5,(short *)0x0);
            }
            local_res20 = psVar8;
            uVar7 = FUN_00069854((longlong)plVar20,local_40,local_res10[0]);
            if ((*(short *)((longlong)plVar20 + 0x14) == 6) && (*(char *)plVar20[5] != '\x06')) {
              sVar5 = *(short *)(local_58 + (ulonglong)(uVar7 & 0xffff) * 2);
              if (sVar5 != -1) {
                lVar15 = *plVar20;
                goto LAB_0006a2fd;
              }
LAB_0006a325:
              psVar11 = (short *)0x0;
            }
            else {
              sVar5 = *(short *)(local_58 + (ulonglong)(uVar7 & 0xffff) * 2);
              lVar15 = DAT_00193900;
              if (sVar5 == -1) goto LAB_0006a325;
LAB_0006a2fd:
              psVar11 = (short *)FUN_000484c8(lVar15,sVar5,(short *)0x0);
            }
            uVar10 = 0;
            sVar5 = *psVar8;
            psVar17 = psVar8;
            psVar14 = psVar11;
            while ((sVar5 != 0 && (sVar5 == *psVar14))) {
              psVar17 = psVar17 + 1;
              psVar14 = psVar14 + 1;
              sVar5 = *psVar17;
            }
            local_78 = psVar11;
            if (*psVar17 != *psVar14) {
              sVar5 = *psVar9;
              psVar17 = psVar9;
              uVar18 = uVar10;
              while (sVar5 != 0) {
                psVar17 = psVar17 + 1;
                uVar18 = uVar18 + 1;
                sVar5 = *psVar17;
              }
              if (uVar18 != 0) {
                psVar17 = psVar9 + (uVar18 - 1);
                do {
                  if (*psVar17 != 0x20) break;
                  psVar17 = psVar17 + -1;
                  uVar18 = uVar18 - 1;
                } while (uVar18 != 0);
              }
              psVar9[uVar18] = 0;
              sVar5 = *psVar9;
              psVar17 = psVar9;
              while (sVar5 != 0) {
                psVar17 = psVar17 + 1;
                uVar10 = uVar10 + 1;
                sVar5 = *psVar17;
              }
              FUN_000697e4((longlong)psVar9,uVar10);
              DAT_00190af0 = FUN_00001450(DAT_00190af0,DAT_00190ae8 * 8,DAT_00190ae8 * 8 + 8);
              pbVar12 = (byte *)FUN_00014034(psVar11);
              local_70 = pbVar12;
              local_68 = FUN_00014034(psVar8);
              lVar16 = 0;
              sVar5 = *psVar9;
              psVar8 = psVar9;
              lVar15 = lVar16;
              while (sVar5 != 0) {
                psVar8 = psVar8 + 1;
                lVar15 = lVar15 + 1;
                sVar5 = *psVar8;
              }
              sVar5 = *(short *)pbVar12;
              lVar21 = lVar16;
              while (sVar5 != 0) {
                pbVar12 = pbVar12 + 2;
                lVar21 = lVar21 + 1;
                sVar5 = *(short *)pbVar12;
              }
              sVar5 = *local_68;
              psVar8 = local_68;
              lVar19 = lVar16;
              while (sVar5 != 0) {
                psVar8 = psVar8 + 1;
                lVar19 = lVar19 + 1;
                sVar5 = *psVar8;
              }
              psVar8 = (short *)&DAT_00171250;
              do {
                psVar8 = psVar8 + 1;
                lVar16 = lVar16 + 1;
              } while (*psVar8 != 0);
              puVar13 = (ushort *)FUN_000014c8((lVar16 + lVar19 + lVar21 + lVar15) * 2 + 2);
              pbVar12 = local_70;
              goto LAB_00069f2a;
            }
LAB_00069e36:
            FUN_000013d0((longlong *)&local_60);
            FUN_000013d0((longlong *)&local_res20);
            FUN_000013d0((longlong *)&local_78);
          }
          else {
            if (uVar6 == 0xb) {
              pbVar12 = (byte *)plVar20[5];
              sVar5 = FUN_00026be4(pbVar12);
              if (sVar5 != -1) {
                psVar9 = (short *)FUN_000484c8(*plVar20,sVar5,(short *)0x0);
              }
              uVar18 = 0;
              sVar5 = *psVar9;
              psVar8 = psVar9;
              uVar10 = uVar18;
              while (sVar5 != 0) {
                psVar8 = psVar8 + 1;
                uVar10 = uVar10 + 1;
                sVar5 = *psVar8;
              }
              if (uVar10 != 0) {
                psVar8 = psVar9 + (uVar10 - 1);
                do {
                  if (*psVar8 != 0x20) break;
                  psVar8 = psVar8 + -1;
                  uVar10 = uVar10 - 1;
                } while (uVar10 != 0);
              }
              psVar9[uVar10] = 0;
              sVar5 = *psVar9;
              psVar8 = psVar9;
              while (sVar5 != 0) {
                psVar8 = psVar8 + 1;
                uVar18 = uVar18 + 1;
                sVar5 = *psVar8;
              }
              local_60 = psVar9;
              FUN_000697e4((longlong)psVar9,uVar18);
              cVar3 = '\0';
              local_48 = 0;
              local_50 = 0;
              uVar6 = FUN_00026d98((char *)pbVar12);
              uVar18 = (ulonglong)uVar6;
              uVar6 = FUN_00026e08(pbVar12);
              uVar10 = (ulonglong)uVar6;
              FUN_0001ae7c(*(uint *)(plVar20 + 1),(uint)uVar6,uVar18 & 0xffffffff,
                           (undefined4 *)&local_50,cVar3);
              cVar3 = '\x10';
              if ((*pbVar12 == 7) && ((pbVar12[0xd] & 0x30) != 0x20)) {
                cVar3 = (-((pbVar12[0xd] & 0x30) != 0) & 0xeaU) + 0x20;
              }
              local_res20 = FUN_000699f0(cVar3,uVar10,local_50);
              uVar6 = FUN_00026d98((char *)pbVar12);
              uVar10 = (ulonglong)uVar6;
              uVar6 = FUN_00026e08(pbVar12);
              lVar15 = DAT_00180208;
              FUN_0001b00c(0,DAT_00180208,*(uint *)(plVar20 + 1),(uint)uVar6,uVar10,
                           (undefined4 *)&local_48);
              cVar3 = '\x10';
              if ((*pbVar12 == 7) && ((pbVar12[0xd] & 0x30) != 0x20)) {
                cVar3 = (-((pbVar12[0xd] & 0x30) != 0) & 0xeaU) + 0x20;
              }
              psVar14 = FUN_000699f0(cVar3,lVar15,local_48);
              psVar8 = local_res20;
              sVar5 = *local_res20;
              psVar11 = psVar14;
              psVar17 = local_res20;
              while ((sVar5 != 0 && (sVar5 == *psVar11))) {
                psVar17 = psVar17 + 1;
                psVar11 = psVar11 + 1;
                sVar5 = *psVar17;
              }
              local_78 = psVar14;
              if (*psVar17 == *psVar11) goto LAB_00069e36;
              DAT_00190af0 = FUN_00001450(DAT_00190af0,DAT_00190ae8 * 8,DAT_00190ae8 * 8 + 8);
              local_70 = (byte *)FUN_00014034(psVar14);
              local_68 = FUN_00014034(psVar8);
              lVar16 = 0;
              sVar5 = *psVar9;
              psVar11 = psVar9;
              lVar15 = lVar16;
              while (sVar5 != 0) {
                psVar11 = psVar11 + 1;
                lVar15 = lVar15 + 1;
                sVar5 = *psVar11;
              }
              sVar5 = *psVar14;
              psVar11 = psVar14;
              lVar21 = lVar16;
              while (sVar5 != 0) {
                psVar11 = psVar11 + 1;
                lVar21 = lVar21 + 1;
                sVar5 = *psVar11;
              }
              sVar5 = *psVar8;
              lVar19 = lVar16;
              while (sVar5 != 0) {
                psVar8 = psVar8 + 1;
                lVar19 = lVar19 + 1;
                sVar5 = *psVar8;
              }
              psVar8 = (short *)&DAT_00171250;
              do {
                psVar8 = psVar8 + 1;
                lVar16 = lVar16 + 1;
              } while (*psVar8 != 0);
              local_38 = (ushort *)FUN_000014c8((lVar16 + lVar19 + lVar21 + lVar15) * 2 + 2);
              FUN_000b25f4((short *)local_38,(byte *)u__s___s__>__s__00171260,psVar9,psVar14);
              puVar13 = local_38;
            }
            else {
              if (uVar6 != 0x13) goto LAB_00069c66;
              pbVar12 = (byte *)plVar20[5];
              local_70 = pbVar12;
              uVar6 = FUN_00026d98((char *)pbVar12);
              local_68 = (short *)((ulonglong)(uVar6 >> 1) * 2 + 2);
              psVar8 = (short *)FUN_000014c8(local_68);
              local_res20 = psVar8;
              FUN_0010749e((undefined4 *)psVar8,(ulonglong)local_68,0);
              sVar5 = FUN_00026be4(pbVar12);
              psVar9 = (short *)0x0;
              if (sVar5 != -1) {
                psVar9 = (short *)FUN_000484c8(*plVar20,sVar5,(short *)0x0);
              }
              uVar18 = 0;
              sVar5 = *psVar9;
              psVar11 = psVar9;
              uVar10 = uVar18;
              while (sVar5 != 0) {
                psVar11 = psVar11 + 1;
                uVar10 = uVar10 + 1;
                sVar5 = *psVar11;
              }
              if (uVar10 != 0) {
                psVar11 = psVar9 + (uVar10 - 1);
                do {
                  if (*psVar11 != 0x20) break;
                  psVar11 = psVar11 + -1;
                  uVar10 = uVar10 - 1;
                } while (uVar10 != 0);
              }
              psVar9[uVar10] = 0;
              sVar5 = *psVar9;
              psVar11 = psVar9;
              while (sVar5 != 0) {
                psVar11 = psVar11 + 1;
                uVar18 = uVar18 + 1;
                sVar5 = *psVar11;
              }
              local_60 = psVar9;
              FUN_000697e4((longlong)psVar9,uVar18);
              uVar6 = FUN_00026d98((char *)local_70);
              uVar10 = (ulonglong)uVar6;
              uVar6 = FUN_00026e08(local_70);
              FUN_0001ae7c(*(uint *)(plVar20 + 1),(uint)uVar6,uVar10 & 0xffffffff,
                           (undefined4 *)psVar8,'\0');
              psVar11 = (short *)FUN_000014c8(local_68);
              local_78 = psVar11;
              uVar6 = FUN_00026d98((char *)local_70);
              uVar10 = (ulonglong)uVar6;
              uVar6 = FUN_00026e08(local_70);
              FUN_0001b00c(0,DAT_00180208,*(uint *)(plVar20 + 1),(uint)uVar6,uVar10,
                           (undefined4 *)psVar11);
              psVar11 = local_78;
              sVar5 = *psVar8;
              psVar17 = local_78;
              while ((sVar5 != 0 && (sVar5 == *psVar17))) {
                psVar8 = psVar8 + 1;
                psVar17 = psVar17 + 1;
                sVar5 = *psVar8;
              }
              if (*psVar8 == *psVar17) goto LAB_00069e36;
              DAT_00190af0 = FUN_00001450(DAT_00190af0,DAT_00190ae8 * 8,DAT_00190ae8 * 8 + 8);
              pbVar12 = (byte *)FUN_00014034(psVar11);
              local_70 = pbVar12;
              local_68 = FUN_00014034(local_res20);
              lVar16 = 0;
              sVar5 = *psVar9;
              psVar8 = psVar9;
              lVar15 = lVar16;
              while (sVar5 != 0) {
                psVar8 = psVar8 + 1;
                lVar15 = lVar15 + 1;
                sVar5 = *psVar8;
              }
              sVar5 = *(short *)pbVar12;
              pbVar1 = pbVar12;
              lVar21 = lVar16;
              while (sVar5 != 0) {
                pbVar1 = pbVar1 + 2;
                lVar21 = lVar21 + 1;
                sVar5 = *(short *)pbVar1;
              }
              sVar5 = *local_68;
              psVar8 = local_68;
              lVar19 = lVar16;
              while (sVar5 != 0) {
                psVar8 = psVar8 + 1;
                lVar19 = lVar19 + 1;
                sVar5 = *psVar8;
              }
              psVar8 = (short *)&DAT_00171250;
              do {
                psVar8 = psVar8 + 1;
                lVar16 = lVar16 + 1;
              } while (*psVar8 != 0);
              puVar13 = (ushort *)FUN_000014c8((lVar16 + lVar19 + lVar21 + lVar15) * 2 + 2);
LAB_00069f2a:
              FUN_000b25f4((short *)puVar13,(byte *)u__s___s__>__s__00171260,psVar9,pbVar12);
            }
            uVar10 = FUN_00069a48(puVar13);
            if ((char)uVar10 == '\0') {
              *(ushort **)(DAT_00190af0 + DAT_00190ae8 * 8) = puVar13;
              DAT_00190ae8 = DAT_00190ae8 + 1;
            }
            FUN_000013d0((longlong *)&local_60);
            FUN_000013d0((longlong *)&local_res20);
            FUN_000013d0((longlong *)&local_78);
            FUN_000013d0((longlong *)&local_70);
            FUN_000013d0((longlong *)&local_68);
          }
        }
      }
LAB_00069c66:
      local_res18 = local_res18 + 1;
      uVar10 = (ulonglong)local_res18;
    } while (local_res18 < *(uint *)(param_1 + 0x1c));
  }
  return;
}

