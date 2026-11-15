
void FUN_00019744(longlong param_1,uint param_2)

{
  uint *puVar1;
  short sVar2;
  ushort uVar3;
  ushort uVar4;
  short *psVar5;
  short *psVar6;
  byte *pbVar7;
  short *psVar8;
  short *psVar9;
  longlong *plVar10;
  uint uVar11;
  ulonglong uVar12;
  ulonglong uVar13;
  byte *pbVar14;
  uint *puVar15;
  uint uVar16;
  short *local_res8;
  
  uVar12 = 0;
  if (*(int *)(param_1 + 0x1c) != 0) {
    do {
      psVar9 = (short *)0x0;
      plVar10 = (longlong *)((ulonglong)*(uint *)(param_1 + 0x20 + uVar12 * 4) + DAT_001937f8);
      uVar16 = *(uint *)(plVar10 + 1);
      if ((((uVar16 != 1) && (1 < uVar16 - 7)) && (*(short *)((longlong)plVar10 + 0x3a) != 0)) &&
         (pbVar7 = (byte *)plVar10[5], pbVar7 != (byte *)0x0)) {
        uVar4 = *(ushort *)((longlong)plVar10 + 0x3a);
        puVar15 = (uint *)(plVar10 + 8);
        puVar1 = (uint *)((ulonglong)uVar4 + (longlong)puVar15);
        pbVar14 = pbVar7;
        uVar3 = FUN_00026e08(pbVar7);
        uVar11 = (uint)uVar3;
        if (*(short *)((longlong)plVar10 + 0x14) == 0x13) {
          sVar2 = (short)*puVar15;
          if (sVar2 != 0) {
            psVar5 = psVar9;
            if (sVar2 != -1) {
              psVar5 = (short *)FUN_000484c8(*plVar10,sVar2,(short *)0x0);
            }
            local_res8 = psVar5;
            if (psVar5 == (short *)0x0) goto LAB_00019a8f;
            psVar6 = psVar5;
            psVar8 = psVar9;
            if (*psVar5 == 0) {
LAB_00019843:
              uVar13 = 2;
              FUN_000013d0((longlong *)&local_res8);
              psVar5 = (short *)FUN_000014c8(2);
            }
            else {
              do {
                psVar6 = psVar6 + 1;
                psVar8 = (short *)((longlong)psVar8 + 1);
              } while (*psVar6 != 0);
              psVar6 = psVar5;
              if (psVar8 == (short *)0x0) goto LAB_00019843;
              do {
                psVar6 = psVar6 + 1;
                psVar9 = (short *)((longlong)psVar9 + 1);
              } while (*psVar6 != 0);
              uVar13 = (longlong)psVar9 * 2;
            }
            local_res8 = psVar5;
            FUN_0001b00c(1,DAT_00180210,*(uint *)(plVar10 + 1),uVar11,uVar13,(undefined4 *)psVar5);
            if (psVar5 != (short *)0x0) {
              FUN_000013d0((longlong *)&local_res8);
            }
          }
          psVar9 = (short *)0x0;
          sVar2 = (short)*puVar1;
          if (sVar2 != 0) {
            psVar5 = psVar9;
            if (sVar2 != -1) {
              psVar5 = (short *)FUN_000484c8(*plVar10,sVar2,(short *)0x0);
            }
            local_res8 = psVar5;
            if (psVar5 != (short *)0x0) {
              psVar6 = psVar5;
              psVar8 = psVar9;
              if (*psVar5 == 0) {
LAB_00019900:
                uVar13 = 2;
                FUN_000013d0((longlong *)&local_res8);
                psVar5 = (short *)FUN_000014c8(2);
              }
              else {
                do {
                  psVar6 = psVar6 + 1;
                  psVar8 = (short *)((longlong)psVar8 + 1);
                } while (*psVar6 != 0);
                psVar6 = psVar5;
                if (psVar8 == (short *)0x0) goto LAB_00019900;
                do {
                  psVar6 = psVar6 + 1;
                  psVar9 = (short *)((longlong)psVar9 + 1);
                } while (*psVar6 != 0);
                uVar13 = (longlong)psVar9 * 2;
              }
              local_res8 = psVar5;
              FUN_0001b00c(1,DAT_001801f0,*(uint *)(plVar10 + 1),uVar11,uVar13,(undefined4 *)psVar5)
              ;
              if (param_2 < *(uint *)(plVar10 + 1)) {
                FUN_0001b00c(1,DAT_001801c0,*(uint *)(plVar10 + 1),uVar11,uVar13,
                             (undefined4 *)psVar5);
              }
              if (psVar5 != (short *)0x0) {
                FUN_000013d0((longlong *)&local_res8);
              }
            }
          }
        }
        else if ((*(uint *)((longlong)plVar10 + 0x1c) & 0x80000) == 0) {
          FUN_0001b00c(1,DAT_00180210,uVar16,uVar11,(ulonglong)uVar4,puVar15);
          FUN_0001b00c(1,DAT_001801f0,*(uint *)(plVar10 + 1),uVar11,
                       (ulonglong)*(ushort *)((longlong)plVar10 + 0x3a),puVar1);
          if (param_2 < *(uint *)(plVar10 + 1)) {
            FUN_0001b00c(1,DAT_001801c0,*(uint *)(plVar10 + 1),uVar11,
                         (ulonglong)*(ushort *)((longlong)plVar10 + 0x3a),puVar1);
          }
        }
        else {
          uVar4 = FUN_00026d98((char *)pbVar7);
          uVar13 = (ulonglong)uVar4;
          FUN_0001b2a4(1,DAT_00180210,uVar16,(ulonglong)uVar11,uVar13,puVar15,(char *)pbVar14);
          FUN_0001b2a4(1,DAT_001801f0,*(uint *)(plVar10 + 1),(ulonglong)uVar11,uVar13,puVar1,
                       (char *)plVar10[5]);
          if (param_2 < *(uint *)(plVar10 + 1)) {
            FUN_0001b2a4(1,DAT_001801c0,*(uint *)(plVar10 + 1),(ulonglong)uVar11,uVar13,puVar1,
                         (char *)plVar10[5]);
          }
        }
      }
LAB_00019a8f:
      uVar16 = (int)uVar12 + 1;
      uVar12 = (ulonglong)uVar16;
    } while (uVar16 < *(uint *)(param_1 + 0x1c));
  }
  return;
}

