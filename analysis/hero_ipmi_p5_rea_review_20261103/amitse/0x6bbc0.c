
void FUN_0006bbc0(undefined8 *param_1,longlong *param_2,char param_3)

{
  int iVar1;
  byte *pbVar2;
  ushort uVar3;
  short sVar4;
  undefined2 uVar5;
  longlong lVar6;
  ushort *puVar7;
  ushort *puVar8;
  ushort *puVar9;
  short *psVar10;
  ushort *puVar11;
  uint *puVar12;
  ushort **ppuVar13;
  ulonglong *puVar14;
  short *psVar15;
  ushort *puVar16;
  longlong *plVar17;
  undefined8 *puVar18;
  ushort *local_res20;
  undefined2 local_58 [4];
  ushort *local_50;
  longlong local_48;
  ushort *local_40;
  
  puVar9 = (ushort *)0x0;
  local_48 = 0;
  puVar8 = puVar9;
  if ((param_3 == '\0') || (puVar8 = *(ushort **)((int *)*param_1 + 4), *(int *)*param_1 == 0x1000))
  {
    uVar3 = FUN_00028634(param_2,&local_48);
    puVar11 = (ushort *)(ulonglong)uVar3;
    if ((uVar3 != 0xfffe) && (*(short *)((longlong)param_2 + 0x14) == 1)) {
      iVar1 = *(int *)(local_48 + 100);
      if (iVar1 == 1) {
        lVar6 = FUN_0000c13c(uVar3,1,'\0');
        sVar4 = FUN_00009e3c(*param_2,lVar6);
        pbVar2 = (byte *)param_2[5];
        if ((4 < *pbVar2) &&
           ((((*pbVar2 < 9 || (*pbVar2 == 0xf)) || ((byte)(*pbVar2 - 0x1a) < 3)) ||
            (*pbVar2 == 0x23)))) {
          *(short *)(pbVar2 + 2) = sVar4;
        }
      }
      else {
        if (iVar1 == 3) {
          local_res20 = (ushort *)0x0;
          local_40 = (ushort *)FUN_0001a908(4,(ulonglong *)&local_res20);
          if (local_40 == (ushort *)0x0) {
            return;
          }
          if (*local_40 <= uVar3) {
            return;
          }
          pbVar2 = (byte *)param_2[5];
          if ((4 < *pbVar2) &&
             (((*pbVar2 < 9 || (*pbVar2 == 0xf)) ||
              (((byte)(*pbVar2 - 0x1a) < 3 || (*pbVar2 == 0x23)))))) {
            *(ushort *)(pbVar2 + 2) = local_40[(longlong)puVar11 * 6 + 6];
          }
          ppuVar13 = &local_40;
          *(ushort *)(param_2 + 4) = local_40[(longlong)puVar11 * 6 + 7];
          *param_2 = *(longlong *)(local_40 + (longlong)puVar11 * 6 + 2);
        }
        else {
          if (iVar1 == 0xe) {
            local_40 = (ushort *)0x0;
            puVar12 = DAT_001937e8;
            puVar7 = puVar9;
            puVar16 = puVar9;
            if (*DAT_001937e8 == 0) {
              return;
            }
            do {
              plVar17 = (longlong *)((ulonglong)puVar12[(longlong)puVar16 + 1] + DAT_001938e0);
              if (((*(byte *)((longlong)plVar17 + 0x14) & 0x20) != 0) && (*plVar17 != 0)) {
                if (puVar7 == puVar11) {
                  local_res20 = (ushort *)((ulonglong)local_res20 & 0xffffffffffff0000);
                  FUN_0004acf8(*plVar17,local_58,(undefined2 *)&local_res20);
                  puVar7 = puVar9;
                  if (*(short *)((longlong)plVar17 + 0xe) != -1) {
                    puVar7 = (ushort *)
                             FUN_000484c8(*plVar17,*(short *)((longlong)plVar17 + 0xe),(short *)0x0)
                    ;
                  }
                  local_50 = puVar7;
                  if (puVar7 != (ushort *)0x0) {
                    sVar4 = FUN_00009e3c(*param_2,(longlong)puVar7);
                    pbVar2 = (byte *)param_2[5];
                    if ((4 < *pbVar2) &&
                       ((((*pbVar2 < 9 || (*pbVar2 == 0xf)) || ((byte)(*pbVar2 - 0x1a) < 3)) ||
                        (*pbVar2 == 0x23)))) {
                      *(short *)(pbVar2 + 2) = sVar4;
                    }
                  }
                  sVar4 = (short)local_res20;
                  if ((short)local_res20 != 0) {
                    FUN_000013d0((longlong *)&local_50);
                    puVar7 = puVar9;
                    if (sVar4 != -1) {
                      puVar7 = (ushort *)FUN_000484c8(*plVar17,sVar4,(short *)0x0);
                    }
                    local_50 = puVar7;
                    sVar4 = FUN_00009e3c(*param_2,(longlong)puVar7);
                    uVar5 = FUN_00026c8c((byte *)param_2[5],sVar4);
                    *(undefined2 *)(param_2 + 4) = uVar5;
                  }
                  *(short *)(param_2 + 3) = (short)plVar17[2];
                  if (param_3 == '\0') {
                    *(ushort *)((longlong)plVar17 + 0x12) = DAT_0018f054;
                  }
                  else {
                    *(ushort *)((longlong)plVar17 + 0x12) = puVar8[8];
                    DAT_0018f054 = puVar8[8];
                  }
                  FUN_000013d0((longlong *)&local_50);
                  puVar12 = DAT_001937e8;
                  puVar7 = local_40;
                }
                puVar7 = (ushort *)((longlong)puVar7 + 1);
                local_40 = puVar7;
              }
              puVar16 = (ushort *)((longlong)puVar16 + 1);
            } while (puVar16 < (ushort *)(ulonglong)*puVar12);
            return;
          }
          if (iVar1 != 8) {
            if (iVar1 != 7) {
              if (iVar1 == 0x10) {
                psVar10 = FUN_0002900c(uVar3);
              }
              else {
                if (iVar1 != 0x11) {
                  return;
                }
                puVar14 = DAT_0018f0d0;
                if (uVar3 != 0) {
                  do {
                    puVar14 = (ulonglong *)puVar14[3];
                    puVar11 = (ushort *)((longlong)puVar11 - 1);
                  } while (puVar11 != (ushort *)0x0);
                }
                psVar10 = (short *)FUN_000296b4(puVar14);
              }
              if (psVar10 == (short *)0x0) {
                return;
              }
              sVar4 = FUN_00009e3c(*param_2,(longlong)psVar10);
              pbVar2 = (byte *)param_2[5];
              if (*pbVar2 < 5) {
                return;
              }
              if (((8 < *pbVar2) && (*pbVar2 != 0xf)) &&
                 ((2 < (byte)(*pbVar2 - 0x1a) && (*pbVar2 != 0x23)))) {
                return;
              }
              *(short *)(pbVar2 + 2) = sVar4;
              return;
            }
            if (DAT_00193880 == (ushort *)0x0) {
              return;
            }
            puVar18 = (undefined8 *)(DAT_00193878 + 0x10);
            puVar8 = puVar9;
            do {
              if ((((*(byte *)((longlong)puVar18 + -0xc) & 8) == 0) &&
                  (pbVar2 = (byte *)*puVar18, (*pbVar2 & 0x7f) == 5)) && (pbVar2[1] == 1)) {
                if (puVar11 == puVar8) {
                  sVar4 = *(short *)(pbVar2 + 4);
                  if (sVar4 == 1) {
                    uVar5 = 0x6f;
                    goto LAB_0006c065;
                  }
                  if (sVar4 != 2) {
                    if (sVar4 == 3) {
                      uVar5 = 0x6e;
                      goto LAB_0006c065;
                    }
                    if (sVar4 == 4) {
                      uVar5 = 0x73;
                    }
                    else {
                      if (sVar4 == 5) goto LAB_0006c04f;
                      if (sVar4 == 6) {
                        uVar5 = 0x70;
                      }
                      else if (sVar4 == 0x80) {
                        uVar5 = 0x71;
                      }
                      else {
                        uVar5 = 0x74;
                      }
                    }
                    goto LAB_0006c065;
                  }
                  local_res20 = (ushort *)FUN_000484c8(DAT_00193900,0x6d,(short *)0x0);
                  psVar15 = &DAT_0016feb0;
                  for (psVar10 = (short *)puVar18[-1]; (*psVar10 != 0 && (*psVar10 == *psVar15));
                      psVar10 = psVar10 + 1) {
                    psVar15 = psVar15 + 1;
                  }
                  if (*psVar10 == *psVar15) {
LAB_0006c04f:
                    uVar5 = 0x72;
LAB_0006c065:
                    local_res20 = (ushort *)FUN_000484c8(DAT_00193900,uVar5,(short *)0x0);
                  }
                  sVar4 = FUN_00009e3c(*param_2,(longlong)local_res20);
                  pbVar2 = (byte *)param_2[5];
                  if ((4 < *pbVar2) &&
                     ((((*pbVar2 < 9 || (*pbVar2 == 0xf)) || ((byte)(*pbVar2 - 0x1a) < 3)) ||
                      (*pbVar2 == 0x23)))) {
                    *(short *)(pbVar2 + 2) = sVar4;
                  }
                  FUN_000013d0((longlong *)&local_res20);
                  return;
                }
                puVar8 = (ushort *)((longlong)puVar8 + 1);
              }
              puVar9 = (ushort *)((longlong)puVar9 + 1);
              puVar18 = puVar18 + 9;
              if (DAT_00193880 <= puVar9) {
                return;
              }
            } while( true );
          }
          sVar4 = FUN_00049eb4(uVar3);
          if (sVar4 == 0) {
            return;
          }
          local_res20 = (ushort *)0x0;
          if (*DAT_001937f0 < 7) {
            return;
          }
          puVar8 = (ushort *)FUN_0001b814(6,(ulonglong *)&local_res20);
          if (puVar8 == (ushort *)0x0) {
            return;
          }
          local_40 = puVar8;
          FUN_00046004((longlong)puVar8,(ulonglong)puVar11);
          FUN_0001aee8(6,0,(ulonglong)local_res20,puVar8);
          FUN_000013d0((longlong *)&local_40);
          if (sVar4 != -1) {
            puVar9 = (ushort *)FUN_000484c8(DAT_00193900,sVar4,(short *)0x0);
          }
          local_res20 = puVar9;
          sVar4 = FUN_00009e3c(*param_2,(longlong)puVar9);
          pbVar2 = (byte *)param_2[5];
          if ((4 < *pbVar2) &&
             (((*pbVar2 < 9 || (*pbVar2 == 0xf)) ||
              (((byte)(*pbVar2 - 0x1a) < 3 || (*pbVar2 == 0x23)))))) {
            *(short *)(pbVar2 + 2) = sVar4;
          }
          ppuVar13 = &local_res20;
        }
        FUN_000013d0((longlong *)ppuVar13);
      }
    }
  }
  return;
}

