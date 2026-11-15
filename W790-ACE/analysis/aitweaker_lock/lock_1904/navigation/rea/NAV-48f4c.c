
void Candidate_RefreshControl(longlong param_1)

{
  byte bVar1;
  short sVar2;
  ushort uVar3;
  undefined2 uVar4;
  short *psVar5;
  ushort *puVar6;
  ushort *puVar7;
  undefined8 *puVar8;
  longlong lVar9;
  ulonglong uVar10;
  ushort uVar11;
  int iVar12;
  uint *puVar13;
  ulonglong *puVar14;
  ushort uVar15;
  byte *pbVar16;
  ushort uVar17;
  longlong *plVar18;
  ushort *local_res8;
  ushort *local_res10;
  ushort *local_res18;
  ushort *local_res20;
  longlong local_58 [3];
  
  plVar18 = (longlong *)(param_1 + 0x20);
  puVar6 = (ushort *)0x0;
  local_58[0] = 0;
  uVar3 = FUN_0001e86c(plVar18,local_58);
  if (uVar3 == 0xfffe) {
    return;
  }
  if (*(short *)(param_1 + 0x34) != 1) {
    return;
  }
  if (*(int *)(local_58[0] + 100) != 9) {
    *(undefined1 *)(param_1 + 0x73) = 2;
  }
  puVar13 = DAT_00092270;
  iVar12 = *(int *)(local_58[0] + 100);
  if (iVar12 == 1) {
    psVar5 = (short *)FUN_00009168(uVar3,0,'\0');
    uVar4 = FUN_00049aa8(*plVar18,psVar5);
    pbVar16 = *(byte **)(param_1 + 0x48);
    if (*pbVar16 < 5) {
      return;
    }
    if ((((8 < *pbVar16) && (*pbVar16 != 0xf)) && (2 < (byte)(*pbVar16 - 0x1a))) &&
       (*pbVar16 != 0x23)) {
      return;
    }
    *(undefined2 *)(pbVar16 + 2) = uVar4;
    return;
  }
  if (iVar12 == 3) {
    local_res10 = (ushort *)0x0;
    local_res8 = (ushort *)0x0;
    local_res18 = (ushort *)FUN_00010f40(4,(ulonglong *)&local_res10);
    if (local_res18 == (ushort *)0x0) {
      return;
    }
    puVar7 = local_res8;
    if (uVar3 < *local_res18) {
      uVar10 = (ulonglong)uVar3;
      pbVar16 = *(byte **)(param_1 + 0x48);
      if ((4 < *pbVar16) &&
         (((*pbVar16 < 9 || (*pbVar16 == 0xf)) ||
          (((byte)(*pbVar16 - 0x1a) < 3 || (*pbVar16 == 0x23)))))) {
        *(ushort *)(pbVar16 + 2) = local_res18[uVar10 * 6 + 6];
      }
      *(ushort *)(param_1 + 0x40) = local_res18[uVar10 * 6 + 7];
      lVar9 = *(longlong *)(local_res18 + uVar10 * 6 + 2);
      *plVar18 = lVar9;
      puVar7 = puVar6;
      if (*(short *)(param_1 + 0x5c) != -1) {
        puVar6 = (ushort *)FUN_00033df4(lVar9,*(short *)(param_1 + 0x5c),(short *)0x0);
        puVar7 = puVar6;
      }
    }
    local_res8 = puVar7;
    FUN_00005958((longlong *)&local_res18);
    if (puVar6 == (ushort *)0x0) {
      return;
    }
    goto LAB_000495d4;
  }
  if (iVar12 == 0xe) {
    *(undefined1 *)(param_1 + 0x73) = 0;
    local_res18 = (ushort *)0x0;
    local_res20 = (ushort *)0x0;
    puVar7 = puVar6;
    if (*puVar13 == 0) {
      return;
    }
    do {
      plVar18 = (longlong *)((ulonglong)puVar13[(longlong)local_res20 + 1] + DAT_00092b08);
      if ((((*(byte *)((longlong)plVar18 + 0x14) & 0x20) != 0) && (*plVar18 != 0)) &&
         (*plVar18 != 0xffff)) {
        if (puVar7 == (ushort *)(ulonglong)uVar3) {
          local_res8 = (ushort *)((ulonglong)local_res8 & 0xffffffffffff0000);
          FUN_00035dd0(*plVar18,(undefined2 *)&local_res10,(undefined2 *)&local_res8);
          puVar7 = puVar6;
          if (*(short *)((longlong)plVar18 + 0xe) != -1) {
            puVar7 = (ushort *)
                     FUN_00033df4(*plVar18,*(short *)((longlong)plVar18 + 0xe),(short *)0x0);
          }
          local_res10 = puVar7;
          uVar4 = FUN_00049aa8(*(longlong *)(param_1 + 0x20),(short *)puVar7);
          pbVar16 = *(byte **)(param_1 + 0x48);
          if ((4 < *pbVar16) &&
             ((((*pbVar16 < 9 || (*pbVar16 == 0xf)) || ((byte)(*pbVar16 - 0x1a) < 3)) ||
              (*pbVar16 == 0x23)))) {
            *(undefined2 *)(pbVar16 + 2) = uVar4;
          }
          FUN_00005958((longlong *)&local_res10);
          if ((short)local_res8 != 0) {
            puVar7 = puVar6;
            if ((short)local_res8 != -1) {
              puVar7 = (ushort *)FUN_00033df4(*plVar18,(short)local_res8,(short *)0x0);
            }
            local_res10 = puVar7;
            uVar4 = FUN_00049aa8(*(longlong *)(param_1 + 0x20),(short *)puVar7);
            uVar4 = FUN_0001cd6c(*(byte **)(param_1 + 0x48),uVar4);
            *(undefined2 *)(param_1 + 0x40) = uVar4;
            FUN_00005958((longlong *)&local_res10);
          }
          *(short *)(param_1 + 0x38) = (short)plVar18[2];
          local_res8 = local_res20;
          *(undefined2 *)((longlong)plVar18 + 0x12) = *(undefined2 *)(DAT_00082748 + 0x28);
          DAT_0008275c = *(undefined2 *)(DAT_00082748 + 0x28);
          puVar13 = DAT_00092270;
          puVar7 = local_res18;
          lVar9 = DAT_00082748;
          if (local_res20 < (ushort *)(ulonglong)*DAT_00092270) {
            do {
              local_res10 = (ushort *)((ulonglong)puVar13[(longlong)local_res8 + 1] + DAT_00092b08);
              if (*plVar18 == *(longlong *)local_res10) {
                uVar17 = local_res10[8];
                lVar9 = *(longlong *)(lVar9 + 0x30);
                (*(code *)PTR_FUN_0006af68)(*(undefined8 *)(lVar9 + (ulonglong)uVar17 * 8),0);
                (*(code *)PTR_FUN_0006af70)
                          (*(undefined8 *)(lVar9 + (ulonglong)uVar17 * 8),local_res10);
                puVar13 = DAT_00092270;
                lVar9 = DAT_00082748;
              }
              local_res8 = (ushort *)((longlong)local_res8 + 1);
              puVar7 = local_res18;
            } while (local_res8 < (ushort *)(ulonglong)*puVar13);
          }
        }
        puVar7 = (ushort *)((longlong)puVar7 + 1);
        local_res18 = puVar7;
      }
      local_res20 = (ushort *)((longlong)local_res20 + 1);
    } while (local_res20 < (ushort *)(ulonglong)*puVar13);
    return;
  }
  if ((iVar12 == 0x17) || (iVar12 == 0x18)) {
LAB_0004949d:
    *(undefined1 *)(param_1 + 0x73) = 0;
    return;
  }
  if (iVar12 == 8) {
    local_res8 = (ushort *)0x0;
    puVar8 = FUN_000013e4(u_IDESecDev_0007f720,&DAT_000785d0,(undefined4 *)0x0,
                          (longlong *)&local_res8);
    FUN_0005b214((longlong)puVar8,(ulonglong)uVar3);
    (**(code **)(DAT_000824d8 + 0x58))(u_IDESecDev_0007f720,&DAT_000785d0,2,local_res8,puVar8);
    (**(code **)(DAT_000824c8 + 0x48))(puVar8);
    lVar9 = FUN_0005b4a4((ulonglong)uVar3);
    if (lVar9 == 0) {
      return;
    }
    sVar2 = *(short *)(lVar9 + 0x12);
    if (sVar2 == 0) {
      return;
    }
    local_res8 = (ushort *)0x0;
    if (*DAT_00092278 < 7) {
      return;
    }
    puVar7 = (ushort *)FUN_00011dcc(6,(ulonglong *)&local_res8);
    if (puVar7 == (ushort *)0x0) {
      return;
    }
    local_res10 = puVar7;
    FUN_0005b214((longlong)puVar7,(ulonglong)uVar3);
    Candidate_ReadVarstoreField(6,0,(ulonglong)local_res8,puVar7);
    FUN_00005958((longlong *)&local_res10);
    if (sVar2 != -1) {
      puVar6 = (ushort *)FUN_00033df4(DAT_00092b30,sVar2,(short *)0x0);
    }
    local_res8 = puVar6;
    uVar4 = FUN_00049aa8(*(longlong *)(param_1 + 0x20),(short *)puVar6);
    pbVar16 = *(byte **)(param_1 + 0x48);
    if (*pbVar16 < 5) goto LAB_000495d4;
    if ((8 < *pbVar16) && (*pbVar16 != 0xf)) {
      bVar1 = *pbVar16;
LAB_0004940a:
      if ((2 < (byte)(bVar1 - 0x1a)) && (*pbVar16 != 0x23)) goto LAB_000495d4;
    }
  }
  else {
    if (iVar12 == 7) {
      return;
    }
    if (iVar12 == 0x10) {
      *(undefined1 *)(param_1 + 0x73) = 0;
      local_res8 = (ushort *)FUN_0001f1c8(uVar3);
    }
    else {
      if (iVar12 != 0x11) {
        if (iVar12 == 0xf) goto LAB_0004949d;
        if (iVar12 != 0x16) {
          return;
        }
        *(undefined1 *)(param_1 + 0x73) = 0;
        uVar10 = 0;
        local_res8 = (ushort *)0x0;
        uVar17 = 0;
        do {
          uVar11 = uVar17 + 1;
          if (*(short *)(DAT_00082848 + uVar10 * 2) == 0) {
            uVar11 = uVar17;
          }
          if (uVar3 + 1 == (uint)uVar11) {
            iVar12 = (int)uVar10;
            if (iVar12 == 0) {
              uVar4 = 0x96;
            }
            else if (iVar12 == 1) {
              uVar4 = 0x97;
            }
            else if (iVar12 == 2) {
              uVar4 = 0x98;
            }
            else if (iVar12 == 3) {
              uVar4 = 0x99;
            }
            else if (iVar12 == 4) {
              uVar4 = 0x9a;
            }
            else if (iVar12 == 5) {
              uVar4 = 0x9b;
            }
            else {
              if (iVar12 != 6) break;
              uVar4 = 0x9c;
            }
            local_res8 = (ushort *)FUN_00033df4(DAT_00092b30,uVar4,(short *)0x0);
            if (local_res8 != (ushort *)0x0) {
              uVar4 = FUN_00049aa8(*plVar18,(short *)local_res8);
              pbVar16 = *(byte **)(param_1 + 0x48);
              if ((4 < *pbVar16) &&
                 ((((*pbVar16 < 9 || (*pbVar16 == 0xf)) || ((byte)(*pbVar16 - 0x1a) < 3)) ||
                  (*pbVar16 == 0x23)))) {
                *(undefined2 *)(pbVar16 + 2) = uVar4;
              }
            }
            break;
          }
          uVar15 = (short)uVar10 + 1;
          uVar10 = (ulonglong)uVar15;
          uVar17 = uVar11;
        } while (uVar15 < 8);
        FUN_00005958((longlong *)&local_res8);
        local_res8 = (ushort *)FUN_00033df4(DAT_00092b30,0x9d,(short *)0x0);
        if (local_res8 != (ushort *)0x0) {
          uVar4 = FUN_00049aa8(*plVar18,(short *)local_res8);
          uVar4 = FUN_0001cd6c(*(byte **)(param_1 + 0x48),uVar4);
          *(undefined2 *)(param_1 + 0x40) = uVar4;
        }
        goto LAB_000495d4;
      }
      puVar14 = DAT_000827e0;
      if (uVar3 != 0) {
        uVar10 = (ulonglong)uVar3;
        do {
          puVar14 = (ulonglong *)puVar14[3];
          uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
      }
      local_res8 = (ushort *)FUN_0001f86c(puVar14);
    }
    if (local_res8 == (ushort *)0x0) goto LAB_000495d4;
    uVar4 = FUN_00049aa8(*plVar18,(short *)local_res8);
    pbVar16 = *(byte **)(param_1 + 0x48);
    if (*pbVar16 < 5) goto LAB_000495d4;
    if ((8 < *pbVar16) && (*pbVar16 != 0xf)) {
      bVar1 = *pbVar16;
      goto LAB_0004940a;
    }
  }
  *(undefined2 *)(pbVar16 + 2) = uVar4;
LAB_000495d4:
  FUN_00005958((longlong *)&local_res8);
  return;
}

