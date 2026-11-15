
longlong Observed_FormBrowser2_BrowserCallback
                   (undefined8 param_1,ulonglong *param_2,short *param_3,char param_4,
                   longlong *param_5,short *param_6)

{
  short sVar1;
  ushort uVar2;
  bool bVar3;
  short *psVar4;
  short *psVar5;
  longlong lVar6;
  uint uVar7;
  longlong lVar8;
  ulonglong uVar9;
  longlong lVar10;
  ulonglong uVar11;
  ushort *puVar12;
  ushort *puVar13;
  longlong *plVar14;
  uint uVar15;
  ushort *puVar16;
  longlong *plVar17;
  ushort *puVar18;
  ushort *puVar19;
  short *local_78;
  ushort *local_70;
  uint local_68 [2];
  ulonglong local_60;
  short *local_58;
  ushort *local_50;
  undefined8 *local_48;
  undefined8 local_40;
  ulonglong local_38 [2];
  
  puVar16 = (ushort *)0x0;
  local_40 = 0;
  puVar19 = (ushort *)0x0;
  local_78 = (short *)0x0;
  puVar12 = (ushort *)0x0;
  local_50 = (ushort *)0x0;
  local_70 = (ushort *)0x0;
  local_58 = (short *)0x0;
  local_60 = 0;
  local_38[0] = 0;
  local_48 = (undefined8 *)0x0;
  local_68[0] = 0;
  if ((DAT_00082700 == '\0') && (DAT_00082970 == '\0')) {
    return -0x7ffffffffffffffd;
  }
  if ((DAT_00082830 == 3) && (DAT_00082648 == 2)) {
    FUN_00021528();
  }
  puVar13 = (ushort *)0x0;
  if ((param_2 == (ulonglong *)0x0) || ((*param_2 != 0 && (param_3 == (short *)0x0)))) {
    lVar10 = -0x7ffffffffffffffe;
    goto LAB_00021af8;
  }
  puVar19 = puVar12;
  if (param_5 == (longlong *)0x0) {
    uVar7 = *DAT_00092278;
    if (DAT_00082828 < uVar7) {
      puVar13 = (ushort *)
                ((ulonglong)DAT_00092278[(ulonglong)DAT_00082828 + 1] + (longlong)DAT_00092278);
    }
    if ((puVar13 != (ushort *)0x0) &&
       (uVar15 = DAT_00082828, *(longlong *)(puVar13 + 0x38) == DAT_00082810)) {
LAB_0002183e:
      puVar19 = puVar12;
      if (puVar13 != (ushort *)0x0) {
        if (uVar15 < uVar7) {
          puVar12 = (ushort *)FUN_00011dcc((ulonglong)uVar15,&local_60);
          puVar19 = puVar12;
          local_70 = puVar12;
          if (puVar12 != (ushort *)0x0) {
            lVar10 = FUN_0001ddcc((undefined8 *)puVar13,(longlong *)&local_50,local_38);
            puVar19 = local_50;
            if ((-1 < lVar10) && (local_50 != (ushort *)0x0)) {
              lVar10 = 0;
              if (param_4 == '\0') {
                sVar1 = *param_3;
                psVar5 = param_3;
                lVar8 = lVar10;
                while (sVar1 != 0) {
                  psVar5 = psVar5 + 1;
                  lVar8 = lVar8 + 1;
                  sVar1 = *psVar5;
                }
                uVar2 = *local_50;
                puVar16 = local_50;
                while (uVar2 != 0) {
                  puVar16 = puVar16 + 1;
                  lVar10 = lVar10 + 1;
                  uVar2 = *puVar16;
                }
                uVar11 = (lVar10 + lVar8) * 2 + 4;
                local_78 = (short *)FUN_0003eea8(lVar10,uVar11);
                uVar11 = uVar11 >> 1;
                uVar9 = uVar11;
                FUN_0003e700(local_78,uVar11,(short *)puVar19);
                FUN_0003e7a0(local_78,uVar9,(short *)&DAT_0007bfec);
                FUN_0003e7a0(local_78,uVar11,param_3);
                local_58 = local_78;
                do {
                  if ((*(uint *)(puVar13 + 0x34) & 0x2000) != 0) {
                    lVar10 = -0x7ffffffffffffffd;
                    break;
                  }
                  lVar10 = FUN_00021cd4((longlong *)&local_70,&local_60,local_68,
                                        (undefined8 **)&local_58);
                  puVar12 = local_70;
                  if (lVar10 < 0) break;
                  if (uVar15 == 8) {
                    lVar10 = FUN_00022c60(local_60,local_70);
                  }
                  else {
                    lVar10 = FUN_00011518(uVar15,local_68[0],local_60,local_70);
                  }
                } while (local_58 != (short *)0x0);
              }
              else {
                if (((*param_2 != 0) && (param_3 != (short *)0x0)) &&
                   (psVar5 = param_3, psVar4 = FUN_00006b10(param_3,u_OFFSET__0007c2e8),
                   psVar4 != (short *)0x0)) {
                  sVar1 = *param_3;
                  psVar4 = param_3;
                  lVar8 = lVar10;
                  while (sVar1 != 0) {
                    psVar4 = psVar4 + 1;
                    lVar8 = lVar8 + 1;
                    sVar1 = *psVar4;
                  }
                  local_48 = FUN_0003eea8(psVar5,lVar8 * 2 + 4);
                  sVar1 = *param_3;
                  psVar5 = param_3;
                  while (sVar1 != 0) {
                    psVar5 = psVar5 + 1;
                    lVar10 = lVar10 + 1;
                    sVar1 = *psVar5;
                  }
                  (**(code **)(DAT_000824c8 + 0x160))(local_48,param_3,lVar10 * 2);
                }
                do {
                  lVar10 = FUN_00021b4c((longlong)puVar13,puVar12,(short *)puVar19,&local_78,
                                        &local_48);
                  lVar8 = 0;
                  if (lVar10 < 0) goto LAB_00021af8;
                  if (local_58 == (short *)0x0) {
                    uVar2 = *puVar19;
                    lVar6 = lVar8;
                    puVar16 = puVar19;
                    while (uVar2 != 0) {
                      puVar16 = puVar16 + 1;
                      lVar6 = lVar6 + 1;
                      uVar2 = *puVar16;
                    }
                    lVar6 = lVar6 + 1;
                  }
                  else {
                    uVar2 = *puVar19;
                    lVar6 = lVar8;
                    puVar16 = puVar19;
                    while (uVar2 != 0) {
                      puVar16 = puVar16 + 1;
                      lVar6 = lVar6 + 1;
                      uVar2 = *puVar16;
                    }
                  }
                  psVar5 = local_78 + lVar6;
                  sVar1 = *psVar5;
                  while (sVar1 != 0) {
                    psVar5 = psVar5 + 1;
                    lVar8 = lVar8 + 1;
                    sVar1 = *psVar5;
                  }
                  psVar5 = local_58 + lVar8 + 1;
                  if ((short *)*param_2 < psVar5) {
                    *param_2 = (ulonglong)psVar5;
                    lVar10 = -0x7ffffffffffffffb;
                    goto LAB_00021af8;
                  }
                  psVar4 = param_3;
                  if (local_58 != (short *)0x0) {
                    psVar4 = (short *)((longlong)(local_58 + -1) + (longlong)param_3);
                  }
                  (**(code **)(DAT_000824c8 + 0x160))(psVar4);
                  local_58 = psVar5;
                } while (local_48 != (undefined8 *)0x0);
                *param_2 = (ulonglong)psVar5;
              }
            }
            goto LAB_00021af8;
          }
        }
        else {
          local_60 = 0;
          local_70 = (ushort *)0x0;
          puVar19 = (ushort *)0x0;
        }
      }
    }
  }
  else {
    bVar3 = false;
    uVar7 = *DAT_00092278;
    puVar19 = puVar16;
    puVar18 = puVar16;
    if (uVar7 != 0) {
      do {
        if (((((uint)puVar13 < uVar7) &&
             (plVar14 = (longlong *)
                        ((ulonglong)DAT_00092278[(longlong)puVar13 + 1] + (longlong)DAT_00092278),
             plVar14 != (longlong *)0x0)) && (*plVar14 == *param_5)) &&
           ((plVar14[1] == param_5[1] && ((*(uint *)(plVar14 + 0xd) & 0x2000) == 0)))) {
          puVar19 = puVar12;
          if (param_6 == (short *)0x0) goto LAB_000217e5;
          plVar17 = plVar14 + 2;
          psVar5 = param_6;
          while( true ) {
            if (((short)*plVar17 == (short)local_40) || ((short)*plVar17 != *psVar5)) break;
            plVar17 = (longlong *)((longlong)plVar17 + 2);
            psVar5 = psVar5 + 1;
          }
          if (((short)*plVar17 == *psVar5) &&
             (bVar3 = true, puVar18 = puVar13, plVar14[0xe] == DAT_00082810)) goto LAB_000217f7;
        }
        uVar15 = (uint)puVar13 + 1;
        puVar13 = (ushort *)(ulonglong)uVar15;
      } while (uVar15 < uVar7);
      puVar19 = puVar12;
      if (bVar3) {
LAB_000217f7:
        puVar13 = (ushort *)0x0;
        uVar15 = (uint)puVar18;
        if (uVar15 < uVar7) {
          puVar13 = (ushort *)
                    ((ulonglong)DAT_00092278[(longlong)puVar18 + 1] + (longlong)DAT_00092278);
        }
        goto LAB_0002183e;
      }
    }
  }
LAB_000217e5:
  puVar12 = puVar19;
  lVar10 = -0x7ffffffffffffff2;
  puVar19 = puVar16;
LAB_00021af8:
  if (local_78 != (short *)0x0) {
    FUN_00005958((longlong *)&local_78);
  }
  if (puVar12 != (ushort *)0x0) {
    FUN_00005958((longlong *)&local_70);
  }
  if (puVar19 != (ushort *)0x0) {
    FUN_00005958((longlong *)&local_50);
  }
  return lVar10;
}

