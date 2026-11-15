// 0x460

void entry(undefined8 param_1,longlong param_2)

{
  FUN_0000048c(param_1,param_2);
  FUN_00001fcc(param_1,param_2);
  return;
}


// 0x8288

longlong FUN_00008288(char *param_1,uint param_2,undefined8 *param_3,undefined8 *param_4)

{
  longlong *plVar1;
  char *pcVar2;
  byte bVar3;
  longlong lVar4;
  char *pcVar5;
  longlong *plVar6;
  undefined4 *puVar7;
  ulonglong uVar8;
  ulonglong uVar9;
  char *pcVar10;
  undefined8 uVar11;
  char *pcVar12;
  longlong lVar13;
  longlong lVar14;
  ushort *puVar15;
  ulonglong uVar16;
  byte *pbVar17;
  ulonglong uVar18;
  undefined *puVar19;
  longlong local_58;
  undefined4 *local_50 [3];
  undefined8 local_38;
  undefined8 local_30;
  
  uVar9 = 0;
  uVar16 = (ulonglong)param_2;
  local_58 = 0;
  DAT_000169a8 = 0;
  uVar11 = 0x28;
  FUN_00000300(local_50,0x28);
  lVar4 = (**(code **)(DAT_00016980 + 0x140))(&DAT_00013b20,0,&local_58);
  if (lVar4 < 0) {
    return lVar4;
  }
  pcVar5 = (char *)FUN_000041f4((ulonglong)(param_2 + 1));
  if (pcVar5 == (char *)0x0) {
    return -0x7ffffffffffffff7;
  }
  if ((param_2 != 0) && (pcVar5 != param_1)) {
    FUN_000002c0((undefined8 *)pcVar5,(undefined8 *)param_1,uVar16);
  }
  plVar6 = (longlong *)FUN_000041f4(0x28);
  if (plVar6 == (longlong *)0x0) {
    return -0x7ffffffffffffff7;
  }
  *plVar6 = 0;
  plVar1 = plVar6 + 2;
  *plVar1 = 0;
  plVar6[4] = 0;
  if (param_2 == 0) {
    lVar4 = -0x7ffffffffffffffe;
    goto LAB_000086fd;
  }
  if (local_58 == 0) {
    lVar4 = -0x7ffffffffffffffa;
    goto LAB_000086fd;
  }
  puVar7 = (undefined4 *)FUN_000041c4(uVar11,0x10);
  *plVar6 = (longlong)puVar7;
  uVar8 = uVar9;
  if (puVar7 == (undefined4 *)0x0) goto LAB_0000837e;
  do {
    uVar18 = uVar8 + 1;
    pcVar10 = &DAT_00015909 + uVar8;
    uVar8 = uVar18;
  } while (*pcVar10 != '\0');
  lVar4 = FUN_00003f4c(pcVar5,&DAT_00015908,uVar18);
  uVar8 = uVar9;
  if (lVar4 == 0) {
    *puVar7 = 0;
    do {
      uVar8 = uVar9 + 1;
      pcVar10 = &DAT_00015909 + uVar9;
      uVar9 = uVar8;
    } while (*pcVar10 != '\0');
LAB_000084c8:
    pbVar17 = (byte *)(pcVar5 + uVar8);
    pcVar10 = thunk_FUN_00003fe4((char *)pbVar17,s_HTTP_1_1_00015930);
    if (pcVar10 != (char *)0x0) {
      pcVar10[-1] = '\0';
      lVar4 = 0;
      bVar3 = *pbVar17;
      while (bVar3 != 0) {
        lVar4 = lVar4 + 1;
        bVar3 = pbVar17[lVar4];
      }
      uVar11 = FUN_000041f4(lVar4 * 2 + 2);
      *(undefined8 *)(*plVar6 + 8) = uVar11;
      puVar15 = *(ushort **)(*plVar6 + 8);
      if (puVar15 != (ushort *)0x0) {
        for (; *pbVar17 != 0; pbVar17 = pbVar17 + 1) {
          *puVar15 = (ushort)*pbVar17;
          puVar15 = puVar15 + 1;
        }
        *puVar15 = 0;
        puVar19 = &DAT_00014fbc;
        pcVar12 = thunk_FUN_00003fe4(pcVar10,&DAT_00014fbc);
        lVar4 = 0;
        if (pcVar12 == (char *)0x0) goto LAB_000086e7;
        do {
          lVar4 = lVar4 + 1;
        } while (puVar19[lVar4] != '\0');
        pcVar12 = pcVar12 + lVar4;
        local_50[0] = (undefined4 *)0x0;
        local_50[0] = (undefined4 *)FUN_000041c4(pcVar10,4);
        if (local_50[0] != (undefined4 *)0x0) {
          if (pcVar5 + (uVar16 - (longlong)pcVar12) == (char *)0x0) {
            plVar6[4] = 0;
            plVar6[3] = 0;
            *plVar1 = 0;
            plVar6[1] = 0;
            lVar4 = (*(code *)*DAT_000168d8)(DAT_000168d8,plVar6,local_50);
            if (-1 < lVar4) {
              DAT_000169a8 = *local_50[0];
              *param_3 = local_30;
              *param_4 = local_38;
              lVar4 = 0;
            }
            goto LAB_000086fd;
          }
          puVar19 = &DAT_0001593c;
          pcVar10 = thunk_FUN_00003fe4(pcVar12,&DAT_0001593c);
          if (pcVar10 == (char *)0x0) goto LAB_000086e7;
          lVar4 = 0;
          do {
            lVar4 = lVar4 + 1;
          } while (puVar19[lVar4] != '\0');
          lVar4 = (**(code **)(local_58 + 8))
                            (local_58,pcVar12,pcVar10 + (lVar4 - (longlong)pcVar12),plVar1,
                             plVar6 + 1);
          lVar14 = 0;
          if (lVar4 < 0) goto LAB_000086fd;
          do {
            lVar13 = lVar14 + 1;
            pcVar12 = &DAT_0001593d + lVar14;
            lVar14 = lVar13;
          } while (*pcVar12 != '\0');
          pcVar12 = pcVar5 + ((uVar16 - lVar13) - (longlong)pcVar10);
          plVar6[3] = (longlong)pcVar12;
          if (pcVar12 == (char *)0x0) {
            plVar6[4] = 0;
            goto LAB_000086fd;
          }
          pcVar12 = (char *)FUN_000041c4(0,pcVar12);
          lVar4 = 0;
          plVar6[4] = (longlong)pcVar12;
          if (pcVar12 != (char *)0x0) {
            do {
              lVar14 = lVar4 + 1;
              pcVar2 = &DAT_0001593d + lVar4;
              lVar4 = lVar14;
            } while (*pcVar2 != '\0');
            if ((plVar6[3] != 0) && (pcVar12 != pcVar10 + lVar14)) {
              FUN_000002c0((undefined8 *)pcVar12,(undefined8 *)(pcVar10 + lVar14),plVar6[3]);
            }
            lVar4 = (*(code *)*DAT_000168d8)(DAT_000168d8,plVar6,local_50);
            if (-1 < lVar4) {
              DAT_000169a8 = *local_50[0];
              *param_3 = local_30;
              *param_4 = local_38;
            }
            goto LAB_000086fd;
          }
        }
      }
LAB_0000837e:
      lVar4 = -0x7ffffffffffffff7;
      goto LAB_000086fd;
    }
  }
  else {
    do {
      uVar18 = uVar8 + 1;
      lVar4 = uVar8 + 1;
      uVar8 = uVar18;
    } while (s_POST_00015910[lVar4] != '\0');
    lVar4 = FUN_00003f4c(pcVar5,s_POST_00015910,uVar18);
    uVar8 = uVar9;
    if (lVar4 == 0) {
      *puVar7 = 1;
      do {
        uVar8 = uVar9 + 1;
        lVar4 = uVar9 + 1;
        uVar9 = uVar8;
      } while (s_POST_00015910[lVar4] != '\0');
      goto LAB_000084c8;
    }
    do {
      uVar18 = uVar8 + 1;
      pcVar10 = &DAT_00015919 + uVar8;
      uVar8 = uVar18;
    } while (*pcVar10 != '\0');
    lVar4 = FUN_00003f4c(pcVar5,&DAT_00015918,uVar18);
    uVar8 = uVar9;
    if (lVar4 == 0) {
      *puVar7 = 6;
      do {
        uVar8 = uVar9 + 1;
        pcVar10 = &DAT_00015919 + uVar9;
        uVar9 = uVar8;
      } while (*pcVar10 != '\0');
      goto LAB_000084c8;
    }
    do {
      uVar18 = uVar8 + 1;
      lVar4 = uVar8 + 1;
      uVar8 = uVar18;
    } while (s_PATCH_00015920[lVar4] != '\0');
    lVar4 = FUN_00003f4c(pcVar5,s_PATCH_00015920,uVar18);
    uVar8 = uVar9;
    if (lVar4 == 0) {
      *puVar7 = 2;
      do {
        uVar8 = uVar9 + 1;
        lVar4 = uVar9 + 1;
        uVar9 = uVar8;
      } while (s_PATCH_00015920[lVar4] != '\0');
      goto LAB_000084c8;
    }
    do {
      uVar18 = uVar8 + 1;
      lVar4 = uVar8 + 1;
      uVar8 = uVar18;
    } while (s_DELETE_00015928[lVar4] != '\0');
    lVar4 = FUN_00003f4c(pcVar5,s_DELETE_00015928,uVar18);
    if (lVar4 == 0) {
      *puVar7 = 7;
      do {
        uVar8 = uVar9 + 1;
        lVar4 = uVar9 + 1;
        uVar9 = uVar8;
      } while (s_DELETE_00015928[lVar4] != '\0');
      goto LAB_000084c8;
    }
  }
LAB_000086e7:
  lVar4 = -0x7ffffffffffffff2;
LAB_000086fd:
  if (*(longlong *)(*plVar6 + 8) != 0) {
    (**(code **)(DAT_00016838 + 0x48))();
  }
  if (*plVar6 != 0) {
    (**(code **)(DAT_00016838 + 0x48))();
  }
  if (*plVar1 != 0) {
    (**(code **)(DAT_00016838 + 0x48))();
  }
  if (plVar6[4] != 0) {
    (**(code **)(DAT_00016838 + 0x48))();
  }
  (**(code **)(DAT_00016838 + 0x48))(plVar6);
  (**(code **)(DAT_00016838 + 0x48))(pcVar5);
  return lVar4;
}

