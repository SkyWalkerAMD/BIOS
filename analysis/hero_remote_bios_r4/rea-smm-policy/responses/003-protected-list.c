/* 0x8bc0 */

ulonglong FUN_00008bc0(short *param_1,longlong *param_2,ulonglong param_3,longlong param_4,
                      int *param_5)

{
  longlong lVar1;
  undefined8 uVar2;
  wchar_t *pwVar3;
  wchar_t *pwVar4;
  int local_res18 [4];
  ulonglong local_28 [2];
  
  if ((param_3 & 0x20) != 0) {
    return 0;
  }
  pwVar4 = u_MonotonicCounter_00012828;
  for (pwVar3 = param_1; (*pwVar3 != L'\0' && (*pwVar3 == *pwVar4)); pwVar3 = pwVar3 + 1) {
    pwVar4 = pwVar4 + 1;
  }
  if ((*pwVar3 == *pwVar4) &&
     (lVar1 = FUN_0000a918((longlong *)&DAT_000112f0,param_2,0x10), lVar1 == 0)) {
    local_28[0] = 4;
    if (param_4 == 4) {
      lVar1 = FUN_00005a58((ushort *)u_MonotonicCounter_00012828,(longlong *)&DAT_000112f0,
                           (uint *)0x0,local_28,(undefined8 *)local_res18);
      if (-1 < lVar1) {
        return -(ulonglong)(*param_5 != local_res18[0] + 1) & 0x8000000000000008;
      }
      return 0x8000000000000007;
    }
  }
  else {
    uVar2 = FUN_00003c3c((longlong *)&PTR_LAB_00011410,param_1,param_2);
    if ((char)uVar2 == '\0') {
      return 0;
    }
    lVar1 = FUN_0000a918(param_2,(longlong *)&DAT_000113c0,0x10);
    if (lVar1 == 0) {
      return 0;
    }
    lVar1 = FUN_0000a918(param_2,(longlong *)&DAT_00011438,0x10);
    if (lVar1 == 0) {
      return 0;
    }
  }
  return 0x8000000000000008;
}


/* 0x52d4 */

char * FUN_000052d4(ushort *param_1,longlong *param_2,uint param_3,undefined *param_4,
                   longlong *param_5)

{
  undefined1 *puVar1;
  ulonglong uVar2;
  undefined8 *puVar3;
  longlong *plVar4;
  int *piVar5;
  char cVar6;
  char cVar7;
  char *pcVar8;
  undefined8 uVar9;
  longlong *plVar10;
  ushort *puVar11;
  ulonglong uVar12;
  longlong lVar13;
  uint uVar14;
  longlong *plVar15;
  longlong *plVar16;
  longlong lVar17;
  uint local_res18 [2];
  undefined *local_res20;
  longlong *plVar18;
  longlong *local_110;
  longlong *local_108;
  undefined8 local_100;
  longlong *local_f8;
  longlong *local_f0;
  longlong local_e8;
  code *local_e0;
  int *local_d8;
  undefined **local_d0;
  int *local_c8 [2];
  byte local_b8 [8];
  undefined8 local_b0;
  undefined1 local_a8;
  undefined8 local_a7;
  undefined8 local_9f;
  undefined8 local_97;
  undefined4 local_8f;
  undefined2 local_8b;
  undefined1 local_89;
  longlong local_88 [10];
  
  uVar14 = 0;
  local_110 = (longlong *)0x0;
  local_100 = (longlong *)0x0;
  local_108 = (longlong *)0x0;
  local_b8[0] = 0;
  local_b0 = 0;
  local_a8 = 0;
  local_a7 = 0;
  local_9f = 0;
  local_97 = 0;
  local_8f = 0;
  local_8b = 0;
  local_89 = 0;
  if ((undefined *)0xffff < param_4) {
    return (char *)0x8000000000000009;
  }
  local_res18[0] = param_3;
  local_res20 = param_4;
  pcVar8 = FUN_00004de0(param_1,param_2,param_3,param_4,(char *)param_5);
  if ((longlong)pcVar8 < 0) {
    return pcVar8;
  }
  do {
    uVar9 = FUN_00002b68(param_1,param_2,&local_e8,(longlong *)&local_d8,(longlong *)0x0,
                         (longlong *)&local_f0,(longlong *)&local_110,(longlong *)local_c8,
                         &local_100);
    plVar15 = local_100;
    if ((char)uVar9 == '\0') {
      local_110 = (longlong *)0x0;
      local_d8 = (int *)0x0;
    }
    piVar5 = local_d8;
    plVar4 = local_110;
    if (local_110 == (longlong *)0x0) {
      if (local_d8 == (int *)0x0) {
        local_108 = (longlong *)0x0;
        local_f8 = (longlong *)0x0;
      }
      else {
        if (((byte)param_3 & 3) == 2) {
          return (char *)0x8000000000000002;
        }
        FUN_00002e28(local_d8,(longlong)local_f0,local_b8);
        local_f8 = (longlong *)
                   FUN_00007874(piVar5,local_e8,(longlong *)&local_108,(longlong)local_f0);
      }
      plVar15 = DAT_00017c28;
      if ((param_3 & 1) != 0) {
        plVar15 = DAT_00017c20;
      }
      local_100 = plVar15;
      if (plVar15 == (longlong *)0x0) {
        return (char *)0x8000000000000002;
      }
    }
    else {
      if (((DAT_00011430 != '\0') && (DAT_00013249 != '\0')) &&
         ((*(uint *)((longlong)local_110 + 6) & 0x1000000) == 0)) {
        return (char *)0x8000000000000002;
      }
      if ((param_3 & 2) != 0) {
        plVar10 = DAT_00017c28;
        if ((param_3 & 1) != 0) {
          plVar10 = DAT_00017c20;
        }
        if (local_100 != plVar10) {
          return (char *)0x8000000000000002;
        }
      }
      FUN_00002e28((int *)local_110,(longlong)local_100,local_b8);
      local_f8 = (longlong *)
                 FUN_00007874(local_c8[0],local_e8,(longlong *)&local_108,(longlong)plVar15);
    }
    pcVar8 = (char *)FUN_00004b10(plVar15);
    if ((longlong)pcVar8 < 0) {
      return pcVar8;
    }
  } while ((pcVar8 != (char *)0x0) && (uVar14 = uVar14 + 1, uVar14 < 2));
  if (uVar14 == 2) {
    return (char *)0x8000000000000007;
  }
  uVar9 = FUN_00004aa4((longlong)plVar15);
  uVar2 = plVar15[1];
  uVar12 = 0;
  cVar7 = (char)uVar9;
  if (param_1 != (ushort *)0x0) {
    for (puVar11 = param_1; puVar11 < (ushort *)(uVar2 + (longlong)param_1); puVar11 = puVar11 + 1)
    {
      if (*puVar11 == 0) {
        uVar12 = ((longlong)puVar11 - (longlong)param_1 >> 1) * 2 + 2;
        goto LAB_0000551e;
      }
    }
    uVar12 = uVar2 + 1;
  }
LAB_0000551e:
  if (uVar2 < uVar12) {
    return (char *)0x8000000000000009;
  }
  pcVar8 = (char *)FUN_0000d51c((longlong *)param_1,param_2,local_res18,(longlong *)&param_5,
                                (ulonglong *)&local_res20,local_f8,(ulonglong)local_108,local_b8);
  if ((longlong)pcVar8 < 0) {
    if (pcVar8 == (char *)0x8000000000000014) {
      return (char *)0x0;
    }
    return pcVar8;
  }
  plVar16 = (longlong *)(-(ulonglong)(param_3 != 0) & (ulonglong)local_res20);
  local_110 = plVar16;
  uVar12 = FUN_00003c9c(param_1,param_2);
  plVar10 = local_110;
  cVar6 = (char)uVar12;
  local_100 = (longlong *)(CONCAT44(local_100._4_4_,local_res18[0]) & 0xffffffff00000040);
  if ((((local_res18[0] & 0x40) == 0) && (plVar16 == (longlong *)0x0)) ||
     ((local_res18[0] & 2) == 0)) {
    if (plVar4 == (longlong *)0x0) {
      return (char *)0x800000000000000e;
    }
    if ((DAT_00013249 != '\0') && ((*(byte *)(plVar15 + 7) & 1) == 0)) {
      return (char *)0x8000000000000002;
    }
    if (cVar6 != '\0') {
      return (char *)0x8000000000000008;
    }
    puVar1 = (undefined1 *)((longlong)plVar4 + 9);
    puVar3 = (undefined8 *)plVar15[8];
    local_res20 = (undefined *)(CONCAT71(local_res20._1_7_,*puVar1) ^ 0x80);
    if (puVar3 != (undefined8 *)0x0) {
      cVar7 = (*(code *)*puVar3)(puVar3,puVar1,1);
      if (cVar7 == '\0') {
        return (char *)0x8000000000000007;
      }
      cVar7 = (*(code *)puVar3[3])(puVar3,puVar1,1,&local_res20);
      (*(code *)puVar3[1])(puVar3,puVar1,1);
      pcVar8 = (char *)(~-(ulonglong)(cVar7 != '\0') & 0x8000000000000007);
      if (-1 < (longlong)pcVar8) {
        if (local_f0 == plVar15) {
          FUN_000029c8(param_1,param_2,plVar15);
          return pcVar8;
        }
        return pcVar8;
      }
      return pcVar8;
    }
    return (char *)0x8000000000000003;
  }
  if (plVar4 == (longlong *)0x0) {
    if ((((local_f8 != (longlong *)0x0) && ((local_res18[0] & 0x40) == 0)) &&
        (local_108 == local_110)) &&
       (lVar13 = FUN_0000a918(local_f8,param_5,(ulonglong)local_110), lVar13 == 0)) {
      return (char *)0x0;
    }
    if (cVar7 != '\0') {
      pcVar8 = (char *)FUN_00002ec0((short *)param_1,param_2,local_res18[0],(ulonglong)local_110,
                                    param_5,plVar15,0,(longlong)local_b8,(undefined8 *)0x0,0);
      if (-1 < (longlong)pcVar8) {
        if (cVar6 == '\0') {
          if (piVar5 == (int *)0x0) {
            FUN_000026e8(plVar15[3] - (ulonglong)*(ushort *)((longlong)plVar15 + 0x2a),
                         (longlong)plVar15);
          }
          else if (((byte)DAT_00017940 & 5) == 0) {
            FUN_00002860(plVar15[3] - (ulonglong)*(ushort *)((longlong)plVar15 + 0x2a),
                         (longlong)plVar15);
          }
        }
        else {
LAB_00005858:
          FUN_000060a4();
          FUN_00002a88();
        }
      }
LAB_00005865:
      if ((pcVar8 == (char *)0x8000000000000007) &&
         (uVar9 = FUN_00004aa4((longlong)plVar15), (char)uVar9 == '\0')) goto LAB_00005898;
LAB_00005883:
      cVar7 = '\x01';
    }
  }
  else {
    if ((cVar6 != '\0') &&
       (pcVar8 = (char *)FUN_00005034(param_1,local_110,(longlong)param_5), (longlong)pcVar8 < 0)) {
      return pcVar8;
    }
    if (cVar7 != '\0') {
      if ((undefined8 *)plVar15[8] != (undefined8 *)0x0) {
        pcVar8 = (char *)FUN_0000332c((int *)plVar4,local_e8,local_res18[0],(ulonglong)plVar10,
                                      param_5,local_c8[0],(longlong)local_b8,plVar15,
                                      (undefined8 *)plVar15[8]);
        if ((-1 < (longlong)pcVar8) && (cVar6 != '\0')) goto LAB_00005858;
        goto LAB_00005865;
      }
      pcVar8 = (char *)0x8000000000000003;
      goto LAB_00005883;
    }
  }
  if ((pcVar8 != (char *)0x8000000000000009) && (cVar7 != '\0')) {
    return pcVar8;
  }
LAB_00005898:
  plVar10 = local_110;
  lVar13 = 0;
  local_e8 = 0;
  local_e0 = FUN_00003c3c;
  local_d0 = &PTR_LAB_00011410;
  local_c8[1] = (int *)0x3ffc;
  local_d8 = (int *)0x0;
  local_c8[0] = (int *)0x0;
  if (plVar4 != (longlong *)0x0) {
    *(byte *)((longlong)plVar4 + 9) = *(byte *)((longlong)plVar4 + 9) ^ 0x80;
  }
  local_res20 = (undefined *)((ulonglong)local_res20 & 0xffffffff00000000);
  lVar17 = lVar13;
  do {
    local_88[0] = lVar13;
    uVar12 = FUN_00004294((longlong)plVar15,*(undefined **)((longlong)&local_e8 + lVar17),
                          *(undefined8 *)((longlong)&local_d8 + lVar17),local_88,
                          *(undefined **)((longlong)local_c8 + lVar17));
    if ((longlong)uVar12 < 0) {
      if (local_88[0] != 0) goto LAB_00005a0f;
LAB_00005a14:
      if (-1 < (longlong)pcVar8) {
        return pcVar8;
      }
      break;
    }
    plVar16 = local_f8;
    plVar18 = local_108;
    if ((int)local_100 == 0) {
      plVar16 = (longlong *)0x0;
      plVar18 = (longlong *)0x0;
    }
    pcVar8 = (char *)FUN_00002ec0((short *)param_1,param_2,local_res18[0],(ulonglong)plVar10,param_5
                                  ,local_88,0,(longlong)local_b8,plVar16,(ulonglong)plVar18);
    if (pcVar8 != (char *)0x8000000000000009) {
      if (-1 < (longlong)pcVar8) {
        pcVar8 = (char *)FUN_00004724(plVar15,(longlong)local_88);
      }
LAB_00005a0f:
      FUN_00001d7c(local_88[0]);
      goto LAB_00005a14;
    }
    if ((((0x1ff < (ulonglong)((longlong)plVar10 - (longlong)local_108)) &&
         (&UNK_000003ff < plVar10)) &&
        (uVar12 = FUN_000037d4((longlong *)&PTR_DAT_00011530,param_1,param_2), (char)uVar12 == '\0')
        ) && (uVar12 = FUN_000037d4((longlong *)&PTR_DAT_00011450,param_1,param_2),
             (char)uVar12 == '\0')) goto LAB_00005a0f;
    lVar13 = 0;
    FUN_00001d7c(local_88[0]);
    lVar17 = lVar17 + 8;
    uVar14 = (int)local_res20 + 1;
    local_res20 = (undefined *)CONCAT44(local_res20._4_4_,uVar14);
  } while (uVar14 < 2);
  if (plVar4 != (longlong *)0x0) {
    *(byte *)((longlong)plVar4 + 9) = *(byte *)((longlong)plVar4 + 9) ^ 0x80;
  }
  FUN_00004b10(plVar15);
  return pcVar8;
}


/* 0x8b34 */

undefined8 * FUN_00008a80(undefined8 *param_1,ulonglong param_2)

{
  ushort *puVar1;
  ushort *puVar2;
  ulonglong uVar3;
  undefined8 *puVar4;
  undefined8 local_28;
  ulonglong local_20;
  longlong local_18 [2];
  
  if (0x20 < param_2) {
    if (&local_28 != param_1) {
      FUN_00001180(&local_28,param_1,0x20);
    }
    if ((param_2 - 0x20 == local_20) && (1 < local_20)) {
      puVar1 = (ushort *)FUN_0000a2b8(local_20,param_1 + 4);
      if (puVar1 == (ushort *)0x0) {
        return (undefined8 *)0x8000000000000009;
      }
      for (puVar2 = puVar1; puVar2 < (ushort *)(local_20 + (longlong)puVar1); puVar2 = puVar2 + 1) {
        if (*puVar2 == 0) {
          uVar3 = ((longlong)puVar2 - (longlong)puVar1 >> 1) * 2 + 2;
          goto LAB_00008b2c;
        }
      }
      uVar3 = local_20 + 1;
LAB_00008b2c:
      if (uVar3 <= local_20) {
        puVar4 = FUN_00005b3c(&local_20,puVar1,local_18);
        if (-1 < (longlong)puVar4) {
          FUN_000092e8((short *)(param_1 + 4),local_20,(short *)puVar1);
          if (param_1 + 2 != local_18) {
            FUN_00001180(param_1 + 2,local_18,0x10);
          }
        }
        param_1[1] = local_20;
        FUN_0000a384((ulonglong)puVar1);
        return puVar4;
      }
    }
  }
  return (undefined8 *)0x8000000000000002;
}


/* 0xbd28 */

void FUN_0000bd28(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 *param_4,
                 undefined8 param_5)

{
  longlong lVar1;
  
  lVar1 = (**(code **)(DAT_000132f0 + 0x50))(0x200,8,param_2,0,param_4);
  if (-1 < lVar1) {
    (**(code **)(DAT_000132f0 + 0xa8))(param_1,*param_4,param_5);
  }
  return;
}

