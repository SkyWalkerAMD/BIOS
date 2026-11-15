/* 0xbec8 */

/* WARNING: Type propagation algorithm not settling */

longlong ProtectedVariableCheck
                   (ushort *param_1,longlong *param_2,uint param_3,ulonglong param_4,
                   undefined8 *param_5)

{
  longlong lVar1;
  ulonglong uVar2;
  wchar_t *pwVar3;
  wchar_t wVar4;
  wchar_t *pwVar5;
  ulonglong *puVar6;
  byte bVar7;
  undefined **ppuVar8;
  undefined4 local_dc8;
  undefined4 local_dc4;
  undefined4 local_dc0;
  undefined4 local_dbc;
  undefined4 local_db8;
  undefined4 local_db4;
  undefined4 local_db0;
  undefined4 local_dac;
  ulonglong local_da8;
  undefined4 local_da0;
  undefined4 local_d9c;
  undefined4 local_d98;
  undefined4 local_d94;
  ulonglong local_d90 [404];
  char local_ee;
  
  local_db4 = 0x47e4fb8e;
  local_db0 = 0xec391abc;
  local_db8 = 0x5855ce1b;
  local_dac = 0xcf960caa;
  local_d90[2] = 8;
  local_da0 = 0x2441822e;
  local_d9c = 0x4d667e0c;
  local_d98 = 0xb2c9328f;
  local_d94 = 0x340ceea;
  if (DAT_00011a51 == -1) {
    FUN_000101c0((undefined4 *)(local_d90 + 3),0,0xd46);
    local_da8 = 0xd46;
    lVar1 = FUN_0000618c((ushort *)u_Setup_00012060,(longlong *)&DAT_00011210,(uint *)0x0,&local_da8
                         ,local_d90 + 3);
    if (-1 < lVar1) {
      DAT_00011a51 = local_ee;
    }
  }
  if (DAT_00011a51 == '\0') {
    uVar2 = FUN_0000c478(param_1,param_2);
    if ((char)uVar2 != '\0') {
      return -0x7fffffffffffffed;
    }
    lVar1 = FUN_0000b1ac(param_2,(longlong *)&local_db8,0x10);
    if (lVar1 == 0) {
      pwVar5 = u__SETADMINPASSWD_00012c70;
      wVar4 = *param_1;
      pwVar3 = (wchar_t *)param_1;
      while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
        pwVar3 = pwVar3 + 1;
        pwVar5 = pwVar5 + 1;
        wVar4 = *pwVar3;
      }
      if (*pwVar3 == *pwVar5) {
        return -0x7fffffffffffffed;
      }
    }
    if (lVar1 == 0) {
      pwVar3 = u__SETUSERPASSWD_00012c90;
      for (; (*param_1 != L'\0' && (*param_1 == *pwVar3)); param_1 = param_1 + 1) {
        pwVar3 = pwVar3 + 1;
      }
      if (*param_1 == *pwVar3) {
        return -0x7fffffffffffffed;
      }
    }
    return -0x7ffffffffffffffd;
  }
  pwVar5 = u_NvLockMailbox_00012c50;
  wVar4 = *param_1;
  pwVar3 = (wchar_t *)param_1;
  while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
    pwVar3 = pwVar3 + 1;
    pwVar5 = pwVar5 + 1;
    wVar4 = *pwVar3;
  }
  if ((*pwVar3 == *pwVar5) &&
     (lVar1 = FUN_0000b1ac(param_2,(longlong *)&DAT_00011a58,0x10), lVar1 == 0)) {
    return (ulonglong)(-(uint)((param_3 & 4) != 0) & 0xc) + 0x8000000000000003;
  }
  if (DAT_00013218 == 0) {
    if (DAT_000132fa == '\0') {
      local_da8 = local_da8 & 0xffffffff00000000;
      puVar6 = &local_da8;
      local_d90[0] = 0;
      local_dc8 = 0x5855ce1b;
      local_dc4 = 0x47e4fb8e;
      local_dc0 = 0xec391abc;
      local_dbc = 0xcf960caa;
      lVar1 = FUN_0000618c((ushort *)u__SETUPPASSWD_00012ce0,(longlong *)&local_dc8,(uint *)puVar6,
                           local_d90,(undefined8 *)0x0);
      if (lVar1 != -0x7ffffffffffffff2) {
        puVar6 = (ulonglong *)0x0;
        VariableSetCore((ushort *)u__SETUPPASSWD_00012ce0,(longlong *)&local_dc8,0,(undefined *)0x0,
                        (longlong *)0x0);
      }
      local_da8 = 0;
      local_d90[1] = 0;
      local_d90[0] = 0;
      FUN_0000b094(&DAT_00011040,&LAB_0000bbe4,puVar6,(undefined8 *)&local_dc8,local_d90);
      FUN_0000b094(&DAT_00011070,&LAB_0000bc84,puVar6,(undefined8 *)&DAT_00013300,&local_da8);
      FUN_0000b094(&DAT_00011000,FUN_0000bc30,puVar6,(undefined8 *)&local_dc8,local_d90 + 1);
      DAT_000132fa = '\x01';
      if (DAT_00013218 != 0) goto LAB_0000c1ea;
    }
  }
  else {
LAB_0000c1ea:
    if ((DAT_0001330b == '\0') && (DAT_000130e1 == '\x01')) {
      FUN_0000bd3c();
      DAT_0001330b = '\x01';
    }
    if (((DAT_000132c9 == '\0') && (DAT_00013218 != 0)) &&
       (lVar1 = (**(code **)(DAT_00013218 + 0x28))(DAT_00013218,&DAT_00011a70,&PTR_LAB_00011a68,8),
       lVar1 == 0)) {
      DAT_000132c9 = '\x01';
    }
    if ((DAT_0001330c == '\0') &&
       (lVar1 = (**(code **)(DAT_00013218 + 0x28))(DAT_00013218,&local_da0,&DAT_00011a50,1),
       lVar1 == 0)) {
      DAT_0001330c = '\x01';
    }
  }
  if (((DAT_000132c8 == '\0') && (DAT_0001330b == '\0')) &&
     (lVar1 = FUN_0000618c((ushort *)u_NvLockMailbox_00012c50,(longlong *)&DAT_00011a58,(uint *)0x0,
                           local_d90 + 2,&DAT_000133a8), lVar1 == 0)) {
    DAT_0001330d = DAT_000133a8 == 1;
  }
  lVar1 = -0x7ffffffffffffffd;
  ppuVar8 = &PTR_FUN_00012cd0;
  do {
    if (lVar1 != -0x7ffffffffffffffd) {
      return lVar1;
    }
    lVar1 = (*(code *)*ppuVar8)(param_1,param_2,param_3,param_4,param_5);
    ppuVar8 = ppuVar8 + 1;
  } while (*ppuVar8 != (undefined *)0x0);
  if (lVar1 != -0x7ffffffffffffffd) {
    return lVar1;
  }
  bVar7 = -(DAT_00011a50 != '\0') & DAT_0001330d;
  lVar1 = FUN_0000b1ac(param_2,(longlong *)&local_db8,0x10);
  if (lVar1 == 0) {
    pwVar5 = u__SETADMINPASSWD_00012c70;
    wVar4 = *param_1;
    pwVar3 = (wchar_t *)param_1;
    while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
      pwVar3 = pwVar3 + 1;
      pwVar5 = pwVar5 + 1;
      wVar4 = *pwVar3;
    }
    if (*pwVar3 != *pwVar5) goto LAB_0000c393;
LAB_0000c3ca:
    if (DAT_0001330d == 0) {
      if ((1 < param_4) &&
         (*(short *)((longlong)param_5 + ((param_4 & 0xfffffffffffffffe) - 2)) == 0)) {
        param_4 = param_4 - 2;
      }
      if (param_4 - 6 < 0x23) {
        lVar1 = FUN_0000c6ec((short *)param_1,param_5,param_4);
        if (lVar1 == 0) {
          lVar1 = -0x7fffffffffffffa1;
        }
      }
      else {
        lVar1 = -0x7ffffffffffffffe;
      }
    }
    else {
      lVar1 = -0x7fffffffffffffe6;
    }
  }
  else {
LAB_0000c393:
    if (lVar1 == 0) {
      pwVar5 = u__SETUSERPASSWD_00012c90;
      wVar4 = *param_1;
      pwVar3 = (wchar_t *)param_1;
      while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
        pwVar3 = pwVar3 + 1;
        pwVar5 = pwVar5 + 1;
        wVar4 = *pwVar3;
      }
      if (*pwVar3 == *pwVar5) goto LAB_0000c3ca;
    }
    lVar1 = -0x7ffffffffffffffd;
    if (((DAT_00013082 != '\0') && (bVar7 != 0)) && (DAT_000132c8 == '\0')) {
      lVar1 = -0x7ffffffffffffffd;
    }
  }
  return lVar1;
}


/* 0x6790 */

char * VariableSetCore(ushort *param_1,longlong *param_2,uint param_3,undefined *param_4,
                      longlong *param_5)

{
  undefined1 *puVar1;
  undefined8 *puVar2;
  longlong *plVar3;
  int *piVar4;
  char cVar5;
  char cVar6;
  char *pcVar7;
  undefined8 uVar8;
  longlong *plVar9;
  ulonglong uVar10;
  ulonglong uVar11;
  longlong lVar12;
  ushort *puVar13;
  uint uVar14;
  longlong *plVar15;
  longlong lVar16;
  longlong *plVar17;
  uint local_res18 [2];
  undefined *local_res20;
  longlong *plVar18;
  longlong *local_120;
  longlong *local_118;
  undefined8 local_110;
  longlong *local_108;
  longlong local_100;
  int *local_f8;
  code *local_f0;
  int *local_e8;
  undefined **local_e0;
  byte local_d8 [8];
  undefined8 local_d0;
  undefined1 local_c8;
  undefined8 local_c7;
  undefined8 local_bf;
  undefined8 local_b7;
  undefined4 local_af;
  undefined2 local_ab;
  undefined1 local_a9;
  longlong *local_a8 [2];
  longlong local_98 [11];
  
  uVar14 = 0;
  local_120 = (longlong *)0x0;
  local_110 = (longlong *)0x0;
  local_118 = (longlong *)0x0;
  local_d8[0] = 0;
  local_d0 = 0;
  local_c8 = 0;
  local_c7 = 0;
  local_bf = 0;
  local_b7 = 0;
  local_af = 0;
  local_ab = 0;
  local_a9 = 0;
  if ((undefined *)0xffff < param_4) {
    return (char *)0x8000000000000009;
  }
  local_res18[0] = param_3;
  local_res20 = param_4;
  pcVar7 = FUN_000062b8(param_1,param_2,param_3,param_4,(char *)param_5);
  if ((longlong)pcVar7 < 0) {
    return pcVar7;
  }
  do {
    uVar8 = FUN_00004074(param_1,param_2,&local_100,(longlong *)&local_f8,(longlong *)0x0,
                         (longlong *)local_a8,(longlong *)&local_120,(longlong *)&local_e8,
                         &local_110);
    plVar18 = local_a8[0];
    plVar15 = local_110;
    if ((char)uVar8 == '\0') {
      local_120 = (longlong *)0x0;
      local_f8 = (int *)0x0;
    }
    piVar4 = local_f8;
    plVar3 = local_120;
    plVar9 = (longlong *)0x0;
    if (local_120 == (longlong *)0x0) {
      if (local_f8 == (int *)0x0) {
        local_118 = (longlong *)0x0;
      }
      else {
        if (((byte)param_3 & 3) == 2) {
          return (char *)0x8000000000000002;
        }
        FUN_00004334(local_f8,(longlong)local_a8[0],local_d8);
        plVar9 = (longlong *)FUN_00008704(piVar4,local_100,(longlong *)&local_118,(longlong)plVar18)
        ;
      }
      plVar15 = DAT_00013aa8;
      if ((param_3 & 1) != 0) {
        plVar15 = DAT_00013aa0;
      }
      local_110 = plVar15;
      local_108 = plVar9;
      if (plVar15 == (longlong *)0x0) {
        return (char *)0x8000000000000002;
      }
    }
    else {
      if ((DAT_000130e1 != '\0') && ((*(uint *)((longlong)local_120 + 6) & 0x1000000) == 0)) {
        return (char *)0x8000000000000002;
      }
      if ((param_3 & 2) != 0) {
        plVar9 = DAT_00013aa8;
        if ((param_3 & 1) != 0) {
          plVar9 = DAT_00013aa0;
        }
        if (local_110 != plVar9) {
          return (char *)0x8000000000000002;
        }
      }
      FUN_00004334((int *)local_120,(longlong)local_110,local_d8);
      local_108 = (longlong *)
                  FUN_00008704(local_e8,local_100,(longlong *)&local_118,(longlong)plVar15);
    }
    pcVar7 = (char *)FUN_00005fd8(plVar15);
    if ((longlong)pcVar7 < 0) {
      return pcVar7;
    }
  } while ((pcVar7 != (char *)0x0) && (uVar14 = uVar14 + 1, uVar14 < 2));
  if (uVar14 == 2) {
    return (char *)0x8000000000000007;
  }
  uVar8 = FUN_00005f6c((longlong)plVar15);
  uVar11 = plVar15[1];
  cVar6 = (char)uVar8;
  puVar13 = param_1;
  uVar10 = FUN_00002ed4((short *)param_1,uVar11);
  if (uVar11 < uVar10) {
    return (char *)0x8000000000000009;
  }
  pcVar7 = (char *)FUN_0000d79c((longlong *)puVar13,param_2,local_res18,(longlong *)&param_5,
                                (ulonglong *)&local_res20,local_108,(ulonglong)local_118,local_d8);
  if ((longlong)pcVar7 < 0) {
    if (pcVar7 == (char *)0x8000000000000014) {
      return (char *)0x0;
    }
    return pcVar7;
  }
  plVar17 = (longlong *)(-(ulonglong)(param_3 != 0) & (ulonglong)local_res20);
  local_120 = plVar17;
  uVar11 = FUN_00005174(param_1,param_2);
  plVar9 = local_120;
  cVar5 = (char)uVar11;
  local_res20 = (undefined *)CONCAT71(local_res20._1_7_,cVar5);
  local_110 = (longlong *)(CONCAT44(local_110._4_4_,param_3) & 0xffffffff00000040);
  if ((((param_3 & 0x40) == 0) && (plVar17 == (longlong *)0x0)) || ((param_3 & 2) == 0)) {
    if (plVar3 == (longlong *)0x0) {
      return (char *)0x800000000000000e;
    }
    if ((DAT_000130e1 != '\0') && ((*(byte *)(plVar15 + 7) & 1) == 0)) {
      return (char *)0x8000000000000002;
    }
    if (cVar5 != '\0') {
      return (char *)0x8000000000000008;
    }
    puVar1 = (undefined1 *)((longlong)plVar3 + 9);
    puVar2 = (undefined8 *)plVar15[8];
    local_res20 = (undefined *)(CONCAT71(local_res20._1_7_,*puVar1) ^ 0x80);
    if (puVar2 != (undefined8 *)0x0) {
      cVar6 = (*(code *)*puVar2)(puVar2,puVar1,1);
      if (cVar6 == '\0') {
        return (char *)0x8000000000000007;
      }
      cVar6 = (*(code *)puVar2[3])(puVar2,puVar1,1,&local_res20);
      (*(code *)puVar2[1])(puVar2,puVar1,1);
      pcVar7 = (char *)(~-(ulonglong)(cVar6 != '\0') & 0x8000000000000007);
      if (-1 < (longlong)pcVar7) {
        if (plVar18 == plVar15) {
          FUN_00003ed4(param_1,param_2,plVar15);
          return pcVar7;
        }
        return pcVar7;
      }
      return pcVar7;
    }
    return (char *)0x8000000000000003;
  }
  if (plVar3 == (longlong *)0x0) {
    if ((((local_108 != (longlong *)0x0) && ((param_3 & 0x40) == 0)) && (local_118 == local_120)) &&
       (lVar12 = FUN_0000b1ac(local_108,param_5,(ulonglong)local_120), lVar12 == 0)) {
      return (char *)0x0;
    }
    if (cVar6 != '\0') {
      pcVar7 = (char *)FUN_000043cc((short *)param_1,param_2,param_3,(ulonglong)local_120,param_5,
                                    plVar15,0,(longlong)local_d8,(undefined8 *)0x0,0);
      if (-1 < (longlong)pcVar7) {
        if ((char)local_res20 == '\0') {
          if (piVar4 == (int *)0x0) {
            FUN_00003bf4(plVar15[3] - (ulonglong)*(ushort *)((longlong)plVar15 + 0x2a),
                         (longlong)plVar15);
          }
          else if (((byte)DAT_000137c0 & 5) == 0) {
            FUN_00003d6c(plVar15[3] - (ulonglong)*(ushort *)((longlong)plVar15 + 0x2a),
                         (longlong)plVar15);
          }
        }
        else {
LAB_00006cec:
          FUN_000073b4();
          FUN_00003f94();
        }
      }
LAB_00006cf9:
      if ((pcVar7 == (char *)0x8000000000000007) &&
         (uVar8 = FUN_00005f6c((longlong)plVar15), (char)uVar8 == '\0')) goto LAB_00006d26;
LAB_00006d17:
      cVar6 = '\x01';
    }
  }
  else {
    if ((cVar5 != '\0') &&
       (pcVar7 = (char *)FUN_000064f0(param_1,local_120,(longlong)param_5), (longlong)pcVar7 < 0)) {
      return pcVar7;
    }
    if (cVar6 != '\0') {
      if ((undefined8 *)plVar15[8] != (undefined8 *)0x0) {
        pcVar7 = (char *)FUN_00004838((int *)plVar3,local_100,param_3,(ulonglong)plVar9,param_5,
                                      local_e8,(longlong)local_d8,plVar15,(undefined8 *)plVar15[8]);
        if ((-1 < (longlong)pcVar7) && ((char)local_res20 != '\0')) goto LAB_00006cec;
        goto LAB_00006cf9;
      }
      pcVar7 = (char *)0x8000000000000003;
      goto LAB_00006d17;
    }
  }
  if ((pcVar7 != (char *)0x8000000000000009) && (cVar6 != '\0')) {
    return pcVar7;
  }
LAB_00006d26:
  lVar12 = 0;
  local_f8 = (int *)0x0;
  local_f0 = FUN_00005114;
  local_e0 = &PTR_LAB_000113e0;
  local_a8[1] = (longlong *)&LAB_000054c4;
  local_e8 = (int *)0x0;
  local_a8[0] = (longlong *)0x0;
  if (plVar3 != (longlong *)0x0) {
    *(byte *)((longlong)plVar3 + 9) = *(byte *)((longlong)plVar3 + 9) ^ 0x80;
  }
  local_res20 = (undefined *)((ulonglong)local_res20 & 0xffffffff00000000);
  lVar16 = lVar12;
  do {
    local_98[0] = lVar12;
    uVar11 = FUN_0000575c((longlong)plVar15,*(undefined **)((longlong)&local_f8 + lVar16),
                          *(undefined8 *)((longlong)&local_e8 + lVar16),local_98,
                          *(undefined **)((longlong)local_a8 + lVar16));
    if ((longlong)uVar11 < 0) {
      if (local_98[0] != 0) goto LAB_00006ec2;
LAB_00006ec7:
      if (-1 < (longlong)pcVar7) {
        return pcVar7;
      }
      break;
    }
    plVar18 = local_108;
    plVar9 = local_118;
    if ((int)local_110 == 0) {
      plVar18 = (longlong *)0x0;
      plVar9 = (longlong *)0x0;
    }
    pcVar7 = (char *)FUN_000043cc((short *)param_1,param_2,param_3,(ulonglong)local_120,param_5,
                                  local_98,0,(longlong)local_d8,plVar18,(ulonglong)plVar9);
    if (pcVar7 != (char *)0x8000000000000009) {
      if (-1 < (longlong)pcVar7) {
        if ((undefined8 *)plVar15[8] == (undefined8 *)0x0) {
          pcVar7 = (char *)0x8000000000000003;
        }
        else {
          pcVar7 = (char *)FUN_00005bec(plVar15,(longlong)local_98,(undefined8 *)plVar15[8]);
        }
      }
LAB_00006ec2:
      FUN_00003288(local_98[0]);
      goto LAB_00006ec7;
    }
    if ((((0x1ff < (ulonglong)((longlong)local_120 - (longlong)local_118)) &&
         (&UNK_000003ff < local_120)) &&
        (uVar11 = FUN_00004cac((longlong *)&PTR_DAT_000114e0,param_1,param_2), (char)uVar11 == '\0')
        ) && (uVar11 = FUN_00004cac((longlong *)&PTR_DAT_00011400,param_1,param_2),
             (char)uVar11 == '\0')) goto LAB_00006ec2;
    lVar12 = 0;
    FUN_00003288(local_98[0]);
    lVar16 = lVar16 + 8;
    uVar14 = (int)local_res20 + 1;
    local_res20 = (undefined *)CONCAT44(local_res20._4_4_,uVar14);
  } while (uVar14 < 2);
  if (plVar3 != (longlong *)0x0) {
    *(byte *)((longlong)plVar3 + 9) = *(byte *)((longlong)plVar3 + 9) ^ 0x80;
  }
  FUN_00005fd8(plVar15);
  return pcVar7;
}


/* 0x225c */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

char * FUN_0000225c(undefined8 param_1,longlong param_2)

{
  char *pcVar1;
  undefined8 uVar2;
  longlong lVar3;
  undefined8 *puVar4;
  bool bVar5;
  undefined8 local_res8;
  undefined8 local_res10;
  undefined1 local_res18 [8];
  undefined8 local_res20;
  undefined1 local_68 [8];
  undefined4 *local_60;
  undefined1 *local_58;
  undefined1 *local_50;
  undefined1 local_48;
  
  local_res10 = 0;
  if (DAT_000131e0 == 0) {
    DAT_000131d0 = *(longlong *)(param_2 + 0x60);
    DAT_000131d8 = *(longlong *)(param_2 + 0x58);
    _DAT_000131c8 = param_1;
    DAT_000131e0 = param_2;
  }
  DAT_00013ac8 = param_1;
  _DAT_00013ad0 = param_2;
  FUN_0000aeb0();
  FUN_0000afb0();
  _DAT_000131e8 = _DAT_000131e8 + 1;
  _DAT_000131f8 = _DAT_000131f8 + 1;
  (**(code **)(DAT_000131d0 + 0x50))(0x201,8,&LAB_0000b0ec,FUN_00001d38,&local_res8);
  (**(code **)(DAT_000131d0 + 0x50))(0x60000202,8,&LAB_0000b128,&LAB_00001d7c,&local_res8);
  FUN_0000af38(1,0x3108000);
  DAT_00013080 = '\0';
  if (0x20045 < *(uint *)(param_2 + 8)) {
    DAT_00013081 = 1;
  }
  FUN_0000773c();
  if (DAT_00013248 == (undefined *)0x0) {
    DAT_0001195c = 0;
    DAT_00013248 = &DAT_00011958;
    DAT_00013088 = &DAT_00011958;
  }
  pcVar1 = (char *)FUN_00007c94();
  if (-1 < (longlong)pcVar1) {
    bVar5 = pcVar1 == (char *)0x4000000000000002;
    uVar2 = FUN_00001754(FUN_00006f04);
    if (((char)uVar2 == '\0') && (FUN_00005d68(DAT_00013aa0,'\x01',3), DAT_00013080 != '\0')) {
      bVar5 = true;
    }
    lVar3 = FUN_0000ccb8();
    if (-1 < lVar3) {
      puVar4 = &DAT_00013310;
      (**(code **)(DAT_000131d0 + 0x140))(&DAT_00011140,0);
      if (DAT_00013310 == 0) {
        FUN_0000b094(&DAT_00011140,&LAB_0000cc4c,puVar4,&local_res8,local_68);
      }
      local_res8 = 0;
      (**(code **)(DAT_000131d0 + 0x170))(0x200,8,FUN_0000cc6c,0,&DAT_00011050,&local_res8);
    }
    pcVar1 = (char *)FUN_00002d28();
    if (-1 < (longlong)pcVar1) {
      local_60 = &DAT_000137c0;
      _DAT_00013ac0 = 0;
      local_58 = &LAB_00002688;
      local_50 = &DAT_00013ac0;
      uVar2 = 2;
      local_48 = bVar5;
      pcVar1 = FUN_00007050((ushort *)u_NvramMailBox_00012098,(longlong *)&DAT_00011170,2,
                            (undefined *)(IMAGE_DOS_HEADER_00000000.e_res_4_ + 2),
                            (longlong *)&local_60);
      if ((longlong)pcVar1 < 0) {
        pcVar1 = FUN_00007050((ushort *)u_NvramMailBox_00012098,(longlong *)&DAT_00011170,0,
                              (undefined *)0x0,(longlong *)0x0);
        if ((longlong)pcVar1 < 0) {
          return pcVar1;
        }
        uVar2 = 2;
        pcVar1 = FUN_00007050((ushort *)u_NvramMailBox_00012098,(longlong *)&DAT_00011170,2,
                              (undefined *)(IMAGE_DOS_HEADER_00000000.e_res_4_ + 2),
                              (longlong *)&local_60);
        if ((longlong)pcVar1 < 0) {
          return pcVar1;
        }
      }
      FUN_0000b094(&DAT_00011120,FUN_00001d38,uVar2,&local_res20,local_res18);
      FUN_0000b094(&DAT_000110d0,FUN_00002220,uVar2,&local_res20,local_res18);
      *(undefined1 **)(DAT_000131d8 + 0x50) = &LAB_00001988;
      *(undefined1 **)(DAT_000131d8 + 0x48) = &LAB_00001898;
      *(code **)(DAT_000131d8 + 0x80) = FUN_00001a9c;
      (**(code **)(DAT_000131d0 + 0x148))(&local_res10,&DAT_00011300,0,0);
      if (DAT_00013080 == '\0') {
        FUN_00001f80(local_res10);
      }
      pcVar1 = (char *)0x0;
    }
  }
  return pcVar1;
}


/* 0xc460 */

/* WARNING: Type propagation algorithm not settling */

longlong ProtectedVariableCheck
                   (ushort *param_1,longlong *param_2,uint param_3,ulonglong param_4,
                   undefined8 *param_5)

{
  longlong lVar1;
  ulonglong uVar2;
  wchar_t *pwVar3;
  wchar_t wVar4;
  wchar_t *pwVar5;
  ulonglong *puVar6;
  byte bVar7;
  undefined **ppuVar8;
  undefined4 local_dc8;
  undefined4 local_dc4;
  undefined4 local_dc0;
  undefined4 local_dbc;
  undefined4 local_db8;
  undefined4 local_db4;
  undefined4 local_db0;
  undefined4 local_dac;
  ulonglong local_da8;
  undefined4 local_da0;
  undefined4 local_d9c;
  undefined4 local_d98;
  undefined4 local_d94;
  ulonglong local_d90 [404];
  char local_ee;
  
  local_db4 = 0x47e4fb8e;
  local_db0 = 0xec391abc;
  local_db8 = 0x5855ce1b;
  local_dac = 0xcf960caa;
  local_d90[2] = 8;
  local_da0 = 0x2441822e;
  local_d9c = 0x4d667e0c;
  local_d98 = 0xb2c9328f;
  local_d94 = 0x340ceea;
  if (DAT_00011a51 == -1) {
    FUN_000101c0((undefined4 *)(local_d90 + 3),0,0xd46);
    local_da8 = 0xd46;
    lVar1 = FUN_0000618c((ushort *)u_Setup_00012060,(longlong *)&DAT_00011210,(uint *)0x0,&local_da8
                         ,local_d90 + 3);
    if (-1 < lVar1) {
      DAT_00011a51 = local_ee;
    }
  }
  if (DAT_00011a51 == '\0') {
    uVar2 = FUN_0000c478(param_1,param_2);
    if ((char)uVar2 != '\0') {
      return -0x7fffffffffffffed;
    }
    lVar1 = FUN_0000b1ac(param_2,(longlong *)&local_db8,0x10);
    if (lVar1 == 0) {
      pwVar5 = u__SETADMINPASSWD_00012c70;
      wVar4 = *param_1;
      pwVar3 = (wchar_t *)param_1;
      while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
        pwVar3 = pwVar3 + 1;
        pwVar5 = pwVar5 + 1;
        wVar4 = *pwVar3;
      }
      if (*pwVar3 == *pwVar5) {
        return -0x7fffffffffffffed;
      }
    }
    if (lVar1 == 0) {
      pwVar3 = u__SETUSERPASSWD_00012c90;
      for (; (*param_1 != L'\0' && (*param_1 == *pwVar3)); param_1 = param_1 + 1) {
        pwVar3 = pwVar3 + 1;
      }
      if (*param_1 == *pwVar3) {
        return -0x7fffffffffffffed;
      }
    }
    return -0x7ffffffffffffffd;
  }
  pwVar5 = u_NvLockMailbox_00012c50;
  wVar4 = *param_1;
  pwVar3 = (wchar_t *)param_1;
  while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
    pwVar3 = pwVar3 + 1;
    pwVar5 = pwVar5 + 1;
    wVar4 = *pwVar3;
  }
  if ((*pwVar3 == *pwVar5) &&
     (lVar1 = FUN_0000b1ac(param_2,(longlong *)&DAT_00011a58,0x10), lVar1 == 0)) {
    return (ulonglong)(-(uint)((param_3 & 4) != 0) & 0xc) + 0x8000000000000003;
  }
  if (DAT_00013218 == 0) {
    if (DAT_000132fa == '\0') {
      local_da8 = local_da8 & 0xffffffff00000000;
      puVar6 = &local_da8;
      local_d90[0] = 0;
      local_dc8 = 0x5855ce1b;
      local_dc4 = 0x47e4fb8e;
      local_dc0 = 0xec391abc;
      local_dbc = 0xcf960caa;
      lVar1 = FUN_0000618c((ushort *)u__SETUPPASSWD_00012ce0,(longlong *)&local_dc8,(uint *)puVar6,
                           local_d90,(undefined8 *)0x0);
      if (lVar1 != -0x7ffffffffffffff2) {
        puVar6 = (ulonglong *)0x0;
        VariableSetCore((ushort *)u__SETUPPASSWD_00012ce0,(longlong *)&local_dc8,0,(undefined *)0x0,
                        (longlong *)0x0);
      }
      local_da8 = 0;
      local_d90[1] = 0;
      local_d90[0] = 0;
      FUN_0000b094(&DAT_00011040,&LAB_0000bbe4,puVar6,(undefined8 *)&local_dc8,local_d90);
      FUN_0000b094(&DAT_00011070,&LAB_0000bc84,puVar6,(undefined8 *)&DAT_00013300,&local_da8);
      FUN_0000b094(&DAT_00011000,FUN_0000bc30,puVar6,(undefined8 *)&local_dc8,local_d90 + 1);
      DAT_000132fa = '\x01';
      if (DAT_00013218 != 0) goto LAB_0000c1ea;
    }
  }
  else {
LAB_0000c1ea:
    if ((DAT_0001330b == '\0') && (DAT_000130e1 == '\x01')) {
      FUN_0000bd3c();
      DAT_0001330b = '\x01';
    }
    if (((DAT_000132c9 == '\0') && (DAT_00013218 != 0)) &&
       (lVar1 = (**(code **)(DAT_00013218 + 0x28))(DAT_00013218,&DAT_00011a70,&PTR_LAB_00011a68,8),
       lVar1 == 0)) {
      DAT_000132c9 = '\x01';
    }
    if ((DAT_0001330c == '\0') &&
       (lVar1 = (**(code **)(DAT_00013218 + 0x28))(DAT_00013218,&local_da0,&DAT_00011a50,1),
       lVar1 == 0)) {
      DAT_0001330c = '\x01';
    }
  }
  if (((DAT_000132c8 == '\0') && (DAT_0001330b == '\0')) &&
     (lVar1 = FUN_0000618c((ushort *)u_NvLockMailbox_00012c50,(longlong *)&DAT_00011a58,(uint *)0x0,
                           local_d90 + 2,&DAT_000133a8), lVar1 == 0)) {
    DAT_0001330d = DAT_000133a8 == 1;
  }
  lVar1 = -0x7ffffffffffffffd;
  ppuVar8 = &PTR_FUN_00012cd0;
  do {
    if (lVar1 != -0x7ffffffffffffffd) {
      return lVar1;
    }
    lVar1 = (*(code *)*ppuVar8)(param_1,param_2,param_3,param_4,param_5);
    ppuVar8 = ppuVar8 + 1;
  } while (*ppuVar8 != (undefined *)0x0);
  if (lVar1 != -0x7ffffffffffffffd) {
    return lVar1;
  }
  bVar7 = -(DAT_00011a50 != '\0') & DAT_0001330d;
  lVar1 = FUN_0000b1ac(param_2,(longlong *)&local_db8,0x10);
  if (lVar1 == 0) {
    pwVar5 = u__SETADMINPASSWD_00012c70;
    wVar4 = *param_1;
    pwVar3 = (wchar_t *)param_1;
    while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
      pwVar3 = pwVar3 + 1;
      pwVar5 = pwVar5 + 1;
      wVar4 = *pwVar3;
    }
    if (*pwVar3 != *pwVar5) goto LAB_0000c393;
LAB_0000c3ca:
    if (DAT_0001330d == 0) {
      if ((1 < param_4) &&
         (*(short *)((longlong)param_5 + ((param_4 & 0xfffffffffffffffe) - 2)) == 0)) {
        param_4 = param_4 - 2;
      }
      if (param_4 - 6 < 0x23) {
        lVar1 = FUN_0000c6ec((short *)param_1,param_5,param_4);
        if (lVar1 == 0) {
          lVar1 = -0x7fffffffffffffa1;
        }
      }
      else {
        lVar1 = -0x7ffffffffffffffe;
      }
    }
    else {
      lVar1 = -0x7fffffffffffffe6;
    }
  }
  else {
LAB_0000c393:
    if (lVar1 == 0) {
      pwVar5 = u__SETUSERPASSWD_00012c90;
      wVar4 = *param_1;
      pwVar3 = (wchar_t *)param_1;
      while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
        pwVar3 = pwVar3 + 1;
        pwVar5 = pwVar5 + 1;
        wVar4 = *pwVar3;
      }
      if (*pwVar3 == *pwVar5) goto LAB_0000c3ca;
    }
    lVar1 = -0x7ffffffffffffffd;
    if (((DAT_00013082 != '\0') && (bVar7 != 0)) && (DAT_000132c8 == '\0')) {
      lVar1 = -0x7ffffffffffffffd;
    }
  }
  return lVar1;
}


/* 0xc6ec */

void FUN_0000c6ec(short *param_1,undefined8 *param_2,ulonglong param_3)

{
  longlong lVar1;
  wchar_t *pwVar2;
  longlong *plVar3;
  short sVar4;
  ulonglong uVar5;
  ushort *puVar6;
  uint local_res20 [2];
  undefined4 local_118;
  undefined4 local_114;
  undefined4 local_110;
  undefined4 local_10c;
  byte *local_108;
  ushort local_100 [28];
  longlong local_c8 [5];
  longlong local_a0 [17];
  
  local_118 = 0xc811fa38;
  local_114 = 0x457942c8;
  local_110 = 0xe960bba9;
  local_10c = 0x34fbdd4e;
  local_res20[0] = 0;
  local_108 = IMAGE_DOS_HEADER_00000000.e_program + 0x11;
  lVar1 = FUN_0000618c((ushort *)u_AMITSESetup_00012cb0,(longlong *)&local_118,local_res20,
                       (ulonglong *)&local_108,local_c8);
  if (lVar1 == 0) {
    FUN_000101ce((undefined4 *)local_100,0x2a,0);
    FUN_00010220((undefined8 *)local_100,param_2,param_3);
    uVar5 = 1;
    puVar6 = local_100;
    do {
      sVar4 = (short)uVar5;
      uVar5 = uVar5 + 1;
      *puVar6 = *puVar6 ^ sVar4 * -0x6ca5;
      puVar6 = puVar6 + 1;
    } while (uVar5 < 0x15);
    pwVar2 = u__SETADMINPASSWD_00012c70;
    for (; (*param_1 != L'\0' && (*param_1 == *pwVar2)); param_1 = param_1 + 1) {
      pwVar2 = pwVar2 + 1;
    }
    if (*param_1 == *pwVar2) {
      FUN_000101ce((undefined4 *)local_a0,0x28,0);
      plVar3 = local_a0;
    }
    else {
      FUN_000101ce((undefined4 *)local_c8,0x28,0);
      plVar3 = local_c8;
    }
    FUN_00010220(plVar3,(undefined8 *)local_100,0x28);
    VariableSetCore((ushort *)u_AMITSESetup_00012cb0,(longlong *)&local_118,local_res20[0],local_108
                    ,local_c8);
  }
  return;
}


/* 0xbc30 */

void FUN_0000bc30(void)

{
  DAT_0001330d = 0;
  DAT_0001330b = 0;
  if (DAT_0001330a == '\0') {
    DAT_000133a8 = 0;
    (**(code **)(DAT_000131d8 + 0x58))(u_NvLockMailbox_00012c50,&DAT_00011a58,2,8,&DAT_000133a8);
  }
  return;
}


/* 0xbbe4 */

void FUN_0000c6ec(short *param_1,undefined8 *param_2,ulonglong param_3)

{
  longlong lVar1;
  wchar_t *pwVar2;
  longlong *plVar3;
  short sVar4;
  ulonglong uVar5;
  ushort *puVar6;
  uint local_res20 [2];
  undefined4 local_118;
  undefined4 local_114;
  undefined4 local_110;
  undefined4 local_10c;
  byte *local_108;
  ushort local_100 [28];
  longlong local_c8 [5];
  longlong local_a0 [17];
  
  local_118 = 0xc811fa38;
  local_114 = 0x457942c8;
  local_110 = 0xe960bba9;
  local_10c = 0x34fbdd4e;
  local_res20[0] = 0;
  local_108 = IMAGE_DOS_HEADER_00000000.e_program + 0x11;
  lVar1 = FUN_0000618c((ushort *)u_AMITSESetup_00012cb0,(longlong *)&local_118,local_res20,
                       (ulonglong *)&local_108,local_c8);
  if (lVar1 == 0) {
    FUN_000101ce((undefined4 *)local_100,0x2a,0);
    FUN_00010220((undefined8 *)local_100,param_2,param_3);
    uVar5 = 1;
    puVar6 = local_100;
    do {
      sVar4 = (short)uVar5;
      uVar5 = uVar5 + 1;
      *puVar6 = *puVar6 ^ sVar4 * -0x6ca5;
      puVar6 = puVar6 + 1;
    } while (uVar5 < 0x15);
    pwVar2 = u__SETADMINPASSWD_00012c70;
    for (; (*param_1 != L'\0' && (*param_1 == *pwVar2)); param_1 = param_1 + 1) {
      pwVar2 = pwVar2 + 1;
    }
    if (*param_1 == *pwVar2) {
      FUN_000101ce((undefined4 *)local_a0,0x28,0);
      plVar3 = local_a0;
    }
    else {
      FUN_000101ce((undefined4 *)local_c8,0x28,0);
      plVar3 = local_c8;
    }
    FUN_00010220(plVar3,(undefined8 *)local_100,0x28);
    VariableSetCore((ushort *)u_AMITSESetup_00012cb0,(longlong *)&local_118,local_res20[0],local_108
                    ,local_c8);
  }
  return;
}

