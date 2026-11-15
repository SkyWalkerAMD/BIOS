/* 0x12b0 */

longlong entry(ulonglong param_1,longlong param_2)

{
  longlong lVar1;
  undefined *puVar2;
  
  FUN_00001330(param_1,param_2);
  puVar2 = &DAT_00013450;
  DAT_00013550 = -0x7fffffffffffffff;
  lVar1 = FUN_00001000((undefined8 *)&DAT_00013450);
  if (lVar1 == 0) {
    lVar1 = FUN_00001820(puVar2,param_2);
    if ((-1 < lVar1) || (DAT_00013550 < 0)) {
      DAT_00013550 = lVar1;
    }
    FUN_000010d0(0x13450,0xffffffffffffffff);
  }
  lVar1 = DAT_00013550;
  if (DAT_00013550 < 0) {
    FUN_0000a384(DAT_000175e8);
  }
  return lVar1;
}


/* 0xc030 */

undefined8
FUN_0000bf84(ushort *param_1,longlong *param_2,undefined8 param_3,ulonglong param_4,
            longlong *param_5)

{
  ulonglong uVar1;
  undefined8 uVar2;
  longlong lVar3;
  
  uVar1 = FUN_0000c638(param_1,param_2);
  if ((char)uVar1 != '\x01') {
    return 0x8000000000000003;
  }
  if (DAT_00013438 != 3) {
    uVar2 = FUN_0000c6f0(param_5,param_4);
    if ((int)uVar2 == 0) {
      if ((param_4 != 6) || (lVar3 = FUN_0000a918(param_5,(longlong *)&DAT_00013400,6), lVar3 != 0))
      {
        FUN_0000bed8();
        return 0x8000000000000006;
      }
    }
    else if ((int)uVar2 == 3) {
      if (DAT_0001343d == '\x01') {
        DAT_00013438 = DAT_00013438 + 1;
      }
      else {
        DAT_00013438 = 0;
      }
      FUN_0000bed8();
      return 0x800000000000001a;
    }
    FUN_0000bf30();
    DAT_00013438 = 0;
    return 0x800000000000005f;
  }
  return 0x800000000000000f;
}


/* 0xc5b2 */

/* WARNING: Type propagation algorithm not settling */

longlong FUN_0000c064(ushort *param_1,longlong *param_2,uint param_3,ulonglong param_4,int *param_5)

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
  if (DAT_00011b91 == -1) {
    FUN_0000ffe0((undefined4 *)(local_d90 + 3),0,0xd46);
    local_da8 = 0xd46;
    lVar1 = FUN_00004cac((ushort *)u_Setup_00012e20,(longlong *)&DAT_00011250,(uint *)0x0,&local_da8
                         ,local_d90 + 3);
    if (-1 < lVar1) {
      DAT_00011b91 = local_ee;
    }
  }
  if (DAT_00011b91 == '\0') {
    uVar2 = FUN_0000c638(param_1,param_2);
    if ((char)uVar2 != '\0') {
      return -0x7fffffffffffffed;
    }
    lVar1 = FUN_0000a918(param_2,(longlong *)&local_db8,0x10);
    if (lVar1 == 0) {
      pwVar5 = u__SETADMINPASSWD_00012e30;
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
      pwVar3 = u__SETUSERPASSWD_00012e50;
      for (; (*param_1 != L'\0' && (*param_1 == *pwVar3)); param_1 = param_1 + 1) {
        pwVar3 = pwVar3 + 1;
      }
      if (*param_1 == *pwVar3) {
        return -0x7fffffffffffffed;
      }
    }
    return -0x7ffffffffffffffd;
  }
  pwVar5 = u_NvLockMailbox_00012e00;
  wVar4 = *param_1;
  pwVar3 = (wchar_t *)param_1;
  while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
    pwVar3 = pwVar3 + 1;
    pwVar5 = pwVar5 + 1;
    wVar4 = *pwVar3;
  }
  if ((*pwVar3 == *pwVar5) &&
     (lVar1 = FUN_0000a918(param_2,(longlong *)&DAT_00011b98,0x10), lVar1 == 0)) {
    return (ulonglong)(-(uint)((param_3 & 4) != 0) & 0xc) + 0x8000000000000003;
  }
  if (DAT_000132e0 == 0) {
    if (DAT_0001342a == '\0') {
      local_da8 = local_da8 & 0xffffffff00000000;
      puVar6 = &local_da8;
      local_d90[0] = 0;
      local_dc8 = 0x5855ce1b;
      local_dc4 = 0x47e4fb8e;
      local_dc0 = 0xec391abc;
      local_dbc = 0xcf960caa;
      lVar1 = FUN_00004cac((ushort *)u__SETUPPASSWD_00012ea0,(longlong *)&local_dc8,(uint *)puVar6,
                           local_d90,(undefined8 *)0x0);
      if (lVar1 != -0x7ffffffffffffff2) {
        puVar6 = (ulonglong *)0x0;
        FUN_000052d4((ushort *)u__SETUPPASSWD_00012ea0,(longlong *)&local_dc8,0,(undefined *)0x0,
                     (longlong *)0x0);
      }
      local_da8 = 0;
      local_d90[1] = 0;
      local_d90[0] = 0;
      FUN_0000bd28(&DAT_00011050,&LAB_0000bd80,puVar6,(undefined8 *)&local_dc8,local_d90);
      FUN_0000bd28(&DAT_00011070,&LAB_0000be20,puVar6,(undefined8 *)&DAT_00013430,&local_da8);
      FUN_0000a858();
      DAT_0001342a = '\x01';
      if (DAT_000132e0 != 0) goto LAB_0000c378;
    }
  }
  else {
LAB_0000c378:
    if ((DAT_0001343b == '\0') && (DAT_00013249 == '\x01')) {
      FUN_0000bed8();
      DAT_0001343b = '\x01';
    }
    if (((DAT_000133fa == '\0') && (DAT_000132e0 != 0)) &&
       (lVar1 = (**(code **)(DAT_000132e0 + 0x28))(DAT_000132e0,&DAT_00011bb0,&PTR_LAB_00011ba8,8),
       lVar1 == 0)) {
      DAT_000133fa = '\x01';
    }
    if ((DAT_0001343c == '\0') &&
       (lVar1 = (**(code **)(DAT_000132e0 + 0x28))(DAT_000132e0,&local_da0,&DAT_00011b90,1),
       lVar1 == 0)) {
      DAT_0001343c = '\x01';
    }
  }
  if (((DAT_000133f9 == '\0') && (DAT_0001343b == '\0')) &&
     (lVar1 = FUN_00004cac((ushort *)u_NvLockMailbox_00012e00,(longlong *)&DAT_00011b98,(uint *)0x0,
                           local_d90 + 2,&DAT_000135c0), lVar1 == 0)) {
    DAT_0001343d = DAT_000135c0 == 1;
  }
  lVar1 = -0x7ffffffffffffffd;
  ppuVar8 = &PTR_FUN_00012e90;
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
  bVar7 = -(DAT_00011b90 != '\0') & DAT_0001343d;
  lVar1 = FUN_0000a918(param_2,(longlong *)&local_db8,0x10);
  if (lVar1 == 0) {
    pwVar5 = u__SETADMINPASSWD_00012e30;
    wVar4 = *param_1;
    pwVar3 = (wchar_t *)param_1;
    while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
      pwVar3 = pwVar3 + 1;
      pwVar5 = pwVar5 + 1;
      wVar4 = *pwVar3;
    }
    if (*pwVar3 != *pwVar5) goto LAB_0000c522;
LAB_0000c559:
    if (DAT_0001343d == 0) {
      if ((1 < param_4) &&
         (*(short *)((longlong)param_5 + ((param_4 & 0xfffffffffffffffe) - 2)) == 0)) {
        param_4 = param_4 - 2;
      }
      if (param_4 - 6 < 0x23) {
        lVar1 = FUN_0000c8ac((short *)param_1,(undefined8 *)param_5,param_4);
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
LAB_0000c522:
    if (lVar1 == 0) {
      pwVar5 = u__SETUSERPASSWD_00012e50;
      wVar4 = *param_1;
      pwVar3 = (wchar_t *)param_1;
      while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
        pwVar3 = pwVar3 + 1;
        pwVar5 = pwVar5 + 1;
        wVar4 = *pwVar3;
      }
      if (*pwVar3 == *pwVar5) goto LAB_0000c559;
    }
    lVar1 = -0x7ffffffffffffffd;
    if (((DAT_00013290 != '\0') && (bVar7 != 0)) && (DAT_000133f9 == '\0')) {
      uVar2 = FUN_00008bc0((short *)param_1,param_2,(ulonglong)param_3,param_4,param_5);
      lVar1 = -0x7ffffffffffffffd;
      if ((longlong)uVar2 < 0) {
        lVar1 = -0x7fffffffffffffe6;
      }
    }
  }
  return lVar1;
}


/* 0xc5f8 */

/* WARNING: Type propagation algorithm not settling */

longlong FUN_0000c064(ushort *param_1,longlong *param_2,uint param_3,ulonglong param_4,int *param_5)

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
  if (DAT_00011b91 == -1) {
    FUN_0000ffe0((undefined4 *)(local_d90 + 3),0,0xd46);
    local_da8 = 0xd46;
    lVar1 = FUN_00004cac((ushort *)u_Setup_00012e20,(longlong *)&DAT_00011250,(uint *)0x0,&local_da8
                         ,local_d90 + 3);
    if (-1 < lVar1) {
      DAT_00011b91 = local_ee;
    }
  }
  if (DAT_00011b91 == '\0') {
    uVar2 = FUN_0000c638(param_1,param_2);
    if ((char)uVar2 != '\0') {
      return -0x7fffffffffffffed;
    }
    lVar1 = FUN_0000a918(param_2,(longlong *)&local_db8,0x10);
    if (lVar1 == 0) {
      pwVar5 = u__SETADMINPASSWD_00012e30;
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
      pwVar3 = u__SETUSERPASSWD_00012e50;
      for (; (*param_1 != L'\0' && (*param_1 == *pwVar3)); param_1 = param_1 + 1) {
        pwVar3 = pwVar3 + 1;
      }
      if (*param_1 == *pwVar3) {
        return -0x7fffffffffffffed;
      }
    }
    return -0x7ffffffffffffffd;
  }
  pwVar5 = u_NvLockMailbox_00012e00;
  wVar4 = *param_1;
  pwVar3 = (wchar_t *)param_1;
  while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
    pwVar3 = pwVar3 + 1;
    pwVar5 = pwVar5 + 1;
    wVar4 = *pwVar3;
  }
  if ((*pwVar3 == *pwVar5) &&
     (lVar1 = FUN_0000a918(param_2,(longlong *)&DAT_00011b98,0x10), lVar1 == 0)) {
    return (ulonglong)(-(uint)((param_3 & 4) != 0) & 0xc) + 0x8000000000000003;
  }
  if (DAT_000132e0 == 0) {
    if (DAT_0001342a == '\0') {
      local_da8 = local_da8 & 0xffffffff00000000;
      puVar6 = &local_da8;
      local_d90[0] = 0;
      local_dc8 = 0x5855ce1b;
      local_dc4 = 0x47e4fb8e;
      local_dc0 = 0xec391abc;
      local_dbc = 0xcf960caa;
      lVar1 = FUN_00004cac((ushort *)u__SETUPPASSWD_00012ea0,(longlong *)&local_dc8,(uint *)puVar6,
                           local_d90,(undefined8 *)0x0);
      if (lVar1 != -0x7ffffffffffffff2) {
        puVar6 = (ulonglong *)0x0;
        FUN_000052d4((ushort *)u__SETUPPASSWD_00012ea0,(longlong *)&local_dc8,0,(undefined *)0x0,
                     (longlong *)0x0);
      }
      local_da8 = 0;
      local_d90[1] = 0;
      local_d90[0] = 0;
      FUN_0000bd28(&DAT_00011050,&LAB_0000bd80,puVar6,(undefined8 *)&local_dc8,local_d90);
      FUN_0000bd28(&DAT_00011070,&LAB_0000be20,puVar6,(undefined8 *)&DAT_00013430,&local_da8);
      FUN_0000a858();
      DAT_0001342a = '\x01';
      if (DAT_000132e0 != 0) goto LAB_0000c378;
    }
  }
  else {
LAB_0000c378:
    if ((DAT_0001343b == '\0') && (DAT_00013249 == '\x01')) {
      FUN_0000bed8();
      DAT_0001343b = '\x01';
    }
    if (((DAT_000133fa == '\0') && (DAT_000132e0 != 0)) &&
       (lVar1 = (**(code **)(DAT_000132e0 + 0x28))(DAT_000132e0,&DAT_00011bb0,&PTR_LAB_00011ba8,8),
       lVar1 == 0)) {
      DAT_000133fa = '\x01';
    }
    if ((DAT_0001343c == '\0') &&
       (lVar1 = (**(code **)(DAT_000132e0 + 0x28))(DAT_000132e0,&local_da0,&DAT_00011b90,1),
       lVar1 == 0)) {
      DAT_0001343c = '\x01';
    }
  }
  if (((DAT_000133f9 == '\0') && (DAT_0001343b == '\0')) &&
     (lVar1 = FUN_00004cac((ushort *)u_NvLockMailbox_00012e00,(longlong *)&DAT_00011b98,(uint *)0x0,
                           local_d90 + 2,&DAT_000135c0), lVar1 == 0)) {
    DAT_0001343d = DAT_000135c0 == 1;
  }
  lVar1 = -0x7ffffffffffffffd;
  ppuVar8 = &PTR_FUN_00012e90;
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
  bVar7 = -(DAT_00011b90 != '\0') & DAT_0001343d;
  lVar1 = FUN_0000a918(param_2,(longlong *)&local_db8,0x10);
  if (lVar1 == 0) {
    pwVar5 = u__SETADMINPASSWD_00012e30;
    wVar4 = *param_1;
    pwVar3 = (wchar_t *)param_1;
    while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
      pwVar3 = pwVar3 + 1;
      pwVar5 = pwVar5 + 1;
      wVar4 = *pwVar3;
    }
    if (*pwVar3 != *pwVar5) goto LAB_0000c522;
LAB_0000c559:
    if (DAT_0001343d == 0) {
      if ((1 < param_4) &&
         (*(short *)((longlong)param_5 + ((param_4 & 0xfffffffffffffffe) - 2)) == 0)) {
        param_4 = param_4 - 2;
      }
      if (param_4 - 6 < 0x23) {
        lVar1 = FUN_0000c8ac((short *)param_1,(undefined8 *)param_5,param_4);
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
LAB_0000c522:
    if (lVar1 == 0) {
      pwVar5 = u__SETUSERPASSWD_00012e50;
      wVar4 = *param_1;
      pwVar3 = (wchar_t *)param_1;
      while ((wVar4 != L'\0' && (wVar4 == *pwVar5))) {
        pwVar3 = pwVar3 + 1;
        pwVar5 = pwVar5 + 1;
        wVar4 = *pwVar3;
      }
      if (*pwVar3 == *pwVar5) goto LAB_0000c559;
    }
    lVar1 = -0x7ffffffffffffffd;
    if (((DAT_00013290 != '\0') && (bVar7 != 0)) && (DAT_000133f9 == '\0')) {
      uVar2 = FUN_00008bc0((short *)param_1,param_2,(ulonglong)param_3,param_4,param_5);
      lVar1 = -0x7ffffffffffffffd;
      if ((longlong)uVar2 < 0) {
        lVar1 = -0x7fffffffffffffe6;
      }
    }
  }
  return lVar1;
}


/* 0xd5ec */

ulonglong FUN_0000d51c(longlong *param_1,longlong *param_2,uint *param_3,longlong *param_4,
                      ulonglong *param_5,longlong *param_6,ulonglong param_7,byte *param_8)

{
  byte bVar1;
  ulonglong uVar2;
  uint uVar3;
  ulonglong *in_stack_ffffffffffffffe8;
  
  uVar3 = *param_3;
  if ((uVar3 & 0x10) == 0) {
    bVar1 = *param_8;
    if (((uVar3 & 0x30) == 0) && ((bVar1 & 0x30) == 0)) {
      return 0;
    }
    if ((uVar3 & 0x30) == 0x30) {
      return 0x8000000000000002;
    }
    if (((((bVar1 & 0x30) != 0) && (uVar3 != 0)) && ((bVar1 & 0x30 & uVar3) == 0)) ||
       ((uVar3 = bVar1 & 0x30 | uVar3, *param_5 == 0 || (*param_4 == 0)))) {
      return 0x800000000000001a;
    }
    if (DAT_00013440 != 0) {
      if ((uVar3 & 0x20) == 0) {
        uVar2 = FUN_0000df60(param_1,param_2,uVar3,param_4,param_5,(longlong)param_6,
                             in_stack_ffffffffffffffe8,(longlong)param_8);
        return uVar2;
      }
      uVar2 = FUN_0000da3c(param_1,param_2,uVar3,param_4,param_5,param_6,param_7,(longlong)param_8);
      return uVar2;
    }
  }
  return 0x8000000000000003;
}


/* 0xd729 */

longlong FUN_0000d5fc(undefined8 param_1,undefined8 param_2,longlong *param_3,ulonglong param_4)

{
  uint uVar1;
  uint uVar2;
  longlong lVar3;
  undefined1 uVar4;
  longlong lVar5;
  longlong *local_res18;
  ulonglong local_res20;
  longlong local_28;
  longlong *local_20;
  
  local_28 = 0;
  local_res18 = param_3;
  local_res20 = param_4;
  lVar3 = FUN_0000ca08((ushort *)&DAT_00012130,&DAT_00011020,(uint *)0x0,&local_20,&local_28);
  if (((-1 < lVar3) && (local_20 != (longlong *)0x0)) && (local_28 != 0)) {
    uVar1 = *(uint *)((longlong)local_20 + 0x14);
    lVar3 = FUN_0000a918(local_20,(longlong *)&DAT_000112d0,0x10);
    if (lVar3 == 0) {
      uVar4 = 0xb;
      lVar5 = 0;
      lVar3 = 0;
    }
    else {
      lVar3 = FUN_0000a918(local_20,&DAT_000111d0,0x10);
      if (lVar3 != 0) {
        return -0x7fffffffffffffe6;
      }
      lVar5 = (longlong)local_20 + (ulonglong)uVar1 + 0x2c;
      uVar4 = 8;
      lVar3 = (ulonglong)*(uint *)(local_20 + 3) - 0x10;
    }
    uVar2 = *(uint *)(local_20 + 3);
    lVar3 = (**(code **)(DAT_00013440 + 8))
                      (DAT_00013440,param_1,param_2,lVar5,lVar3,&local_res18,&local_res20,uVar4,2);
    if (lVar3 < 0) {
      return lVar3;
    }
    if (((ulonglong)uVar2 - 0x10 == local_res20) &&
       (lVar3 = FUN_0000a918((longlong *)((longlong)local_20 + (ulonglong)uVar1 + 0x2c),local_res18,
                             local_res20), lVar3 == 0)) {
      return 0;
    }
  }
  return -0x7fffffffffffffe6;
}


/* 0xd87d */

longlong FUN_0000d748(ushort *param_1,longlong *param_2,undefined8 param_3,undefined8 param_4)

{
  bool bVar1;
  uint uVar2;
  longlong lVar3;
  longlong lVar4;
  longlong *plVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  uint uVar8;
  ulonglong local_38;
  longlong *local_30;
  
  local_38 = 0;
  lVar3 = FUN_0000ca08(param_1,param_2,(uint *)0x0,&local_30,(longlong *)&local_38);
  if (((lVar3 < 0) || (local_30 == (longlong *)0x0)) || (local_38 == 0)) {
    lVar3 = -0x7fffffffffffffe6;
  }
  else {
    bVar1 = false;
    plVar5 = local_30;
    uVar6 = local_38;
    do {
      if ((uVar6 == 0) || (uVar2 = *(uint *)(plVar5 + 2), uVar6 < uVar2)) break;
      lVar4 = FUN_0000a918(plVar5,&DAT_000111d0,0x10);
      if (lVar4 == 0) {
        uVar7 = (ulonglong)*(uint *)(plVar5 + 3);
        lVar4 = (longlong)plVar5 + (ulonglong)*(uint *)((longlong)plVar5 + 0x14) + 0x1c;
        uVar8 = 0;
        uVar2 = (uint)((((ulonglong)uVar2 - (ulonglong)*(uint *)((longlong)plVar5 + 0x14)) - 0x1c) /
                      uVar7);
        if (uVar2 != 0) {
          do {
            lVar3 = (**(code **)(DAT_00013440 + 8))
                              (DAT_00013440,param_3,param_4,lVar4 + 0x10,uVar7,&stack0x00000028,
                               &stack0x00000030,1,2);
            if (-1 < lVar3) {
              bVar1 = true;
              break;
            }
            uVar7 = (ulonglong)*(uint *)(plVar5 + 3);
            uVar8 = uVar8 + 1;
            lVar4 = lVar4 + uVar7;
          } while (uVar8 < uVar2);
        }
      }
      uVar6 = uVar6 - *(uint *)(plVar5 + 2);
      plVar5 = (longlong *)((longlong)plVar5 + (ulonglong)*(uint *)(plVar5 + 2));
    } while (!bVar1);
    if (!bVar1) {
      lVar3 = -0x7fffffffffffffe6;
    }
  }
  return lVar3;
}


/* 0xd893 */

longlong FUN_0000d748(ushort *param_1,longlong *param_2,undefined8 param_3,undefined8 param_4)

{
  bool bVar1;
  uint uVar2;
  longlong lVar3;
  longlong lVar4;
  longlong *plVar5;
  ulonglong uVar6;
  ulonglong uVar7;
  uint uVar8;
  ulonglong local_38;
  longlong *local_30;
  
  local_38 = 0;
  lVar3 = FUN_0000ca08(param_1,param_2,(uint *)0x0,&local_30,(longlong *)&local_38);
  if (((lVar3 < 0) || (local_30 == (longlong *)0x0)) || (local_38 == 0)) {
    lVar3 = -0x7fffffffffffffe6;
  }
  else {
    bVar1 = false;
    plVar5 = local_30;
    uVar6 = local_38;
    do {
      if ((uVar6 == 0) || (uVar2 = *(uint *)(plVar5 + 2), uVar6 < uVar2)) break;
      lVar4 = FUN_0000a918(plVar5,&DAT_000111d0,0x10);
      if (lVar4 == 0) {
        uVar7 = (ulonglong)*(uint *)(plVar5 + 3);
        lVar4 = (longlong)plVar5 + (ulonglong)*(uint *)((longlong)plVar5 + 0x14) + 0x1c;
        uVar8 = 0;
        uVar2 = (uint)((((ulonglong)uVar2 - (ulonglong)*(uint *)((longlong)plVar5 + 0x14)) - 0x1c) /
                      uVar7);
        if (uVar2 != 0) {
          do {
            lVar3 = (**(code **)(DAT_00013440 + 8))
                              (DAT_00013440,param_3,param_4,lVar4 + 0x10,uVar7,&stack0x00000028,
                               &stack0x00000030,1,2);
            if (-1 < lVar3) {
              bVar1 = true;
              break;
            }
            uVar7 = (ulonglong)*(uint *)(plVar5 + 3);
            uVar8 = uVar8 + 1;
            lVar4 = lVar4 + uVar7;
          } while (uVar8 < uVar2);
        }
      }
      uVar6 = uVar6 - *(uint *)(plVar5 + 2);
      plVar5 = (longlong *)((longlong)plVar5 + (ulonglong)*(uint *)(plVar5 + 2));
    } while (!bVar1);
    if (!bVar1) {
      lVar3 = -0x7fffffffffffffe6;
    }
  }
  return lVar3;
}


/* 0xddcc */

ulonglong FUN_0000da3c(longlong *param_1,longlong *param_2,uint param_3,longlong *param_4,
                      ulonglong *param_5,longlong *param_6,ulonglong param_7,longlong param_8)

{
  uint uVar1;
  ushort *puVar2;
  char cVar3;
  char cVar4;
  ulonglong uVar5;
  longlong lVar6;
  undefined8 uVar7;
  byte bVar8;
  char cVar9;
  longlong lVar10;
  undefined8 in_stack_ffffffffffffff60;
  longlong *local_70;
  ulonglong local_68;
  ushort *local_60;
  longlong local_58;
  ulonglong local_50;
  ulonglong local_48;
  ushort *local_40;
  
  if ((param_3 & 0x20) == 0) {
LAB_0000da6e:
    uVar5 = 0x8000000000000002;
  }
  else {
    puVar2 = (ushort *)*param_4;
    if (0x27 < *param_5) {
      uVar1 = *(uint *)(puVar2 + 8);
      if (((ulonglong)uVar1 <= *param_5 - 0x10) && (0x17 < uVar1)) {
        local_60 = puVar2 + 0x14;
        uVar5 = (ulonglong)uVar1 + 0x10;
        lVar10 = (longlong)puVar2 + (uVar5 - (longlong)local_60);
        if ((puVar2[0xb] == 0xef1) &&
           (local_48 = uVar5, local_40 = puVar2,
           lVar6 = FUN_0000a918((longlong *)(puVar2 + 0xc),(longlong *)&DAT_000110d0,0x10),
           lVar6 == 0)) {
          cVar3 = FUN_0000cec4();
          if (((cVar3 == '\0') || (param_6 == (longlong *)0x0)) ||
             (cVar9 = '\x01', *param_5 != uVar5)) {
            cVar9 = '\0';
          }
          if (param_6 == (longlong *)0x0) {
            local_58 = 0;
          }
          else {
            local_58 = *(longlong *)(param_8 + 8);
          }
          if (cVar9 == '\0') {
            lVar6 = FUN_0000e978(puVar2,(longlong *)&local_50);
            uVar5 = 0;
            if (lVar6 < 0) {
              do {
                if ((*(char *)(uVar5 + (longlong)puVar2) != '\0') && ((param_3 & 0x40) == 0))
                goto LAB_0000ddcc;
                uVar5 = uVar5 + 1;
                local_50 = 0;
              } while (uVar5 < 7);
            }
            if ((param_3 & 0x40) == 0) {
              if ((((*(char *)((longlong)puVar2 + 7) != '\0') ||
                   (*(char *)((longlong)puVar2 + 0xf) != '\0')) ||
                  ((*(int *)(puVar2 + 4) != 0 || ((puVar2[6] != 0 || ((char)puVar2[7] != '\0'))))))
                 || ((param_6 != (longlong *)0x0 && (local_50 <= *(ulonglong *)(param_8 + 8)))))
              goto LAB_0000ddcc;
            }
            else if ((param_6 != (longlong *)0x0) && (local_50 < *(ulonglong *)(param_8 + 8))) {
              local_50 = *(ulonglong *)(param_8 + 8);
            }
            *(ulonglong *)(param_8 + 8) = local_50;
          }
          bVar8 = 4;
          lVar6 = FUN_0000a918(param_2,(longlong *)&DAT_00011090,0x10);
          if (lVar6 == 0) {
            bVar8 = 2;
LAB_0000dc2e:
            if ((param_3 & 1) == 0) goto LAB_0000da6e;
            cVar4 = FUN_0000cf4c();
            cVar9 = cVar3;
            if (cVar4 != '\0') goto LAB_0000dc52;
LAB_0000dc54:
            uVar5 = 0;
          }
          else {
            cVar4 = FUN_0000cd7c(param_1,param_2);
            if (cVar4 != '\0') {
              bVar8 = 0;
              goto LAB_0000dc2e;
            }
            cVar4 = FUN_0000cdcc(param_1,param_2);
            if (cVar4 != '\0') {
              bVar8 = 1;
              goto LAB_0000dc2e;
            }
            uVar7 = FUN_0000ce1c(param_1,param_2);
            if ((char)uVar7 != '\0') {
              bVar8 = 3;
              goto LAB_0000dc2e;
            }
LAB_0000dc52:
            if (cVar9 != '\0') goto LAB_0000dc54;
            local_70 = (longlong *)&DAT_00013560;
            uVar5 = FUN_0000d8bc((short *)param_1,param_2,param_3,*param_4,*param_5,
                                 in_stack_ffffffffffffff60,&local_68);
            if ((longlong)uVar5 < 0) goto LAB_0000ddcc;
            if (bVar8 < 2) {
LAB_0000ddad:
              uVar5 = FUN_0000d5fc(local_60,lVar10,local_70,local_68);
LAB_0000ddc7:
              if ((longlong)uVar5 < 0) goto LAB_0000ddcc;
            }
            else if (bVar8 == 2) {
LAB_0000dd79:
              uVar5 = FUN_0000d748((ushort *)&DAT_00012128,&DAT_00011020,local_60,lVar10);
              if ((longlong)uVar5 < 0) goto LAB_0000ddad;
            }
            else {
              if (bVar8 != 3) {
                if (bVar8 == 4) {
                  uVar5 = (**(code **)(DAT_00013440 + 8))
                                    (DAT_00013440,local_60,lVar10,0,0,&local_70,&local_68,9,2);
                  if (((longlong)uVar5 < 0) ||
                     ((param_6 != (longlong *)0x0 &&
                      (lVar10 = FUN_0000a918((longlong *)(param_8 + 0x10),local_70,0x20),
                      lVar10 != 0)))) goto LAB_0000ddcc;
                  FUN_00010040((undefined8 *)(param_8 + 0x10),local_70,0x20);
                }
                goto LAB_0000ddc7;
              }
              uVar5 = FUN_0000d748((ushort *)&DAT_000126e8,(longlong *)&DAT_00011090,local_60,lVar10
                                  );
              if ((longlong)uVar5 < 0) goto LAB_0000dd79;
            }
          }
          *param_5 = *param_5 - local_48;
          *param_4 = (longlong)((longlong)local_40 + local_48);
          if (*param_5 == 0) {
            return uVar5;
          }
          if ((byte)(bVar8 - 3) < 2) {
            return uVar5;
          }
          uVar5 = FUN_0000e7e4((longlong *)((longlong)local_40 + local_48),*param_5,
                               (longlong *)&local_40);
          if ((longlong)uVar5 < 0) {
            return uVar5;
          }
          if ((bVar8 != 0) || (local_40 <= IMAGE_DOS_HEADER_00000000.e_magic + 1)) {
            if ((param_3 & 0x40) == 0) {
              return uVar5;
            }
            if (bVar8 != 0) {
              uVar5 = FUN_0000d334((longlong *)*param_4,param_5,param_6,param_7);
              if (-1 < (longlong)uVar5) {
                return uVar5;
              }
              if (local_58 == *(longlong *)(param_8 + 8)) {
                return uVar5;
              }
              *param_5 = 0;
              return 0;
            }
          }
          goto LAB_0000da6e;
        }
      }
    }
LAB_0000ddcc:
    uVar5 = 0x800000000000001a;
  }
  return uVar5;
}


/* 0xe051 */

undefined8
FUN_0000df60(longlong *param_1,longlong *param_2,uint param_3,longlong *param_4,ulonglong *param_5,
            longlong param_6,ulonglong *param_7,longlong param_8)

{
  ulonglong *puVar1;
  char cVar2;
  longlong lVar3;
  undefined8 uVar4;
  longlong lVar5;
  undefined8 local_res20;
  
  puVar1 = (ulonglong *)*param_4;
  if ((param_3 & 0x10) == 0) {
    return 0x8000000000000002;
  }
  if (*param_5 < 0x28) {
    return 0x800000000000001a;
  }
  if (*(short *)((longlong)puVar1 + 0xe) != 0xef1) {
    return 0x800000000000001a;
  }
  lVar3 = FUN_0000a918((longlong *)(puVar1 + 2),(longlong *)&DAT_000111b0,0x10);
  if (lVar3 != 0) {
    return 0x800000000000001a;
  }
  if (*param_5 < 0x230) {
    return 0x800000000000001a;
  }
  cVar2 = FUN_0000cd7c(param_1,param_2);
  if (cVar2 != '\0') {
    return 0x8000000000000002;
  }
  cVar2 = FUN_0000cdcc(param_1,param_2);
  if (cVar2 != '\0') {
    return 0x8000000000000002;
  }
  lVar3 = FUN_0000a918(param_2,(longlong *)&DAT_00011090,0x10);
  if (lVar3 == 0) {
    return 0x8000000000000002;
  }
  uVar4 = FUN_0000ce1c(param_1,param_2);
  lVar3 = param_8;
  if ((char)uVar4 != '\0') {
    return 0x8000000000000002;
  }
  if ((param_3 & 0x40) == 0) {
    if ((param_6 != 0) && (*puVar1 <= *(ulonglong *)(param_8 + 8))) {
      return 0x800000000000001a;
    }
  }
  else if ((param_6 != 0) && (*puVar1 < *(ulonglong *)(param_8 + 8))) goto LAB_0000e087;
  *(ulonglong *)(param_8 + 8) = *puVar1;
LAB_0000e087:
  param_7 = puVar1 + 6;
  lVar5 = FUN_0000de7c(*param_4,*param_5,param_7);
  if (-1 < lVar5) {
    local_res20 = 0x100;
    uVar4 = (**(code **)(DAT_00013440 + 0x10))
                      (DAT_00013440,&DAT_00011060,1,&param_7,&local_res20,&DAT_000135a0);
    if ((param_6 == 0) ||
       (lVar5 = FUN_0000a918((longlong *)(lVar3 + 0x10),(longlong *)&DAT_000135a0,0x20), lVar5 == 0)
       ) {
      FUN_00010040((undefined8 *)(lVar3 + 0x10),(undefined8 *)&DAT_000135a0,0x20);
      *param_5 = *param_5 - 0x230;
      *param_4 = (longlong)(puVar1 + 0x46);
      return uVar4;
    }
  }
  return 0x800000000000001a;
}


/* 0xe82e */

ulonglong FUN_0000e7e4(longlong *param_1,ulonglong param_2,longlong *param_3)

{
  uint uVar1;
  ulonglong uVar2;
  longlong lVar3;
  undefined1 *puVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  longlong lVar7;
  longlong *plVar8;
  
  if ((param_2 < 0x30001) && (param_1 != (longlong *)0x0)) {
    lVar7 = 0;
    uVar2 = 0x800000000000001a;
    uVar1 = *(uint *)(param_1 + 2);
    while ((uVar5 = (ulonglong)uVar1, param_2 != 0 && (uVar5 <= param_2))) {
      uVar2 = 0;
      plVar8 = (longlong *)&DAT_00012050;
      do {
        lVar3 = FUN_0000a918(param_1,plVar8,0x10);
        if (lVar3 == 0) break;
        uVar2 = uVar2 + 1;
        plVar8 = plVar8 + 2;
      } while (uVar2 < 9);
      if ((((8 < uVar2) || (uVar1 < 0x2d)) || (0x30000 < uVar1)) ||
         ((*(int *)((longlong)param_1 + 0x14) != 0 ||
          (uVar2 = (ulonglong)*(uint *)(param_1 + 3), (uVar5 - 0x1c) % uVar2 != 0)))) {
        return 0x8000000000000002;
      }
      if ((*param_1 == DAT_000111d0) && (param_1[1] == DAT_000111d8)) {
        FUN_0000a5c4();
        puVar4 = FUN_0000f934((byte *)((longlong)param_1 + 0x2c),uVar2 - 0x10);
        uVar6 = ~-(ulonglong)(puVar4 != (undefined1 *)0x0) & 0x8000000000000002;
        FUN_0000a5c4();
        if ((longlong)uVar6 < 0) {
          return uVar6;
        }
      }
      lVar7 = lVar7 + 1;
      uVar6 = 0x1c;
      if (0x1c < uVar5) {
        do {
          uVar6 = uVar6 + uVar2;
        } while (uVar6 < uVar5);
      }
      param_1 = (longlong *)((longlong)param_1 + uVar5);
      uVar2 = 0;
      param_2 = param_2 - uVar5;
      uVar1 = *(uint *)(param_1 + 2);
    }
    if (param_3 != (longlong *)0x0) {
      *param_3 = lVar7;
    }
  }
  else {
    uVar2 = 0x800000000000001a;
  }
  return uVar2;
}


/* 0xe94e */

ulonglong FUN_0000e7e4(longlong *param_1,ulonglong param_2,longlong *param_3)

{
  uint uVar1;
  ulonglong uVar2;
  longlong lVar3;
  undefined1 *puVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  longlong lVar7;
  longlong *plVar8;
  
  if ((param_2 < 0x30001) && (param_1 != (longlong *)0x0)) {
    lVar7 = 0;
    uVar2 = 0x800000000000001a;
    uVar1 = *(uint *)(param_1 + 2);
    while ((uVar5 = (ulonglong)uVar1, param_2 != 0 && (uVar5 <= param_2))) {
      uVar2 = 0;
      plVar8 = (longlong *)&DAT_00012050;
      do {
        lVar3 = FUN_0000a918(param_1,plVar8,0x10);
        if (lVar3 == 0) break;
        uVar2 = uVar2 + 1;
        plVar8 = plVar8 + 2;
      } while (uVar2 < 9);
      if ((((8 < uVar2) || (uVar1 < 0x2d)) || (0x30000 < uVar1)) ||
         ((*(int *)((longlong)param_1 + 0x14) != 0 ||
          (uVar2 = (ulonglong)*(uint *)(param_1 + 3), (uVar5 - 0x1c) % uVar2 != 0)))) {
        return 0x8000000000000002;
      }
      if ((*param_1 == DAT_000111d0) && (param_1[1] == DAT_000111d8)) {
        FUN_0000a5c4();
        puVar4 = FUN_0000f934((byte *)((longlong)param_1 + 0x2c),uVar2 - 0x10);
        uVar6 = ~-(ulonglong)(puVar4 != (undefined1 *)0x0) & 0x8000000000000002;
        FUN_0000a5c4();
        if ((longlong)uVar6 < 0) {
          return uVar6;
        }
      }
      lVar7 = lVar7 + 1;
      uVar6 = 0x1c;
      if (0x1c < uVar5) {
        do {
          uVar6 = uVar6 + uVar2;
        } while (uVar6 < uVar5);
      }
      param_1 = (longlong *)((longlong)param_1 + uVar5);
      uVar2 = 0;
      param_2 = param_2 - uVar5;
      uVar1 = *(uint *)(param_1 + 2);
    }
    if (param_3 != (longlong *)0x0) {
      *param_3 = lVar7;
    }
  }
  else {
    uVar2 = 0x800000000000001a;
  }
  return uVar2;
}

