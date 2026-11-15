
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong SelTimeSynchronize_callback_callee(void)

{
  undefined1 uVar1;
  bool bVar2;
  longlong lVar3;
  longlong lVar4;
  longlong *plVar5;
  undefined8 uVar6;
  longlong lVar7;
  undefined *puVar8;
  ulonglong uVar9;
  int iVar10;
  longlong lVar11;
  uint uVar12;
  ulonglong uVar13;
  int iVar14;
  undefined1 uVar15;
  undefined1 local_res8 [8];
  undefined1 local_res10 [8];
  char local_res18;
  short local_res19 [3];
  char local_res20 [8];
  ushort local_338;
  byte bStack_336;
  byte bStack_335;
  byte bStack_334;
  byte bStack_333;
  byte bStack_332;
  undefined1 uStack_331;
  undefined4 uStack_330;
  undefined4 local_32c;
  uint local_328;
  uint local_324;
  undefined1 local_320 [8];
  undefined8 local_318;
  undefined1 local_310;
  undefined1 local_30f [7];
  longlong local_308 [4];
  undefined8 local_2e8;
  undefined8 uStack_2e0;
  undefined8 local_2d8;
  undefined8 uStack_2d0;
  undefined8 local_2c8;
  undefined8 uStack_2c0;
  undefined8 local_2b8;
  undefined8 uStack_2b0;
  undefined1 local_2a8 [31];
  char local_289;
  
  lVar11 = 0;
  iVar10 = 0;
  local_338 = 0x7dc;
  bStack_336 = 3;
  bStack_335 = 6;
  bStack_334 = 0;
  bStack_333 = 0;
  bStack_332 = 0;
  uStack_331 = 0;
  uStack_330 = 0;
  local_32c = 0;
  local_res8[0] = 3;
  lVar3 = (**(code **)(DAT_00005648 + 0x18))
                    (DAT_00005648 + 0x10,CONCAT71((int7)((ulonglong)&local_res18 >> 8),10),0,0x5c,0,
                     0,&local_res18,local_res8);
  if ((lVar3 < 0) || (local_res18 != '\0')) {
    local_res19[0] = 0x7ff;
  }
  local_res8[0] = 5;
  lVar3 = (**(code **)(DAT_00005648 + 0x18))
                    (DAT_00005648 + 0x10,CONCAT71((int7)((ulonglong)&local_310 >> 8),10),0,0x48,0,0,
                     &local_310,local_res8);
  if (lVar3 < 0) {
    return lVar3;
  }
  FUN_00001000((undefined8 *)&local_328,(undefined8 *)local_30f,4);
  lVar3 = (**(code **)(DAT_00005680 + 0x18))(&local_338,0);
  if (lVar3 < 0) {
    return lVar3;
  }
  uVar13 = 0x7b2;
  uVar9 = (ulonglong)((ushort)(local_338 - 0x7b2) + 1 & 0xffff);
  lVar7 = lVar11;
  do {
    uVar15 = 1;
    bVar2 = false;
    if (((uVar13 & 3) == 0) &&
       (((int)uVar13 != (int)(uVar13 / 100) * 100 || ((int)uVar13 == (int)(uVar13 / 400) * 400)))) {
      bVar2 = true;
    }
    uVar13 = (ulonglong)(ushort)((short)uVar13 + 1);
    lVar4 = lVar7 + 1;
    if (!bVar2) {
      lVar4 = lVar7;
    }
    iVar14 = (int)lVar4;
    uVar9 = uVar9 - 1;
    lVar7 = lVar4;
  } while (uVar9 != 0);
  if (((local_338 & 3) == 0) &&
     (((uVar12 = (uint)local_338, uVar12 != (local_338 / 100) * 100 ||
       (uVar12 == (uVar12 / 400) * 400)) && (bStack_336 < 3)))) {
    iVar14 = iVar14 + -1;
  }
  local_308[0] = _DAT_000055e0;
  local_308[1] = uRam00000000000055e8;
  local_308[2] = _DAT_000055f0;
  local_308[3] = uRam00000000000055f8;
  local_2e8 = _DAT_000055f0;
  uStack_2e0 = uRam00000000000055f8;
  uVar9 = ((ulonglong)
           CONCAT16(bStack_332,
                    CONCAT15(bStack_333,
                             CONCAT14(bStack_334,CONCAT13(bStack_335,CONCAT12(bStack_336,local_338))
                                     ))) & 0xff0000) >> 0x10;
  local_2d8 = _DAT_00005610;
  uStack_2d0 = uRam0000000000005618;
  local_2c8 = _DAT_00005600;
  uStack_2c0 = uRam0000000000005608;
  local_2b8 = _DAT_00005600;
  uStack_2b0 = uRam0000000000005608;
  if (1 < uVar9) {
    plVar5 = local_308;
    lVar7 = uVar9 - 1;
    do {
      lVar11 = lVar11 + *plVar5;
      iVar10 = (int)lVar11;
      plVar5 = plVar5 + 1;
      lVar7 = lVar7 + -1;
    } while (lVar7 != 0);
  }
  local_324 = (bStack_332 - 0x15180) +
              (((uint)bStack_334 +
               ((uint)bStack_335 + (uint)(ushort)(local_338 - 0x7b2) * 0x16d + iVar14 + iVar10) *
               0x18) * 0x3c + (uint)bStack_333) * 0x3c;
  if ((local_324 - 2 <= local_328) && (local_328 <= local_324 + 2)) {
    return lVar3;
  }
  uVar6 = SelOverflowQuery_observed_calls(DAT_00005648 + 0x10,(ulonglong)local_324);
  if ((char)uVar6 == '\x01') {
    local_318 = 0x267;
    puVar8 = &DAT_000050a0;
    (**(code **)(DAT_00005680 + 0x48))
              (u_ServerSetup_00005130,&DAT_000050a0,local_320,&local_318,local_2a8);
    uVar1 = uVar15;
    if (local_289 != '\x01') {
      if (local_289 != '\x02') goto LAB_0000168b;
      uVar1 = 2;
    }
    SelSpacePolicy_observed_calls
              (DAT_00005648 + 0x10,CONCAT71((int7)((ulonglong)puVar8 >> 8),uVar1));
  }
LAB_0000168b:
  local_res8[0] = 3;
  lVar3 = (**(code **)(DAT_00005648 + 0x18))
                    (DAT_00005648 + 0x10,CONCAT71((int7)((ulonglong)local_res20 >> 8),10),0,0x44,
                     &DAT_00005110,0x10,local_res20,local_res8);
  if (lVar3 < 0) {
    return lVar3;
  }
  if (local_res20[0] != '\0') {
    return lVar3;
  }
  local_res8[0] = 1;
  uVar6 = CONCAT71((int7)((ulonglong)&local_324 >> 8),10);
  lVar3 = (**(code **)(DAT_00005648 + 0x18))
                    (DAT_00005648 + 0x10,uVar6,0,0x49,&local_324,4,local_res10,local_res8);
  if (lVar3 < 0) {
    return lVar3;
  }
  uVar6 = SelOverflowQuery_observed_calls(DAT_00005648 + 0x10,uVar6);
  if ((char)uVar6 == '\x01') {
    local_318 = 0x267;
    puVar8 = &DAT_000050a0;
    (**(code **)(DAT_00005680 + 0x48))
              (u_ServerSetup_00005130,&DAT_000050a0,local_320,&local_318,local_2a8);
    if (local_289 != '\x01') {
      if (local_289 != '\x02') goto LAB_0000179c;
      uVar15 = 2;
    }
    SelSpacePolicy_observed_calls
              (DAT_00005648 + 0x10,CONCAT71((int7)((ulonglong)puVar8 >> 8),uVar15));
  }
LAB_0000179c:
  DAT_0000511e = DAT_0000511e | 0x80;
  local_res8[0] = 3;
  lVar3 = (**(code **)(DAT_00005648 + 0x18))
                    (DAT_00005648 + 0x10,CONCAT71((int7)((ulonglong)local_res20 >> 8),10),0,0x44,
                     &DAT_00005110,0x10,local_res20,local_res8);
  if (((-1 < lVar3) && (local_res20[0] == '\0')) && (local_res19[0] != 0x7ff)) {
    local_res8[0] = 1;
    lVar3 = (**(code **)(DAT_00005648 + 0x18))
                      (DAT_00005648 + 0x10,10,0,0x5d,local_res19,2,local_res10,local_res8);
  }
  return lVar3;
}

