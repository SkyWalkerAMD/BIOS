
void Candidate_ChromeConstruction(void)

{
  wchar_t *pwVar1;
  wchar_t *pwVar2;
  longlong *plVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  ulonglong uVar6;
  uint uVar7;
  longlong local_res8;
  
  uVar6 = 0;
  local_res8 = 0;
  pwVar2 = u_BootFlow_000a8338;
  pwVar1 = (wchar_t *)FUN_00007758(u_BootFlow_000a8338,&DAT_00094eb0,(undefined4 *)0x0,&local_res8);
  uVar7 = 0;
  if ((pwVar1 != (wchar_t *)0x0) && (uVar7 = 0, local_res8 == 4)) {
    uVar7 = *(uint *)pwVar1;
    (**(code **)(DAT_000afbc8 + 0x48))();
    pwVar2 = pwVar1;
  }
  if ((((DAT_00094d30 == 0) && (DAT_00094d38 == 0)) || (DAT_000ba910 != (undefined8 *)0x0)) ||
     (DAT_000ba910 = FUN_00059b50(pwVar2,0x180), DAT_000ba910 == (undefined8 *)0x0)) {
    return;
  }
  plVar3 = &DAT_00094d30;
  uVar5 = uVar6;
  while (((*plVar3 != 0x49d3a6659204ecbe || (plVar3[1] != -0x10dc1d66edf7217a)) ||
         (*(ushort *)(plVar3 + 2) != uVar7))) {
    uVar5 = uVar5 + 1;
    plVar3 = plVar3 + 4;
    if (0xb < uVar5) {
LAB_0004f759:
      uVar4 = (ulonglong)DAT_000b0070;
LAB_0004f7f2:
      if (DAT_000b0073 != '\0') {
        return;
      }
      if (uVar7 == 0) {
        return;
      }
      plVar3 = &DAT_00094d30;
      while (((*plVar3 != 0x49d3a6659204ecbe || (plVar3[1] != -0x10dc1d66edf7217a)) ||
             ((short)plVar3[2] != 0))) {
        uVar6 = uVar6 + 1;
        plVar3 = plVar3 + 4;
        if (0xb < uVar6) {
          return;
        }
      }
      plVar3 = &DAT_00094d30 + (uVar6 + 1) * 4;
      while( true ) {
        if ((*plVar3 == 0x49d3a6659204ecbe) && (plVar3[1] == -0x10dc1d66edf7217a)) {
          return;
        }
        if ((*plVar3 == 0) && (plVar3[1] == 0)) break;
        (**(code **)(DAT_000afbc8 + 0x160))(DAT_000ba910 + uVar4 * 4,plVar3,0x20);
        DAT_000b0070 = DAT_000b0070 + 1;
        uVar4 = (ulonglong)DAT_000b0070;
        plVar3 = plVar3 + 4;
        DAT_000b0073 = '\x01';
      }
      return;
    }
  }
  uVar5 = uVar5 + 1;
  if (uVar5 < 0xc) {
    plVar3 = &DAT_00094d30 + uVar5 * 4;
    while (((uVar4 = (ulonglong)DAT_000b0070, *plVar3 != 0x49d3a6659204ecbe ||
            (plVar3[1] != -0x10dc1d66edf7217a)) && ((*plVar3 != 0 || (plVar3[1] != 0))))) {
      (**(code **)(DAT_000afbc8 + 0x160))(DAT_000ba910 + uVar4 * 4,plVar3,0x20);
      DAT_000b0070 = DAT_000b0070 + 1;
      DAT_000b0073 = '\x01';
      uVar5 = uVar5 + 1;
      plVar3 = plVar3 + 4;
      if (0xb < uVar5) {
        DAT_000b0073 = 1;
        return;
      }
    }
    goto LAB_0004f7f2;
  }
  goto LAB_0004f759;
}

