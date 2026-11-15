
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void Candidate_SetupEnterNotify(undefined8 param_1,undefined8 param_2)

{
  char cVar1;
  char *pcVar2;
  ulonglong uVar3;
  longlong lVar4;
  undefined8 uVar5;
  longlong lVar6;
  ulonglong uVar7;
  ulonglong local_res20;
  longlong local_48 [3];
  undefined8 local_30;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  local_48[0] = 0;
  DAT_0004ef10 = &DAT_0004ef10;
  DAT_0004ef18 = &DAT_0004ef10;
  DAT_0004eef0 = &DAT_0004eef0;
  DAT_0004eef8 = &DAT_0004eef0;
  _DAT_0004ef00 = &DAT_0004ef00;
  _DAT_0004ef08 = &DAT_0004ef00;
  _DAT_0004eee0 = &DAT_0004eee0;
  _DAT_0004eee8 = &DAT_0004eee0;
  local_28 = 0xec87d643;
  local_24 = 0x4bb5eba4;
  local_20 = 0x3e3fe5a1;
  local_1c = 0xa90db236;
  pcVar2 = (char *)FUN_00001014(param_1,param_2,&local_res20);
  uVar7 = local_res20;
  if (pcVar2 != (char *)0x0) {
    uVar3 = FUN_0001aa34(pcVar2,local_res20);
    if (uVar3 == uVar7 - 1) {
      (**(code **)(DAT_00043310 + 0x140))(&DAT_000278d0,0,local_48 + 2);
      local_48[1] = 600;
      (**(code **)(DAT_00043310 + 0x40))(4,600,local_48);
      lVar4 = (**(code **)(DAT_00043290 + 0x48))();
      if ((lVar4 < 0) ||
         ((*(char *)(local_48[0] + 0x22e) != '\x01' && (*(char *)(local_48[2] + 8) != '\x01')))) {
        uVar5 = 0xc34;
        FUN_0001e9b0(&DAT_000277c0,0xc34,0,(undefined8 *)&DAT_00043448,&local_30);
      }
      else {
        uVar5 = 0;
        FUN_00000c34(0);
      }
      lVar4 = local_48[0];
      (**(code **)(DAT_00043310 + 0x48))();
      goto LAB_00001202;
    }
    (**(code **)(DAT_00043280 + 0x48))();
    pcVar2 = (char *)0x0;
  }
  uVar5 = 0;
  lVar4 = 0;
  FUN_00000c34(0);
LAB_00001202:
  lVar6 = 6;
  if (((pcVar2 != (char *)0x0) ||
      (pcVar2 = (char *)FUN_00001014(lVar4,uVar5,&local_res20), uVar7 = local_res20,
      pcVar2 != (char *)0x0)) && (uVar7 != 0)) {
    (**(code **)(DAT_00043290 + 0x58))(u_PlatformLangCodes_0003c8d8,&DAT_00027800,6,uVar7,pcVar2);
  }
  local_30 = 0;
  lVar4 = (**(code **)(DAT_00043290 + 0x48))(u_PlatformLang_0003c900,&DAT_00027800,0,&local_30,0);
  if (lVar4 != -0x7ffffffffffffffb) {
    lVar4 = 0;
    if ((pcVar2 == (char *)0x0) || (cVar1 = *pcVar2, cVar1 == '\0')) {
      (**(code **)(DAT_00043280 + 0x40))(4,6,&local_res20);
      (**(code **)(DAT_00043280 + 0x160))(local_res20,s_en_US_0003c88c,6);
    }
    else {
      while ((cVar1 != ';' && (cVar1 != '\0'))) {
        lVar4 = lVar4 + 1;
        cVar1 = pcVar2[lVar4];
      }
      lVar6 = lVar4 + 1;
      (**(code **)(DAT_00043280 + 0x40))(4,lVar6,&local_res20);
      (**(code **)(DAT_00043280 + 0x160))(local_res20,pcVar2,lVar4);
      *(undefined1 *)(local_res20 + lVar4) = 0;
    }
    (**(code **)(DAT_00043290 + 0x58))(u_PlatformLang_0003c900,&DAT_00027800,7,lVar6,local_res20);
    (**(code **)(DAT_00043280 + 0x48))(local_res20);
  }
  if (pcVar2 != (char *)0x0) {
    (**(code **)(DAT_00043280 + 0x48))(pcVar2);
  }
  return;
}

