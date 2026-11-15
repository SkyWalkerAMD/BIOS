
/* WARNING: Type propagation algorithm not settling */

undefined8 FUN_00000420(undefined8 param_1)

{
  longlong lVar1;
  undefined8 uVar2;
  ulonglong uVar3;
  int iVar4;
  bool bVar5;
  undefined1 local_res18 [8];
  undefined1 local_res20 [8];
  char local_78 [8];
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  int local_40 [2];
  ulonglong local_38;
  longlong local_30;
  longlong local_28 [2];
  
  local_30 = 0;
  local_38 = 0;
  local_28[0] = 0;
  local_28[1] = 0;
  bVar5 = false;
  local_70 = 0x9b54b7c3;
  local_6c = 0x4e3f9be0;
  local_68 = 0xc25892bf;
  local_64 = 0xd19d54d7;
  local_res18[0] = 0;
  local_60 = 0xe4f75a82;
  local_5c = 0x49556316;
  local_58 = 0xdf677eb5;
  local_54 = 0x569efad3;
  local_res20[0] = 0;
  local_50 = 0xd9b90d4f;
  local_4c = 0x4b027f30;
  local_48 = 0xc61d7597;
  local_44 = 0x993c8484;
  lVar1 = (**(code **)(DAT_000013d8 + 0x138))(2,&DAT_000012d0,0,&local_38,local_28);
  if ((-1 < lVar1) && (uVar3 = 0, local_38 != 0)) {
    do {
      lVar1 = (**(code **)(DAT_000013d8 + 0x98))
                        (*(undefined8 *)(local_28[0] + uVar3 * 8),&DAT_000012d0,&local_30);
      if ((-1 < lVar1) &&
         ((lVar1 = (**(code **)(local_30 + 0x30))(local_30,2,0,1,local_40), -1 < lVar1 &&
          (local_40[0] == 0x24021a03)))) {
        bVar5 = true;
        local_res18[0] = 1;
        break;
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 < local_38);
  }
  (**(code **)(DAT_000013e0 + 0x58))(u_BmcPresentVar_00001310,&local_70,6,1,local_res18);
  if (bVar5) {
    iVar4 = 0xff;
    do {
      lVar1 = local_30;
      out(0x80,(char)iVar4);
      local_78[0] = '\0';
      (**(code **)(DAT_000013d8 + 0xf8))(1000000,0x80);
      (**(code **)(lVar1 + 0x30))(lVar1,0,8,1,local_78);
      bVar5 = local_78[0] == '\x01';
      iVar4 = iVar4 + -1;
      if (bVar5) break;
    } while (iVar4 != 0);
    uVar2 = 0;
    out(0x80,0);
    if (iVar4 != 0) {
      uVar2 = (**(code **)(DAT_000013d8 + 0x70))(param_1,0x80);
    }
    if (bVar5) {
      uVar2 = (**(code **)(DAT_000013d8 + 0x80))(local_28 + 1,&local_50,0,0);
    }
  }
  else {
    local_res20[0] = 0;
    uVar2 = (**(code **)(DAT_000013e0 + 0x58))(u_BmcFanCtrl_00001330,&local_60,6,1,local_res20);
  }
  return uVar2;
}

