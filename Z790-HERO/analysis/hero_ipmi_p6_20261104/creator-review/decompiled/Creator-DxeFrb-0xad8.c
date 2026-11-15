
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong FUN_00000ad8(undefined8 param_1,ulonglong param_2)

{
  ulonglong uVar1;
  longlong lVar2;
  undefined8 *puVar3;
  undefined8 **ppuVar4;
  undefined *puVar5;
  undefined8 uVar6;
  undefined8 local_res8;
  undefined8 local_res10;
  undefined8 *local_res18;
  undefined8 local_res20;
  undefined8 *puVar7;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined1 local_70 [8];
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  byte local_48 [40];
  
  local_68 = 0x47c7b221;
  local_res10 = param_2 & 0xffff000000000000;
  local_64 = 0x11d2c42a;
  puVar7 = (undefined8 *)&DAT_00001200;
  local_60 = 0xa000578e;
  local_5c = 0x3b7269c9;
  local_58 = 0x6302d008;
  local_54 = 0x4f307f9b;
  local_50 = 0xc960ac87;
  local_4c = 0x4edaf5fe;
  local_78 = 0;
  local_res18 = (undefined8 *)0x0;
  local_res8 = 0;
  local_88 = 0x267;
  lVar2 = (**(code **)(DAT_000011d8 + 0x48))(u_ServerSetup_00001170,&DAT_00001140,0,&local_88);
  uVar1 = local_res10;
  if (lVar2 < 0) {
    local_res10 = local_res10 & 0xfffffffffffff8ff;
    local_res10._0_6_ = CONCAT24(0xe10,(undefined4)local_res10);
    DAT_00001217 = '\x01';
    _DAT_0000121a = 0xa00;
    DAT_0000121c = 1;
  }
  else {
    local_res10._1_1_ = local_res10._1_1_ ^ (local_res10._1_1_ ^ DAT_00001219) & 7;
    uVar6 = local_res10;
    local_res10._6_2_ = SUB82(uVar1,6);
    local_res10._0_4_ = (undefined4)uVar6;
    local_res10._0_6_ = CONCAT24((ushort)DAT_00001218 * 600,(undefined4)local_res10);
    if ((DAT_00001217 == '\0') && (DAT_0000121a == '\0')) {
      return -0x7ffffffffffffffd;
    }
  }
  uVar6 = 0;
  puVar5 = &DAT_00001130;
  lVar2 = (**(code **)(DAT_000011d0 + 0x140))(&DAT_00001130,0,&DAT_00001468);
  if (lVar2 < 0) {
    puVar7 = &local_res8;
    lVar2 = (**(code **)(DAT_000011d0 + 0x50))(0x200,8,0xa80,0);
    if (lVar2 < 0) {
      return lVar2;
    }
    puVar5 = &DAT_00001130;
    uVar6 = local_res8;
    lVar2 = (**(code **)(DAT_000011d0 + 0xa8))(&DAT_00001130,local_res8,local_70);
    if (lVar2 < 0) {
      return lVar2;
    }
  }
  else {
    DAT_000011c0 = 1;
  }
  puVar3 = (undefined8 *)FUN_00000fd8(puVar5,uVar6);
  ppuVar4 = (undefined8 **)0x0;
  if (puVar3 != (undefined8 *)0x0) {
    ppuVar4 = (undefined8 **)FUN_00000260(puVar3,0x30);
  }
  DAT_000011f0 = ppuVar4;
  if (ppuVar4 == (undefined8 **)0x0) {
    lVar2 = -0x7ffffffffffffff7;
  }
  else {
    *ppuVar4 = (undefined8 *)FUN_000002e8;
    ppuVar4[1] = (undefined8 *)FUN_00000414;
    ppuVar4[2] = (undefined8 *)&LAB_0000046c;
    ppuVar4[3] = (undefined8 *)&LAB_000004ac;
    ppuVar4[4] = (undefined8 *)FUN_000004d4;
    ppuVar4[5] = (undefined8 *)FUN_00000708;
    local_80 = 0;
    lVar2 = (**(code **)(DAT_000011d0 + 0x80))(&local_80,&DAT_000010f0,0);
    if (lVar2 < 0) {
      (**(code **)(DAT_000011d0 + 0x48))(DAT_000011f0);
    }
    else {
      if (DAT_00001217 != '\0') {
        lVar2 = FUN_000002e8(DAT_000011f0,1,local_48);
        if ((((-1 < lVar2) && (local_48[0] == 0)) || (lVar2 == -0x7fffffffffffffed)) &&
           (lVar2 = FUN_00000eec((byte *)&local_res10), lVar2 < 0)) {
          return lVar2;
        }
        lVar2 = (**(code **)(DAT_000011d0 + 0x140))(&DAT_00001120,0,&local_res18);
        if (-1 < lVar2) {
          (*(code *)*local_res18)(0xa3c,0x1f);
        }
        FUN_00001010(&DAT_000010b0,8,0x994,ppuVar4,puVar7);
        FUN_00001010(&DAT_00001090,0x10,0x9e4,ppuVar4,puVar7);
        FUN_00001010(&DAT_00001100,0x10,0x9f8,ppuVar4,puVar7);
        FUN_00001010(&DAT_00001110,0x10,0x9e4,ppuVar4,puVar7);
        FUN_00001010(&DAT_00001160,0x10,0x9f8,ppuVar4,puVar7);
      }
      if (DAT_0000121a != '\0') {
        FUN_00001010(&local_68,0x10,0xa0c,ppuVar4,puVar7);
        FUN_00001010(&local_58,0x10,0xa0c,ppuVar4,puVar7);
        FUN_00001010(&DAT_000010e0,0x10,0xa20,ppuVar4,puVar7);
      }
      FUN_00001010(&DAT_00001080,8,0x944,ppuVar4,puVar7);
      puVar7 = &local_res20;
      ppuVar4 = (undefined8 **)0x0;
      (**(code **)(DAT_000011d0 + 0x50))(0x200,8,0x8b8);
      (**(code **)(DAT_000011d0 + 0xa8))(&DAT_000010d0,local_res20,&local_78);
      (**(code **)(DAT_000011d0 + 0x68))(local_res20);
      FUN_00001010(&DAT_000010a0,8,0x910,ppuVar4,puVar7);
      lVar2 = 0;
    }
  }
  return lVar2;
}

