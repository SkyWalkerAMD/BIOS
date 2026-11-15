
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong FUN_000038d4(longlong param_1,longlong param_2,ulonglong param_3,longlong param_4)

{
  uint *puVar1;
  longlong lVar2;
  uint uVar3;
  longlong lVar4;
  ulonglong uVar5;
  int iVar6;
  longlong local_res8;
  uint *local_res20;
  undefined4 uVar7;
  undefined4 local_78;
  undefined4 uStack_74;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  undefined4 local_68;
  uint *local_60;
  undefined8 local_58;
  undefined8 uStack_50;
  undefined4 local_48;
  undefined *local_40;
  
  lVar2 = DAT_0000b2c0;
  puVar1 = (uint *)(DAT_0000b2c0 + 0x48);
  local_58 = _DAT_0000a020;
  uStack_50 = uRam000000000000a028;
  local_40 = &DAT_0000b530;
  local_48 = 0x20;
  local_78 = _DAT_0000a460;
  uStack_74 = uRam000000000000a464;
  uStack_70 = uRam000000000000a468;
  uStack_6c = uRam000000000000a46c;
  iVar6 = (*(uint *)(DAT_0000b2c0 + 0x14) & 1) + 1;
  local_68 = 0x100;
  local_res8 = param_1;
  local_60 = puVar1;
  lVar4 = (*(code *)DAT_0000b5f8[4])(DAT_0000b5f8,&DAT_0000a128,&local_78);
  if (lVar4 < 0) {
    uVar5 = lVar2 + 0x248;
    while( true ) {
      if ((lVar2 + 0x20 + (ulonglong)*(uint *)(lVar2 + 0x20) <= uVar5) ||
         (local_60 = (uint *)(uVar5 + 0x10), *(char *)local_60 == '\0')) goto LAB_00003a40;
      lVar4 = (*(code *)DAT_0000b5f8[4])(DAT_0000b5f8,&DAT_0000a128,&local_78);
      if (-1 < lVar4) break;
      uVar5 = uVar5 + 0x210;
    }
    uVar3 = *(uint *)(lVar2 + 0x14) & 4;
    local_res20 = (uint *)(lVar2 + 0x20);
    if (uVar3 != 0) {
      local_res20 = puVar1;
    }
    local_res8 = (-(ulonglong)(uVar3 != 0) & 0xfffffffffffffed8) + 0x228;
    uVar7 = 0;
    lVar4 = (*(code *)DAT_0000b5f8[2])
                      (DAT_0000b5f8,&DAT_0000a020,1,&local_res20,&local_res8,&DAT_0000b530);
    if (-1 < lVar4) {
      param_4 = uVar5 + 0x110;
      lVar4 = (*(code *)*DAT_0000b5f8)
                        (DAT_0000b5f8,&local_78,&local_58,param_4,0x100,CONCAT44(uVar7,iVar6));
      if (-1 < lVar4) goto LAB_00003a4c;
    }
LAB_00003a40:
    lVar4 = -0x7fffffffffffffe6;
  }
  else {
LAB_00003a4c:
    lVar4 = FUN_000033dc(lVar2,param_2,param_3,CONCAT71((int7)((ulonglong)param_4 >> 8),1));
    if (-1 < lVar4) {
      local_60 = puVar1;
      lVar4 = (*(code *)*DAT_0000b5f8)(DAT_0000b5f8,&local_78,&local_58,lVar2 + 0x148,0x100,iVar6);
    }
  }
  return lVar4;
}

