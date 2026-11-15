
longlong FUN_0000372c(ulonglong param_1,longlong param_2,ulonglong param_3)

{
  uint uVar1;
  longlong lVar2;
  longlong lVar3;
  undefined4 uVar4;
  undefined8 *puVar5;
  ulonglong local_res8;
  undefined8 local_res20;
  ulonglong *local_88;
  undefined8 local_80;
  undefined *local_78;
  undefined8 local_70 [7];
  
  lVar3 = DAT_0000b2c0;
  local_res8 = param_1;
  if ((DAT_0000b600 == DAT_0000a048) && (DAT_0000b608 == DAT_0000a050)) {
    FUN_000011e0((undefined1 *)local_70,0x30,0);
    if (local_70 != DAT_0000b618) {
      FUN_00001180(local_70,DAT_0000b618,0x20);
    }
    puVar5 = local_70;
    uVar4 = 0x30;
  }
  else {
    if (DAT_0000b600 != DAT_0000a0f8) {
      return -0x7ffffffffffffffd;
    }
    puVar5 = DAT_0000b618;
    uVar4 = DAT_0000b610;
    if (DAT_0000b608 != DAT_0000a100) {
      return -0x7ffffffffffffffd;
    }
  }
  uVar1 = *(uint *)(lVar3 + 0x20);
  local_88 = &local_res8;
  local_res20 = 0;
  lVar2 = (**(code **)(DAT_0000b5f8 + 8))
                    (DAT_0000b5f8,lVar3 + 0x38,(ulonglong)uVar1 - 0x18,0,0,&local_88,&local_res20,6,
                     1);
  if (lVar2 < 0) {
    return lVar2;
  }
  if (2 < (byte)((char)local_res8 - 1U)) {
    return -0x7ffffffffffffffd;
  }
  local_80 = *(undefined8 *)(&DAT_0000a288 + (local_res8 & 0xff) * 0x30);
  lVar2 = FUN_000033dc(lVar3,param_2,param_3,local_res8 & 0xff);
  if (-1 < lVar2) {
    local_78 = &DAT_0000b530;
    lVar3 = (**(code **)(DAT_0000b5f8 + 8))
                      (DAT_0000b5f8,lVar3 + 0x38,(ulonglong)uVar1 - 0x18,puVar5,uVar4,&local_78,
                       &local_80,1,2);
    return lVar3;
  }
  return lVar2;
}

