
longlong FUN_00003008(longlong param_1,longlong param_2,ulonglong param_3)

{
  uint uVar1;
  longlong lVar2;
  undefined8 *puVar3;
  undefined4 uVar4;
  undefined *puVar5;
  char local_res20 [8];
  undefined8 local_78;
  undefined8 local_70;
  char *local_68;
  undefined *local_60;
  undefined8 local_58 [6];
  
  lVar2 = FUN_00004650((longlong *)&DAT_00005a60,(longlong *)&DAT_00005040,0x10);
  if (lVar2 == 0) {
    FUN_0000489e((undefined4 *)local_58,0x30,0);
    FUN_000048f0(local_58,DAT_00005a78,0x20);
    puVar3 = local_58;
    uVar4 = 0x30;
LAB_000030ab:
    uVar1 = *(uint *)(param_1 + 0x20);
    local_70 = 0;
    local_60 = &DAT_00005a00;
    local_68 = local_res20;
    lVar2 = (**(code **)(DAT_00005a40 + 8))
                      (DAT_00005a40,param_1 + 0x38,(ulonglong)uVar1 - 0x18,0,0,&local_68,&local_70,6
                       ,1);
    if (lVar2 < 0) {
      return lVar2;
    }
    if (local_res20[0] == '\x01') {
      puVar5 = &DAT_00005030;
      local_78 = 0x20;
    }
    else if (local_res20[0] == '\x02') {
      puVar5 = &DAT_00005100;
      local_78 = 0x30;
    }
    else {
      if (local_res20[0] != '\x03') goto LAB_000031a6;
      puVar5 = &DAT_00005130;
      local_78 = 0x40;
    }
    lVar2 = FUN_00002e74(param_1,param_2,param_3,puVar5);
    if (-1 < lVar2) {
      lVar2 = (**(code **)(DAT_00005a40 + 8))
                        (DAT_00005a40,param_1 + 0x38,(ulonglong)uVar1 - 0x18,puVar3,uVar4,&local_60,
                         &local_78,1,2);
    }
  }
  else {
    lVar2 = FUN_00004650((longlong *)&DAT_00005a60,(longlong *)&DAT_000050d0,0x10);
    puVar3 = DAT_00005a78;
    uVar4 = DAT_00005a70;
    if (lVar2 == 0) goto LAB_000030ab;
LAB_000031a6:
    lVar2 = -0x7ffffffffffffffd;
  }
  return lVar2;
}

