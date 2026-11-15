
longlong FUN_00004a34(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  longlong lVar1;
  longlong lVar2;
  longlong lVar3;
  longlong *plVar4;
  ulonglong uVar5;
  undefined1 uVar6;
  char local_res20 [8];
  undefined1 local_38;
  undefined1 local_37 [7];
  longlong local_30;
  longlong local_28 [2];
  
  local_30 = 0;
  local_res20[0] = '\0';
  if ((short)param_4 != 0x1f42) {
    return -0x7ffffffffffffffd;
  }
  if (*(longlong *)(DAT_000153f8 + 8) != 1) {
    return 0;
  }
  lVar1 = (**(code **)(DAT_00015458 + 0x140))(&DAT_0000a380,0,&local_30);
  uVar6 = (undefined1)param_4;
  if (lVar1 < 0) {
    return lVar1;
  }
  plVar4 = local_28;
  lVar1 = (**(code **)(DAT_00015458 + 0x140))(&DAT_0000a370,0);
  if (lVar1 < 0) {
    lVar2 = FUN_000097d0(param_1,0x2a,(ulonglong)plVar4,uVar6);
    lVar3 = FUN_000097d0(param_1,0x2b,(ulonglong)plVar4,uVar6);
    if ((lVar2 != 0) && (lVar3 != 0)) {
      (**(code **)(local_30 + 0x20))(lVar3,lVar2,1,local_res20);
      (**(code **)(DAT_00015458 + 0x48))(lVar2);
      (**(code **)(DAT_00015458 + 0x48))(lVar3);
      return lVar1;
    }
  }
  lVar2 = FUN_000097d0(param_1,0x29,(ulonglong)plVar4,uVar6);
  lVar3 = FUN_000097d0(param_1,0x28,(ulonglong)plVar4,uVar6);
  if ((lVar2 != 0) && (lVar3 != 0)) {
    lVar1 = (**(code **)(local_30 + 0x20))(lVar3,lVar2,3,local_res20);
    (**(code **)(DAT_00015458 + 0x48))(lVar2);
    (**(code **)(DAT_00015458 + 0x48))(lVar3);
  }
  if (lVar1 < 0) {
    return 0;
  }
  if (local_res20[0] == '\x01') {
    return 0;
  }
  local_38 = 1;
  uVar6 = 3;
  uVar5 = 0;
  lVar1 = (**(code **)(local_28[0] + 8))(local_28[0],6,0,3,0,0,local_37,&local_38);
  if (lVar1 < 0) {
    lVar2 = FUN_000097d0(param_1,0x2c,uVar5,uVar6);
    lVar3 = FUN_000097d0(param_1,0x2b,uVar5,uVar6);
    if ((lVar2 != 0) && (lVar3 != 0)) {
      (**(code **)(local_30 + 0x20))(lVar3,lVar2,1,local_res20);
      (**(code **)(DAT_00015458 + 0x48))(lVar2);
      goto LAB_00004c20;
    }
  }
  lVar2 = FUN_000097d0(param_1,0x2d,uVar5,uVar6);
  lVar3 = FUN_000097d0(param_1,0x28,uVar5,uVar6);
  if (lVar2 == 0) {
    return lVar1;
  }
  if (lVar3 == 0) {
    return lVar1;
  }
  (**(code **)(local_30 + 0x20))(lVar3,lVar2,1,local_res20);
  (**(code **)(DAT_00015458 + 0x48))(lVar2);
LAB_00004c20:
  (**(code **)(DAT_00015458 + 0x48))(lVar3);
  return lVar1;
}

