
ulonglong FUN_00009700(longlong param_1,longlong param_2,ulonglong param_3)

{
  longlong lVar1;
  longlong lVar2;
  ulonglong uVar3;
  longlong lVar4;
  ulonglong local_res10;
  
  if (param_2 == 0) {
    return 0;
  }
  if (param_3 < 0x1001) {
    local_res10 = 0xffffffff;
    lVar1 = (**(code **)(param_1 + 0x58))(param_1,1,DAT_0000ec40,param_2,&local_res10,0);
    if (-1 < lVar1) {
      return local_res10;
    }
    lVar1 = (**(code **)(param_1 + 0x58))(param_1,0,DAT_0000ec40,param_2,&local_res10,0);
    uVar3 = local_res10;
  }
  else {
    lVar4 = (param_3 >> 0xc) + (ulonglong)((param_3 & 0xfff) != 0) + param_2;
    local_res10 = 0xffffffff;
    lVar1 = (**(code **)(param_1 + 0x58))(param_1,1,DAT_0000ec40,lVar4,&local_res10,0);
    if ((lVar1 < 0) &&
       (lVar1 = (**(code **)(param_1 + 0x58))(param_1,0,DAT_0000ec40,lVar4,&local_res10,0),
       lVar1 < 0)) {
      return 0;
    }
    uVar3 = local_res10 + (param_3 - 1) & ~(param_3 - 1);
    lVar1 = (ulonglong)((uVar3 - local_res10 & 0xfff) != 0) + (uVar3 - local_res10 >> 0xc);
    if ((lVar1 != 0) && (lVar2 = (**(code **)(param_1 + 0x60))(param_1,lVar1), lVar2 < 0)) {
      return 0;
    }
    local_res10 = param_2 * 0x1000 + uVar3;
    lVar1 = (lVar4 - lVar1) - param_2;
    if (lVar1 == 0) {
      return uVar3;
    }
    lVar1 = (**(code **)(param_1 + 0x60))(param_1,lVar1);
  }
  if (lVar1 < 0) {
    return 0;
  }
  return uVar3;
}

