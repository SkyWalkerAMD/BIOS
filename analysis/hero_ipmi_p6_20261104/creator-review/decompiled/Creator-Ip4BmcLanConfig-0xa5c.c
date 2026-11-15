
longlong FUN_00000a5c(ulonglong param_1,byte param_2)

{
  longlong lVar1;
  longlong lVar2;
  byte bVar3;
  ulonglong local_res8;
  undefined1 local_res10 [8];
  byte local_res18 [8];
  
  lVar1 = DAT_00000f88;
  local_res18[1] = 0;
  local_res18[2] = 0;
  local_res18[0] = param_2 & 0xf;
  bVar3 = 0;
  local_res18[3] = 0;
  local_res8 = param_1;
  while( true ) {
    local_res10[0] = 3;
    lVar2 = (**(code **)(lVar1 + 8))(lVar1,0xc,0,2,local_res18,4,&local_res8,local_res10);
    if (lVar2 < 0) {
      return lVar2;
    }
    if ((local_res8 & 0x30000) == 0) break;
    (**(code **)(DAT_00000d08 + 0xf8))(1000);
    bVar3 = bVar3 + 1;
    if (9 < bVar3) {
      return -0x7fffffffffffffee;
    }
  }
  return 0;
}

