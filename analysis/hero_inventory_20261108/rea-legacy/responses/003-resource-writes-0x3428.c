
ulonglong FUN_00003428(undefined8 *param_1,short *param_2,longlong param_3)

{
  byte bVar1;
  ulonglong uVar2;
  byte *pbVar3;
  int local_res20 [2];
  char local_38 [16];
  ulonglong local_28;
  longlong local_20;
  
  pbVar3 = (byte *)0x0;
  local_20 = 0;
  local_res20[0] = 3;
  local_28 = 3;
  uVar2 = FUN_0001888c((longlong *)&local_28);
  if (-1 < (longlong)uVar2) {
    pbVar3 = FUN_0001784c(param_3,0,1,(longlong *)0x0);
    if (pbVar3 == (byte *)0x0) {
      uVar2 = 0x8000000000000009;
    }
    else {
      uVar2 = 0;
      bVar1 = *pbVar3;
      while (bVar1 != 0) {
        uVar2 = uVar2 + 1;
        bVar1 = pbVar3[uVar2];
      }
      FUN_00018950(&local_28,s_Content_Type_0001a400,s_application_json_charset_utf_8_00019b50);
      FUN_00015c2c(local_38,10,&DAT_0001a534,uVar2);
      FUN_00018950(&local_28,s_Content_Length_0001a538,local_38);
      FUN_00018950(&local_28,s_OData_Version_00019b80,&DAT_00019b78);
      uVar2 = FUN_00018a80(param_1,2,param_2,&local_28,(char *)pbVar3,(ulonglong *)0x0,
                           (longlong *)0x0,(ulonglong *)0x0,local_res20);
      if ((-1 < (longlong)uVar2) &&
         (((local_res20[0] - 3U & 0xfffffffa) != 0 || (local_res20[0] == 8)))) {
        uVar2 = 0x8000000000000018;
      }
    }
  }
  if (local_20 != 0) {
    FUN_000188d4(&local_28);
  }
  if (pbVar3 != (byte *)0x0) {
    (**(code **)(DAT_0001e070 + 0x48))(pbVar3);
  }
  return uVar2;
}

