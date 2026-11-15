
longlong FUN_00002824(wchar_t *param_1,undefined8 param_2)

{
  wchar_t wVar1;
  longlong lVar2;
  longlong lVar3;
  wchar_t *pwVar4;
  char *local_res8;
  ulonglong local_res18;
  char *local_res20;
  
  lVar3 = 0;
  local_res8 = (char *)0x0;
  pwVar4 = param_1;
  while( true ) {
    wVar1 = *pwVar4;
    while ((wVar1 != L'&' && (wVar1 != L'\0'))) {
      lVar3 = lVar3 + 1;
      wVar1 = param_1[lVar3];
    }
    if (param_1[lVar3] == L'\0') break;
    lVar3 = lVar3 + 1;
    pwVar4 = param_1 + lVar3;
    if ((pwVar4 == u_PATH__000417c8) ||
       (lVar2 = FUN_00001040(pwVar4,u_PATH__000417c8,10), lVar2 == 0)) {
      lVar3 = FUN_0000276c(pwVar4,&local_res8,&local_res18);
      if (-1 < lVar3) {
        if ((((local_res8 == (char *)0x0) || (local_res18 < 4)) ||
            (local_res18 < *(ushort *)(local_res8 + 2))) ||
           ((4 < (byte)(*local_res8 - 1U) && (*local_res8 != '\x7f')))) {
          lVar3 = -0x7ffffffffffffff2;
        }
        else {
          local_res20 = local_res8;
          lVar3 = (**(code **)(DAT_000483d8 + 0xb8))(&DAT_0002c298,&local_res20,param_2);
        }
        (**(code **)(DAT_000483d8 + 0x48))(local_res8);
      }
      return lVar3;
    }
  }
  return -0x7ffffffffffffff2;
}

