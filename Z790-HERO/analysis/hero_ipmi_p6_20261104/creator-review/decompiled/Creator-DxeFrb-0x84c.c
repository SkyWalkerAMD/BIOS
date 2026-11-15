
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

longlong FUN_0000084c(void)

{
  longlong lVar1;
  ulonglong local_res8 [4];
  
  lVar1 = 0;
  if (DAT_0000121a != '\0') {
    local_res8[0] = (ulonglong)DAT_0000121b * 60000000;
    FUN_00000414(DAT_000011f0,3,local_res8);
    DAT_00001496 = DAT_0000121c;
    _DAT_00001494 = 0;
    lVar1 = FUN_000004d4(DAT_000011f0,3,'\0');
  }
  return lVar1;
}

