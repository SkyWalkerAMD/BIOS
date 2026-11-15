longlong FUN_00027d00(longlong param_1,longlong *param_2,ulonglong *param_3)
{
  longlong lVar1;
  short *psVar2;
  ulonglong local_res20;
  short *local_38;
  undefined8 local_30;
  local_res20 = 0x32;
  lVar1 = (**(code **)(DAT_00180320 + 0x50))(DAT_00180320,*(undefined8 *)(param_1 + 0x70),&local_30)
  ;
  if (-1 < lVar1) {
    psVar2 = (short *)FUN_000014c8(0x32);
    local_38 = psVar2;
    lVar1 = FUN_00027bc0(psVar2,&local_res20,param_1,(short *)(param_1 + 0x10),local_30);
    if (lVar1 < 0) {
      if (lVar1 == -0x7ffffffffffffffb) {
        FUN_000013d0((longlong *)&local_38);
        psVar2 = (short *)FUN_000014c8(local_res20);
        if (psVar2 == (short *)0x0) {
          return -0x7ffffffffffffff7;
        }
        local_38 = psVar2;
        lVar1 = FUN_00027bc0(psVar2,&local_res20,param_1,(short *)(param_1 + 0x10),local_30);
      }
      if (lVar1 < 0) {
        FUN_000013d0((longlong *)&local_38);
        return lVar1;
      }
    }
    if (*param_2 != 0) {
      FUN_000013d0(param_2);
    }
    *param_3 = local_res20;
    *param_2 = (longlong)psVar2;
  }
  return lVar1;
}
