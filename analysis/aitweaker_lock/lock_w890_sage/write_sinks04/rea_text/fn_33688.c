
longlong FUN_00033688(undefined8 *param_1,longlong *param_2,ulonglong *param_3)

{
  longlong lVar1;
  short *psVar2;
  longlong lVar3;
  short *psVar4;
  ulonglong local_res20;
  undefined8 local_28 [2];
  
  local_res20 = 0x32;
  lVar3 = DAT_000afc38;
  lVar1 = (**(code **)(DAT_000afc38 + 0x50))(DAT_000afc38,param_1[0xe],local_28);
  if (lVar1 < 0) {
    return lVar1;
  }
  psVar2 = (short *)FUN_00059b50(lVar3,0x32);
  psVar4 = psVar2;
  lVar3 = FUN_00033548(psVar2,&local_res20,param_1,(short *)(param_1 + 2),local_28[0]);
  if (lVar3 < 0) {
    if (lVar3 == -0x7ffffffffffffffb) {
      if (psVar2 != (short *)0x0) {
        (**(code **)(DAT_000afbc8 + 0x48))();
        psVar4 = psVar2;
      }
      psVar2 = (short *)FUN_00059b50(psVar4,local_res20);
      if (psVar2 == (short *)0x0) {
        return -0x7ffffffffffffff7;
      }
      lVar3 = FUN_00033548(psVar2,&local_res20,param_1,(short *)(param_1 + 2),local_28[0]);
      if (-1 < lVar3) goto LAB_0003377c;
    }
    if (psVar2 != (short *)0x0) {
      (**(code **)(DAT_000afbc8 + 0x48))(psVar2);
    }
  }
  else {
LAB_0003377c:
    if (*param_2 != 0) {
      (**(code **)(DAT_000afbc8 + 0x48))();
    }
    *param_3 = local_res20;
    *param_2 = (longlong)psVar2;
  }
  return lVar3;
}

