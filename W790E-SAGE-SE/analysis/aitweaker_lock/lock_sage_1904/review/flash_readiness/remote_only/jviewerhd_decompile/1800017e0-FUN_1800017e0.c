
ulonglong FUN_1800017e0(longlong param_1,char *param_2,undefined8 param_3,undefined8 param_4)

{
  ulonglong uVar1;
  
  uVar1 = FUN_180003700(param_2,(LPCSTR)(param_1 + 0x18),param_3,param_4);
  FUN_180003890((int)param_3,param_1 + 0x18);
  return uVar1 & 0xffffffff;
}

