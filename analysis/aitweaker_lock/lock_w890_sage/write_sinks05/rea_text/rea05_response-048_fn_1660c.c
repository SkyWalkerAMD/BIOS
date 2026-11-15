
void WS05_1660c(void)

{
  longlong lVar1;
  undefined8 local_res18;
  longlong local_res20;
  undefined8 local_28 [2];
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  local_res18 = 0x59ab;
  lVar1 = (**(code **)(DAT_00048460 + 0x140))(&DAT_0002c5e8,0,&local_res20);
  if (-1 < lVar1) {
    local_18 = 0xa3a3b874;
    local_14 = 0x41827636;
    local_10 = 0x2cf51eba;
    local_c = 0xe3944458;
    lVar1 = (**(code **)(local_res20 + 0x20))
                      (u_VARSTORE_OCMR_SETTINGS_NAME_00041870,&local_18,local_28,&local_res18);
    if (-1 < lVar1) {
      FUN_000164e0(local_28[0]);
    }
  }
  return;
}

