
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_00001354(void)

{
  longlong lVar1;
  int *local_res18;
  undefined8 local_res20;
  longlong local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined4 local_20;
  undefined8 local_18;
  undefined4 uStack_10;
  undefined4 uStack_c;
  
  local_res18 = (int *)0x0;
  local_res20 = 0xc;
  lVar1 = (**(code **)(DAT_000020d8 + 0x48))
                    (u_SetupLedData_00002080,0x2000,0,&local_res20,&local_28);
  if (-1 < lVar1) {
    lVar1 = (**(code **)(DAT_000020d0 + 0x140))(&DAT_00002010,0,&local_res18);
    if (-1 < lVar1) {
      if (*local_res18 == 2) {
        local_30 = 0;
        local_38 = 0;
        lVar1 = (**(code **)(DAT_000020d0 + 0x140))(&DAT_00002050,0,&local_38);
        if (-1 < lVar1) {
          local_18 = CONCAT44(uRam0000000000002004,_DAT_00002000);
          uStack_10 = uRam0000000000002008;
          uStack_c = uRam000000000000200c;
          lVar1 = (**(code **)(local_38 + 0x20))
                            (u_SetupLedData_00002080,&local_18,&local_30,&local_res20);
          if (-1 < lVar1) {
            uStack_10 = local_20;
            local_18 = local_28;
            (**(code **)(local_res18 + 4))(&local_18,local_30);
          }
        }
      }
      else {
        local_18 = local_28;
        uStack_10 = local_20;
        (**(code **)(local_res18 + 2))(&local_18);
      }
    }
  }
  return;
}

