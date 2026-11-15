
void FUN_0000160c(void)

{
  longlong lVar1;
  undefined1 local_res18 [8];
  undefined8 local_res20;
  
  local_res18[0] = 1;
  local_res20 = 1;
  lVar1 = (**(code **)(DAT_00002158 + 0x48))
                    (u_FTMActiveFlag_000020b0,&DAT_00002030,0,&local_res20,local_res18);
  if (lVar1 < 0) {
    (**(code **)(DAT_00002158 + 0x58))
              (u_FTMActiveFlag_000020b0,&DAT_00002030,7,local_res20,local_res18);
  }
  return;
}

